#define _GNU_SOURCE
#include "config.h"
#include "lease.h"
#include "request.h"
#include "utils.h"
#include "journal.h"
#include "ha.h"
#include "peer.h"
#include "cluster.h"
#include "probe.h"
#include <pthread.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>

#define COMPACT_INTERVAL   3600   /* hourly: rewrite the journal as just live records */
#define SWEEP_INTERVAL     60     /* reclaim expired leases on a timer */
#define SNAPSHOT_INTERVAL  1      /* members.txt refreshed at most this often */

/* Each received packet gets copied into a queue slot so the main thread can
 * loop straight back to recvmsg without waiting for a worker to finish. */
typedef struct {
    char               buf[BUFFER_SIZE];
    ssize_t            recv_len;
    struct sockaddr_in client_addr;
    int                ifindex;
    bool               broadcast;   /* sent to a broadcast address, not to us */
    bool               forwarded;   /* handed to us by a sibling on our address */
} work_item_t;

static work_item_t    *g_queue      = NULL; /* malloc'd after config load */
static int             g_queue_cap  = 0;    /* set from g_config.num_workers */
static int             g_queue_head  = 0;
static int             g_queue_tail  = 0;
static int             g_queue_count = 0;
static pthread_mutex_t g_queue_mutex    = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_queue_notempty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_queue_notfull  = PTHREAD_COND_INITIALIZER;

/* Guards the in-memory lease table, IP pool, and blacklist.  Held only while
 * a packet is being processed — file writes and sending happen outside it so
 * one slow client never stalls the others. */
pthread_mutex_t g_server_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Serialises writes to members.txt and the dump file (each is an atomic
 * temp-file + rename, but two at once would race on the temp file). */
pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t   *g_workers = NULL; /* malloc'd after config load */
static probe_ctx_t *g_probes  = NULL; /* one per worker, opened before dropping root */

/* --------------------------------------------------------------------------
 * Globals
 * -------------------------------------------------------------------------- */
dhcp_config_t g_config;
static int g_server_socket = -1;   /* 0.0.0.0:67 — broadcasts (shared by every server on this machine) */
static int g_own_socket    = -1;   /* server_ip:67 — traffic addressed to us; replies go out from here */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;  /* set by SIGHUP — hot-reload static+blacklist */
static volatile sig_atomic_t g_dump    = 0;  /* set by SIGUSR1 — dump lease table */
static volatile sig_atomic_t g_compact = 0;  /* set by SIGUSR2 — compact the journal now */

/* --------------------------------------------------------------------------
 * Signal handling
 * -------------------------------------------------------------------------- */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM)
        g_running = 0;
    else if (signum == SIGHUP)
        g_reload = 1;
    else if (signum == SIGUSR1)
        g_dump = 1;
    else if (signum == SIGUSR2)
        g_compact = 1;
}

static int setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    /* SIGINT/SIGTERM should interrupt the blocking recvmsg immediately so the
     * server shuts down without waiting for the next packet to arrive. */
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGINT handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGTERM handler: %s", strerror(errno));
        return -1;
    }

    /* SIGHUP and SIGUSR1 just flip a flag — it's fine if they restart a syscall */
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGHUP handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGUSR1 handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGUSR2, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGUSR2 handler: %s", strerror(errno));
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);
    return 0;
}

/* --------------------------------------------------------------------------
 * PID file
 * -------------------------------------------------------------------------- */
static int write_pid_file(void) {
    int fd = open(g_config.pid_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to create PID file: %s", strerror(errno));
        return -1;
    }
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (write(fd, pid_str, strlen(pid_str)) < 0)
        syslog(LOG_ERR, "Failed to write PID file: %s", strerror(errno));
    close(fd);
    return 0;
}

static void remove_pid_file(void) {
    if (g_config.pid_path)
        unlink(g_config.pid_path);
}

/* --------------------------------------------------------------------------
 * Privilege drop
 *
 * Binding port 67 needs root, but nothing afterwards does — the socket is
 * never rebound, and the runtime files live in a directory the target user
 * can write to.  So once we're bound we permanently shed root.  This is
 * opt-in via the `user` config key: with no user set we keep the previous
 * behaviour of running as whoever launched us.
 *
 * Must run while still single-threaded (before the worker pool starts) so the
 * uid/gid change applies to the whole process.
 * -------------------------------------------------------------------------- */
static int drop_privileges(const char *username) {
    if (!username || !username[0])
        return 0;                 /* not configured — leave privileges as-is */
    if (getuid() != 0) {
        syslog(LOG_INFO, "Not running as root; skipping drop to '%s'", username);
        return 0;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        syslog(LOG_ERR, "drop_privileges: unknown user '%s'", username);
        return -1;
    }

    if (setgid(pw->pw_gid) != 0) {
        syslog(LOG_ERR, "drop_privileges: setgid(%d) failed: %s",
               (int)pw->pw_gid, strerror(errno));
        return -1;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0)
        syslog(LOG_WARNING, "drop_privileges: initgroups failed: %s",
               strerror(errno));
    if (setuid(pw->pw_uid) != 0) {
        syslog(LOG_ERR, "drop_privileges: setuid(%d) failed: %s",
               (int)pw->pw_uid, strerror(errno));
        return -1;
    }

    /* Refuse to continue if root can be regained — a successful setuid(0) here
     * means the drop didn't really stick. */
    if (setuid(0) == 0) {
        syslog(LOG_ERR, "drop_privileges: still able to regain root — aborting");
        return -1;
    }

    syslog(LOG_INFO, "Dropped privileges to '%s' (uid=%d gid=%d)",
           username, (int)pw->pw_uid, (int)pw->pw_gid);
    return 0;
}

/* --------------------------------------------------------------------------
 * Shutdown
 * -------------------------------------------------------------------------- */
static void cleanup_and_exit(int exit_code) {
    syslog(LOG_INFO, "Performing cleanup...");

    if (g_server_socket >= 0) {
        close(g_server_socket);
        g_server_socket = -1;
    }
    if (g_own_socket >= 0) {
        close(g_own_socket);
        g_own_socket = -1;
    }

    peer_stop();
    journal_close();
    cleanup_config();
    remove_pid_file();

    syslog(LOG_INFO, "DHCP server stopped");
    closelog();
    exit(exit_code);
}

/* Packets a sibling handed to us (peer thread).  Never blocks: if the queue
 * is full the packet is dropped and the client simply retries. */
static void enqueue_forwarded(const void *pkt, size_t len, int ifindex) {
    if (len > BUFFER_SIZE || len < sizeof(struct dhcp_packet) - DHCP_OPTIONS_LEN) return;
    pthread_mutex_lock(&g_queue_mutex);
    if (g_running && g_queue && g_queue_count < g_queue_cap) {
        work_item_t *w = &g_queue[g_queue_tail];
        memcpy(w->buf, pkt, len);
        w->recv_len  = (ssize_t)len;
        memset(&w->client_addr, 0, sizeof(w->client_addr));
        w->ifindex   = ifindex;
        w->broadcast = false;
        w->forwarded = true;
        g_queue_tail = (g_queue_tail + 1) % g_queue_cap;
        g_queue_count++;
        pthread_cond_signal(&g_queue_notempty);
    }
    pthread_mutex_unlock(&g_queue_mutex);
}

/* Workers pull packets from the ring buffer, process them, and send replies.
 * The server mutex is held only for the in-memory part of each request so
 * workers can run mostly in parallel.  sendmsg() is thread-safe. */
#define MAX_PROBE_CONFLICTS 3   /* give up on one DISCOVER after this many taken addresses */

static void *worker_thread(void *arg) {
    probe_ctx_t *probe = arg;          /* this worker's conflict-check sockets */

    char send_ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))];

    while (1) {
        /* --- dequeue --- */
        pthread_mutex_lock(&g_queue_mutex);
        while (g_queue_count == 0) {
            if (!g_running) {
                pthread_mutex_unlock(&g_queue_mutex);
                return NULL;
            }
            pthread_cond_wait(&g_queue_notempty, &g_queue_mutex);
        }

        work_item_t item = g_queue[g_queue_head];
        g_queue_head = (g_queue_head + 1) % g_queue_cap;
        g_queue_count--;
        pthread_cond_signal(&g_queue_notfull);
        pthread_mutex_unlock(&g_queue_mutex);

        /* Parse options before taking any lock — this reads only the packet buffer.
         * Bound parsing to the bytes actually received so we never interpret the
         * uninitialised tail of the queue slot as DHCP options. */
        struct dhcp_packet *request = (struct dhcp_packet *)item.buf;
        dhcp_options_t      opts;

        size_t header_len = sizeof(struct dhcp_packet) - sizeof(request->options);
        size_t opt_len    = ((size_t)item.recv_len > header_len)
                          ? (size_t)item.recv_len - header_len : 0;

        if (parse_dhcp_options(request, &opts, opt_len) < 0) {
            syslog(LOG_WARNING, "Worker: failed to parse DHCP options");
            continue;
        }
        if (!opts.found_message_type) {
            syslog(LOG_WARNING, "Worker: packet has no message-type option");
            continue;
        }

        char mac_str[MAC_STR_LEN];
        format_mac_address(request->chaddr, mac_str, sizeof(mac_str));

        /* Take the lock and do all the in-memory work atomically */
        struct dhcp_packet response;
        size_t pkt_len = 0;
        memset(&response, 0, sizeof(response));

        dhcp_result_t result;
        memset(&result, 0, sizeof(result));

        pthread_mutex_lock(&g_server_mutex);
        if (is_blacklisted(&g_config, mac_str)) {
            syslog(LOG_WARNING, "Blocked request from blacklisted MAC: %s", mac_str);
            pthread_mutex_unlock(&g_server_mutex);
            continue;
        }
        pthread_mutex_unlock(&g_server_mutex);

        dhcp_rx_t rx = { .broadcast = item.broadcast, .forwarded = item.forwarded };
        int ret = -1;
        bool give_up = false;
        for (int conflicts = 0; ; ) {
            pthread_mutex_lock(&g_server_mutex);
            ret = process_dhcp_message(request, &response, &opts,
                                       &g_config, &pkt_len, &result, &rx);
            pthread_mutex_unlock(&g_server_mutex);

            /* A fresh address in the OFFER: make sure nothing on the network
             * already uses it.  Done without the lock, so a slow probe never
             * holds up other clients. */
            if (ret < 0 || !result.probe_ip[0] || g_config.probe_timeout_ms <= 0)
                break;
            char who[64] = "?";
            uint32_t ip = inet_addr(result.probe_ip);
            bool on_link = request->giaddr == 0;
            int in_use = probe_address(probe, ip, item.ifindex, on_link,
                                       g_config.probe_timeout_ms, who, sizeof(who));
            pthread_mutex_lock(&g_server_mutex);
            if (in_use == 1) {
                lease_commit_t hold = {0};
                lease_offer_conflict(&g_config, result.device_id, result.probe_ip,
                                     who, &hold);
                pthread_mutex_unlock(&g_server_mutex);
                if (hold.has) {
                    journal_sync(&hold.ticket);
                    peer_broadcast_record(hold.line);
                    snapshot_mark_dirty();
                }
                if (++conflicts >= MAX_PROBE_CONFLICTS) {
                    syslog(LOG_WARNING, "%d addresses in a row were already in use — "
                           "not answering %s this time", conflicts, mac_str);
                    give_up = true;
                    break;
                }
                memset(&result, 0, sizeof(result));
                continue;                  /* build the offer again: next address */
            }
            lease_offer_verified(&g_config, result.device_id, result.probe_ip);
            pthread_mutex_unlock(&g_server_mutex);
            break;
        }
        if (give_up) continue;

        /* A relayed packet for a client that belongs to a sibling sharing our
         * address: it must answer (from its own slice), so pass it on. */
        if (result.forward_to[0]) {
            peer_forward_packet(result.forward_to, item.buf, (size_t)item.recv_len,
                                item.ifindex);
            continue;
        }

        /* The lease must be on disk before we promise it to the client
         * (RFC 2131), then the other nodes hear about it. */
        if (result.commit.has) {
            journal_sync(&result.commit.ticket);
            peer_broadcast_record(result.commit.line);
            snapshot_mark_dirty();
        }

        /* Log and update the lease file — both happen after the lock drops */
        if (result.req_log[0])
            log_dhcp_interaction(&g_config, result.req_log, result.mac,
                                 result.device_id[0] ? result.device_id : NULL,
                                 result.hostname[0] ? result.hostname : NULL,
                                 result.req_ip[0]  ? result.req_ip  : NULL);
        if (result.resp_log[0])
            log_dhcp_interaction(&g_config, result.resp_log, result.mac,
                                 result.device_id[0] ? result.device_id : NULL,
                                 result.hostname[0] ? result.hostname : NULL,
                                 result.resp_ip[0] ? result.resp_ip : NULL);
        if (ret < 0) {
            syslog(LOG_DEBUG, "No response needed for %s", mac_str);
            continue;
        }

        /* Work out where to send the reply.  RFC 2131 has a bunch of rules
         * depending on whether the client has a relay, an existing IP, or
         * wants a broadcast.  The message type determines which path we take. */
        uint8_t resp_type = response.options[2];  /* options[0]=53, [1]=1, [2]=type */

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        if (resp_type == DHCPNAK) {
            /* relay → unicast to relay; ciaddr set → unicast; else → broadcast */
            if (response.giaddr != 0) {
                dest_addr.sin_addr.s_addr = response.giaddr;
                dest_addr.sin_port = htons(DHCP_SERVER_PORT);
            } else if (request->ciaddr != 0) {
                dest_addr.sin_addr.s_addr = request->ciaddr;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            } else {
                dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            }
        } else if (opts.message_type == DHCPINFORM) {
            dest_addr.sin_addr.s_addr = request->ciaddr;
            dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
        } else {
            if (response.giaddr != 0) {
                dest_addr.sin_addr.s_addr = response.giaddr;
                dest_addr.sin_port = htons(DHCP_SERVER_PORT);
            } else if (request->ciaddr != 0) {
                dest_addr.sin_addr.s_addr = request->ciaddr;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            } else {
                dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            }
        }

        /* Pad to 300 bytes — old BOOTP relays may drop shorter packets */
        if (pkt_len < 300)
            pkt_len = 300;

        char dest_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest_addr.sin_addr, dest_ip_str, sizeof(dest_ip_str));
        syslog(LOG_DEBUG, "Routing response (type=%d) to %s:%d via ifindex=%d, %zu bytes",
               resp_type, dest_ip_str, ntohs(dest_addr.sin_port),
               item.ifindex, pkt_len);

        /* Reply on the same interface the packet came in on.  On a multi-homed
         * Pi this matters — without it the reply can go out the wrong port. */
        memset(send_ctrl, 0, sizeof(send_ctrl));

        struct iovec send_iov = {
            .iov_base = &response,
            .iov_len  = pkt_len,
        };
        struct msghdr send_msg = {
            .msg_name       = &dest_addr,
            .msg_namelen    = sizeof(dest_addr),
            .msg_iov        = &send_iov,
            .msg_iovlen     = 1,
            .msg_control    = send_ctrl,
            .msg_controllen = sizeof(send_ctrl),
        };

        struct cmsghdr *scm = CMSG_FIRSTHDR(&send_msg);
        scm->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
        scm->cmsg_level = IPPROTO_IP;
        scm->cmsg_type  = IP_PKTINFO;
        struct in_pktinfo *spi = (struct in_pktinfo *)CMSG_DATA(scm);
        memset(spi, 0, sizeof(*spi));
        spi->ipi_ifindex = item.ifindex;

        /* From our own address when we have it, so the reply's source matches
         * the server identifier even when this machine has several. */
        int send_fd = g_own_socket >= 0 ? g_own_socket : g_server_socket;
        ssize_t sent = sendmsg(send_fd, &send_msg, 0);
        if (sent < 0)
            syslog(LOG_ERR, "sendmsg failed: %s", strerror(errno));
        else
            syslog(LOG_INFO, "Sent %zd bytes to %s (type=%d)", sent, mac_str, resp_type);
    }

    return NULL;
}

/* --------------------------------------------------------------------------
 * Periodic housekeeping — shared by nodes (between packets) and the
 * controller (which has no DHCP socket and just ticks).
 * -------------------------------------------------------------------------- */
static time_t g_last_sweep    = 0;
static time_t g_last_compact  = 0;
static time_t g_last_snapshot = 0;

static void handle_reload(void) {
    if (g_config.node_id && g_config.role == ROLE_CONTROLLER) {
        char msg[512];
        int rc = peer_controller_load(false, msg, sizeof(msg));
        syslog(rc == 0 ? LOG_INFO : LOG_ERR, "SIGHUP: %s", msg);
    } else if (g_config.node_id) {
        syslog(LOG_INFO, "SIGHUP: reloading %s", g_config.cluster_dir);
        cluster_load(&g_config, NULL, NULL, 0);
    } else {
        syslog(LOG_INFO, "SIGHUP: reloading static assignments and blacklist");
        pthread_mutex_lock(&g_server_mutex);
        reload_static_assignments(&g_config);
        reload_blacklist(&g_config);
        pthread_mutex_unlock(&g_server_mutex);
        snapshot_mark_dirty();
    }
}

static void housekeeping(void) {
    time_t now = time(NULL);

    if (g_reload) {
        g_reload = 0;
        handle_reload();
    }

    if (g_dump) {
        g_dump = 0;
        syslog(LOG_INFO, "SIGUSR1: dumping lease table to %s",
               g_config.dump_path ? g_config.dump_path : "(null)");
        pthread_mutex_lock(&g_server_mutex);
        dump_lease_table(&g_config);
        pthread_mutex_unlock(&g_server_mutex);
    }

    /* Reclaim expired leases and stale OFFER reservations */
    if (now - g_last_sweep >= SWEEP_INTERVAL) {
        g_last_sweep = now;
        pthread_mutex_lock(&g_server_mutex);
        int dropped = sweep_expired_leases(&g_config);
        pthread_mutex_unlock(&g_server_mutex);
        if (dropped) snapshot_mark_dirty();
    }

    /* Hourly (or on SIGUSR2): rewrite the journal as just the live records */
    if (g_compact || now - g_last_compact >= COMPACT_INTERVAL) {
        g_compact = 0;
        g_last_compact = now;
        pthread_mutex_lock(&g_server_mutex);
        journal_compact(&g_config);
        pthread_mutex_unlock(&g_server_mutex);
    }

    /* members.txt: rebuilt from memory, at most once a second */
    if (now - g_last_snapshot >= SNAPSHOT_INTERVAL && snapshot_take_dirty()) {
        g_last_snapshot = now;
        size_t len = 0;
        pthread_mutex_lock(&g_server_mutex);
        char *snap = snapshot_build(&g_config, &len);
        pthread_mutex_unlock(&g_server_mutex);
        if (snap) {
            snapshot_save(&g_config, snap, len);
            free(snap);
        } else {
            snapshot_mark_dirty();       /* try again next second */
        }
    }
}

static void usage(void) {
    fprintf(stderr,
        "usage: dhcp_server [-v] [--controller] [--node-id ID] [dhcp.conf]\n"
        "       dhcp_server --ctl [dhcp.conf] status\n"
        "       dhcp_server --ctl [dhcp.conf] partner-down <node>\n"
        "       dhcp_server --ctl [dhcp.conf] push [--force]\n"
        "\n"
        "  -v              also log to stderr\n"
        "  --controller    run as the cluster controller (no DHCP, owns shared config)\n"
        "  --node-id ID    override node_id from dhcp.conf\n"
        "  --ctl           talk to the server running on this machine\n");
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    srand((unsigned int)(time(NULL) ^ (uint32_t)getpid()));

    cli_options_t opts = {0};
    bool verbose = false, ctl = false;
    int  ctl_argc = 0;
    char **ctl_argv = NULL;

    for (int i = 1; i < argc; i++) {
        if (ctl && opts.conf_path) {           /* everything after the conf is the command */
            ctl_argc = argc - i;
            ctl_argv = argv + i;
            break;
        }
        if (strcmp(argv[i], "-v") == 0)                   verbose = true;
        else if (strcmp(argv[i], "--controller") == 0)    opts.controller = true;
        else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) opts.node_id = argv[++i];
        else if (strcmp(argv[i], "--ctl") == 0)           ctl = true;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        else if (argv[i][0] == '-' && !ctl) { usage(); return 2; }
        /* With --ctl the config path is optional: an existing file is the
         * config, anything else starts the command. */
        else if (!opts.conf_path && (!ctl || access(argv[i], F_OK) == 0))
            opts.conf_path = argv[i];
        else if (ctl) { ctl_argc = argc - i; ctl_argv = argv + i; break; }
        else { usage(); return 2; }
    }

    openlog("dhcp_server", LOG_PID | LOG_CONS | (verbose ? LOG_PERROR : 0), LOG_DAEMON);

    if (ctl) {
        if (init_config(&opts) < 0) return 2;
        int rc = peer_ctl_main(&g_config, ctl_argc, ctl_argv);
        cleanup_config();
        return rc;
    }

    syslog(LOG_INFO, "DHCP Server starting...");

    if (setup_signals() < 0) {
        fprintf(stderr, "Failed to setup signal handlers\n");
        return 1;
    }

    if (init_config(&opts) < 0) {
        fprintf(stderr, "Failed to initialize configuration\n");
        cleanup_and_exit(1);
    }

    bool cluster    = g_config.node_id != NULL;
    bool controller = cluster && g_config.role == ROLE_CONTROLLER;

    if (init_data_structures() < 0) {
        fprintf(stderr, "Failed to initialize data structures\n");
        cleanup_and_exit(1);
    }

    /* The controller never answers DHCP, so it doesn't bind port 67 — it can
     * share a machine with a node. */
    if (!controller) {
        g_server_socket = create_server_socket();
        if (g_server_socket < 0) {
            fprintf(stderr, "Failed to create server socket\n");
            cleanup_and_exit(1);
        }
        g_own_socket = create_own_socket(g_config.server_ip);
        if (g_own_socket < 0) {
            int err = errno;
            if (cluster) {
                /* Clients renew by unicasting to server_ip, and peers tell
                 * nodes apart by it — it has to really be ours. */
                fprintf(stderr, "Error: cannot bind server_ip %s:%d: %s%s\n",
                        g_config.server_ip, DHCP_SERVER_PORT, strerror(err),
                        err == EADDRNOTAVAIL ? " — set server_ip to one of this "
                        "machine's addresses (several servers can share it)" : "");
                cleanup_and_exit(1);
            }
            syslog(LOG_INFO, "server_ip %s isn't bindable here (%s) — using the "
                   "shared socket only", g_config.server_ip, strerror(err));
        }
    }

    if (cluster && peer_init(&g_config) < 0) {
        fprintf(stderr, "Failed to start the peer link\n");
        cleanup_and_exit(1);
    }
    if (controller) {
        char msg[512];
        if (peer_controller_load(false, msg, sizeof(msg)) < 0) {
            fprintf(stderr, "Controller: %s\n", msg);
            cleanup_and_exit(1);
        }
    }

    /* Size the queue at 64 slots per worker so it's very unlikely to fill up */
    g_queue_cap = g_config.num_workers * 64;
    if (g_queue_cap < 64) g_queue_cap = 64;

    g_queue   = malloc((size_t)g_queue_cap * sizeof(work_item_t));
    g_workers = malloc((size_t)g_config.num_workers * sizeof(pthread_t));
    if (!g_queue || !g_workers) {
        fprintf(stderr, "Failed to allocate thread pool memory\n");
        free(g_queue); free(g_workers);
        cleanup_and_exit(1);
    }

    if (write_pid_file() < 0) {
        fprintf(stderr, "Failed to write PID file\n");
        cleanup_and_exit(1);
    }

    /* Conflict-check sockets need root too — open them now, one per worker */
    if (!controller) {
        g_probes = calloc((size_t)g_config.num_workers, sizeof(probe_ctx_t));
        if (!g_probes) cleanup_and_exit(1);
        for (int i = 0; i < g_config.num_workers; i++) {
            g_probes[i].arp_fd = g_probes[i].icmp_fd = -1;
            if (g_config.probe_timeout_ms > 0) probe_open(&g_probes[i], i);
        }
        if (g_config.probe_timeout_ms > 0)
            syslog(LOG_INFO, "Conflict check on: new addresses are probed for %d ms "
                   "before being offered", g_config.probe_timeout_ms);
    }

    /* Shed root now that the privileged ports are bound (no-op unless `user`
     * is configured).  Done before any thread starts so it applies process-wide. */
    if (drop_privileges(g_config.run_as_user) < 0) {
        fprintf(stderr, "Failed to drop privileges\n");
        cleanup_and_exit(1);
    }

    if (controller)
        syslog(LOG_INFO, "Cluster controller %s started (peer port %d)",
               g_config.node_id, g_config.peer_port);
    else
        syslog(LOG_INFO, "DHCP Server started on port %d", DHCP_SERVER_PORT);

    /* Mark startup in server.log (CSV: timestamp,event,mac,client_id,hostname,ip) */
    {
        int log_fd = open(g_config.log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            time_t now = time(NULL);
            struct tm tm_buf;
            char ts[32];
            if (localtime_r(&now, &tm_buf))
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
            else
                snprintf(ts, sizeof(ts), "0000-00-00 00:00:00");
            char log_msg[64];
            int n = snprintf(log_msg, sizeof(log_msg), "%s,%s,,,,\n", ts,
                             controller ? "CONTROLLER_START" : "SERVER_START");
            if (n > 0 && write(log_fd, log_msg, (size_t)n) < 0)
                syslog(LOG_WARNING, "Failed to write startup log: %s", strerror(errno));
            close(log_fd);
        }
    }

    /* Spawn worker thread pool */
    int nworkers = controller ? 0 : g_config.num_workers;
    for (int i = 0; i < nworkers; i++) {
        if (pthread_create(&g_workers[i], NULL, worker_thread, &g_probes[i]) != 0) {
            syslog(LOG_ERR, "Failed to create worker thread %d: %s",
                   i, strerror(errno));
            cleanup_and_exit(1);
        }
    }
    if (nworkers)
        syslog(LOG_INFO, "Started %d worker threads (queue cap %d)",
               nworkers, g_queue_cap);

    peer_set_packet_handler(enqueue_forwarded);
    if (cluster && peer_start() < 0) {
        syslog(LOG_ERR, "Failed to start peer thread");
        cleanup_and_exit(1);
    }
    syslog(LOG_INFO, "Entering main loop...");

    /* recvmsg needs a control buffer to deliver the IP_PKTINFO ancillary data */
    char recv_ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))];

    int packet_count = 0;
    g_last_sweep = g_last_compact = time(NULL);
    uint32_t our_ip = inet_addr(g_config.server_ip);   /* per-node: never reloaded */

    while (g_running) {
        housekeeping();

        if (controller) {
            struct timespec ts = { .tv_sec = 1 };
            nanosleep(&ts, NULL);                  /* signals cut this short */
            continue;
        }

        /* ---- wait for a packet on either socket (1 s so timers still run) ---- */
        struct pollfd pfd[2] = {
            { .fd = g_server_socket, .events = POLLIN },
            { .fd = g_own_socket,    .events = POLLIN },
        };
        int nfds = g_own_socket >= 0 ? 2 : 1;
        int ready = poll(pfd, (nfds_t)nfds, 1000);
        if (ready <= 0) {
            if (ready < 0 && errno != EINTR)
                syslog(LOG_ERR, "poll error: %s", strerror(errno));
            continue;
        }
        int rx_fd = (nfds == 2 && (pfd[1].revents & POLLIN)) ? g_own_socket
                                                              : g_server_socket;
        if (!(pfd[0].revents & POLLIN) && rx_fd == g_server_socket)
            continue;                              /* error bits only */

        /* ---- receive ---- */
        char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        memset(recv_ctrl,    0, sizeof(recv_ctrl));

        struct iovec recv_iov = {
            .iov_base = buffer,
            .iov_len  = sizeof(buffer),
        };
        struct msghdr recv_msg = {
            .msg_name       = &client_addr,
            .msg_namelen    = sizeof(client_addr),
            .msg_iov        = &recv_iov,
            .msg_iovlen     = 1,
            .msg_control    = recv_ctrl,
            .msg_controllen = sizeof(recv_ctrl),
        };

        ssize_t recv_len = recvmsg(rx_fd, &recv_msg, MSG_DONTWAIT);

        if (recv_len < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;                          /* timers run at the top */
            syslog(LOG_ERR, "recvmsg error: %s", strerror(errno));
            continue;
        }

        /* Which interface did this arrive on (reply on the same one), and was
         * it addressed to us or broadcast to everyone? */
        int  ifindex   = 0;
        bool broadcast = true;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&recv_msg);
             cm;
             cm = CMSG_NXTHDR(&recv_msg, cm)) {
            if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
                ifindex   = pi->ipi_ifindex;
                broadcast = pi->ipi_addr.s_addr != our_ip;
                break;
            }
        }

        packet_count++;
        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, src_ip_str, sizeof(src_ip_str));
        syslog(LOG_DEBUG, "Packet #%d: %zd bytes from %s:%d (ifindex=%d%s)",
               packet_count, recv_len,
               src_ip_str,
               ntohs(client_addr.sin_port),
               ifindex, broadcast ? ", broadcast" : "");

        if ((size_t)recv_len < sizeof(struct dhcp_packet) - DHCP_OPTIONS_LEN) {
            syslog(LOG_WARNING, "Packet too short (%zd bytes), ignoring", recv_len);
            continue;
        }

        /* ---- enqueue for a worker ---- */
        pthread_mutex_lock(&g_queue_mutex);
        while (g_queue_count == g_queue_cap && g_running)
            pthread_cond_wait(&g_queue_notfull, &g_queue_mutex);

        if (g_running) {
            memcpy(g_queue[g_queue_tail].buf, buffer, (size_t)recv_len);
            g_queue[g_queue_tail].recv_len    = recv_len;
            g_queue[g_queue_tail].client_addr = client_addr;
            g_queue[g_queue_tail].ifindex     = ifindex;
            g_queue[g_queue_tail].broadcast   = broadcast;
            g_queue[g_queue_tail].forwarded   = false;
            g_queue_tail = (g_queue_tail + 1) % g_queue_cap;
            g_queue_count++;
            pthread_cond_signal(&g_queue_notempty);
        }
        pthread_mutex_unlock(&g_queue_mutex);
    }

    /* ---- shutdown: wake workers, drain queue, join ---- */
    syslog(LOG_INFO, "Main loop exited, shutting down workers...");

    pthread_mutex_lock(&g_queue_mutex);
    pthread_cond_broadcast(&g_queue_notempty);
    pthread_mutex_unlock(&g_queue_mutex);

    for (int i = 0; i < nworkers; i++)
        pthread_join(g_workers[i], NULL);

    free(g_workers); g_workers = NULL;
    free(g_queue);   g_queue   = NULL;
    for (int i = 0; g_probes && i < nworkers; i++) probe_close(&g_probes[i]);
    free(g_probes);  g_probes  = NULL;

    /* Leave members.txt matching the journal on the way out */
    snapshot_mark_dirty();
    g_last_snapshot = 0;
    housekeeping();

    cleanup_and_exit(0);
    return 0;
}
