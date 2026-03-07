#define _GNU_SOURCE
#include "config.h"
#include "lease.h"
#include "request.h"
#include "utils.h"
#include <pthread.h>

/* Each received packet gets copied into a queue slot so the main thread can
 * loop straight back to recvmsg without waiting for a worker to finish. */
typedef struct {
    char               buf[BUFFER_SIZE];
    ssize_t            recv_len;
    struct sockaddr_in client_addr;
    int                ifindex;
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
static pthread_mutex_t g_server_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Protects all writes to members.txt.  Workers call update_lease_database
 * or remove_lease_from_database after releasing g_server_mutex, so two
 * workers could otherwise clobber each other's atomic rename. */
pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t *g_workers = NULL; /* malloc'd after config load */

/* --------------------------------------------------------------------------
 * Globals
 * -------------------------------------------------------------------------- */
dhcp_config_t g_config;
static int g_server_socket = -1;
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;  /* set by SIGHUP — hot-reload static+blacklist */
static volatile sig_atomic_t g_dump    = 0;  /* set by SIGUSR1 — dump lease table */

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
 * Shutdown
 * -------------------------------------------------------------------------- */
static void cleanup_and_exit(int exit_code) {
    syslog(LOG_INFO, "Performing cleanup...");

    if (g_server_socket >= 0) {
        close(g_server_socket);
        g_server_socket = -1;
    }

    cleanup_config();
    remove_pid_file();

    syslog(LOG_INFO, "DHCP server stopped");
    closelog();
    exit(exit_code);
}

/* --------------------------------------------------------------------------
 * Hex dump helper (debug)
 * -------------------------------------------------------------------------- */
__attribute__((unused))
static void print_packet_hex(const char *label, const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    char hex_line[80];
    int pos;

    syslog(LOG_DEBUG, "=== %s (%zu bytes) ===", label, len);

    for (size_t i = 0; i < len; i += 16) {
        pos = 0;
        pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, "%04zx: ", i);

        for (size_t j = 0; j < 16 && (i + j) < len; j++)
            pos += snprintf(hex_line + pos, sizeof(hex_line) - pos,
                            "%02x ", bytes[i + j]);

        for (size_t j = (len - i < 16) ? len - i : 16; j < 16; j++)
            pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, "   ");

        pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, " |");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            uint8_t c = bytes[i + j];
            pos += snprintf(hex_line + pos, sizeof(hex_line) - pos,
                            "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, "|");

        syslog(LOG_DEBUG, "%s", hex_line);
    }
    syslog(LOG_DEBUG, "=== End %s ===", label);
}

/* Workers pull packets from the ring buffer, process them, and send replies.
 * The server mutex is held only for the in-memory part of each request so
 * workers can run mostly in parallel.  sendmsg() is thread-safe. */
static void *worker_thread(void *arg) {
    (void)arg;

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

        /* Parse options before taking any lock — this reads only the packet buffer */
        struct dhcp_packet *request = (struct dhcp_packet *)item.buf;
        dhcp_options_t      opts;

        if (parse_dhcp_options(request, &opts) < 0) {
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

        int ret = process_dhcp_message(request, &response, &opts,
                                       &g_config, &pkt_len, &result);
        pthread_mutex_unlock(&g_server_mutex);

        /* Log and update the lease file — both happen after the lock drops */
        if (result.req_log[0])
            log_dhcp_interaction(&g_config, result.req_log, result.mac,
                                 result.hostname[0] ? result.hostname : NULL,
                                 result.req_ip[0]  ? result.req_ip  : NULL);
        if (result.resp_log[0])
            log_dhcp_interaction(&g_config, result.resp_log, result.mac,
                                 result.hostname[0] ? result.hostname : NULL,
                                 result.resp_ip[0] ? result.resp_ip : NULL);
        if (result.write_lease_db)
            update_lease_database(result.mac, result.device_id,
                                  result.resp_ip,
                                  result.hostname[0] ? result.hostname : NULL,
                                  &g_config);
        if (result.remove_lease_db)
            remove_lease_from_database(result.device_id, &g_config);

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

        ssize_t sent = sendmsg(g_server_socket, &send_msg, 0);
        if (sent < 0)
            syslog(LOG_ERR, "sendmsg failed: %s", strerror(errno));
        else
            syslog(LOG_INFO, "Sent %zd bytes to %s (type=%d)", sent, mac_str, resp_type);
    }

    return NULL;
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    srand((unsigned int)(time(NULL) ^ (uint32_t)getpid()));

    openlog("dhcp_server", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "DHCP Server starting...");

    if (setup_signals() < 0) {
        fprintf(stderr, "Failed to setup signal handlers\n");
        return 1;
    }

    if (init_config(argc, argv) < 0) {
        fprintf(stderr, "Failed to initialize configuration\n");
        cleanup_and_exit(1);
    }

    if (init_data_structures() < 0) {
        fprintf(stderr, "Failed to initialize data structures\n");
        cleanup_and_exit(1);
    }

    g_server_socket = create_server_socket();
    if (g_server_socket < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        cleanup_and_exit(1);
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

    syslog(LOG_INFO, "DHCP Server started on port %d", DHCP_SERVER_PORT);

    /* Log startup to server.log */
    {
        int log_fd = open(g_config.log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            char log_msg[256];
            time_t now = time(NULL);
            struct tm tm_buf;
            struct tm *tm_now = localtime_r(&now, &tm_buf);
            char timestamp[64];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_now);
            snprintf(log_msg, sizeof(log_msg),
                     "[%s] ===== SERVER STARTED (PID: %d) =====\n",
                     timestamp, getpid());
            if (write(log_fd, log_msg, strlen(log_msg)) < 0)
                syslog(LOG_WARNING, "Failed to write startup log: %s", strerror(errno));
            close(log_fd);
        }
    }

    /* Spawn worker thread pool */
    for (int i = 0; i < g_config.num_workers; i++) {
        if (pthread_create(&g_workers[i], NULL, worker_thread, NULL) != 0) {
            syslog(LOG_ERR, "Failed to create worker thread %d: %s",
                   i, strerror(errno));
            cleanup_and_exit(1);
        }
    }
    syslog(LOG_INFO, "Started %d worker threads (queue cap %d)",
           g_config.num_workers, g_queue_cap);
    syslog(LOG_INFO, "Entering main loop...");

    /* recvmsg needs a control buffer to deliver the IP_PKTINFO ancillary data */
    char recv_ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))];

    int packet_count = 0;

    while (g_running) {
        /* Hot-reload static assignments and blacklist (under server mutex) */
        if (g_reload) {
            g_reload = 0;
            syslog(LOG_INFO, "SIGHUP: reloading static assignments and blacklist");
            pthread_mutex_lock(&g_server_mutex);
            reload_static_assignments(&g_config);
            reload_blacklist(&g_config);
            pthread_mutex_unlock(&g_server_mutex);
        }

        /* SIGUSR1: dump current lease table */
        if (g_dump) {
            g_dump = 0;
            syslog(LOG_INFO, "SIGUSR1: dumping lease table to %s",
                   g_config.dump_path ? g_config.dump_path : "(null)");
            pthread_mutex_lock(&g_server_mutex);
            dump_lease_table(&g_config);
            pthread_mutex_unlock(&g_server_mutex);
        }

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

        syslog(LOG_DEBUG, "Waiting for DHCP packet...");
        ssize_t recv_len = recvmsg(g_server_socket, &recv_msg, 0);

        if (recv_len < 0) {
            if (errno == EINTR) {
                syslog(LOG_DEBUG, "recvmsg interrupted by signal");
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* SO_RCVTIMEO fired — sweep expired leases */
                pthread_mutex_lock(&g_server_mutex);
                sweep_expired_leases(&g_config);
                pthread_mutex_unlock(&g_server_mutex);
                continue;
            }
            syslog(LOG_ERR, "recvmsg error: %s", strerror(errno));
            continue;
        }

        /* Pull out which interface this packet arrived on so we can reply on the same one */
        int ifindex = 0;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&recv_msg);
             cm;
             cm = CMSG_NXTHDR(&recv_msg, cm)) {
            if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
                ifindex = pi->ipi_ifindex;
                break;
            }
        }

        packet_count++;
        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, src_ip_str, sizeof(src_ip_str));
        syslog(LOG_INFO, "Packet #%d: %zd bytes from %s:%d (ifindex=%d)",
               packet_count, recv_len,
               src_ip_str,
               ntohs(client_addr.sin_port),
               ifindex);

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

    for (int i = 0; i < g_config.num_workers; i++)
        pthread_join(g_workers[i], NULL);

    free(g_workers); g_workers = NULL;
    free(g_queue);   g_queue   = NULL;

    pthread_mutex_destroy(&g_server_mutex);
    pthread_mutex_destroy(&g_file_mutex);
    pthread_mutex_destroy(&g_queue_mutex);
    pthread_cond_destroy(&g_queue_notempty);
    pthread_cond_destroy(&g_queue_notfull);

    cleanup_and_exit(0);
    return 0;
}
