#define _GNU_SOURCE
#include "config.h"
#include "lease.h"
#include "request.h"
#include "utils.h"

dhcp_config_t g_config;
static int g_server_socket = -1;
static volatile sig_atomic_t g_running  = 1;
static volatile sig_atomic_t g_compact  = 0;  /* set by SIGHUP, serviced in main loop */

/* Signal handler — only async-signal-safe operations here.
 * compact_lease_database() is NOT async-safe (uses malloc/file-I/O),
 * so SIGHUP sets a flag that the main loop checks between packets. */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM)
        g_running = 0;
    else if (signum == SIGHUP)
        g_compact = 1;
}

/* Setup signal handlers */
static int setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGINT handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGTERM handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        syslog(LOG_ERR, "Failed to setup SIGHUP handler: %s", strerror(errno));
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);
    return 0;
}

/* Write PID file */
static int write_pid_file(void) {
    char pid_file[256];
    snprintf(pid_file, sizeof(pid_file), "%s%s", SERVER_PATH, PID_FILE);

    int fd = open(pid_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

/* Remove PID file */
static void remove_pid_file(void) {
    char pid_file[256];
    snprintf(pid_file, sizeof(pid_file), "%s%s", SERVER_PATH, PID_FILE);
    unlink(pid_file);
}

/* Shutdown */
static void cleanup_and_exit(int exit_code) {
    syslog(LOG_INFO, "Performing cleanup...");
    compact_lease_database(&g_config);

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

int main(int argc, char **argv) {
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

    if (write_pid_file() < 0) {
        fprintf(stderr, "Failed to write PID file\n");
        cleanup_and_exit(1);
    }

    syslog(LOG_INFO, "DHCP Server started on port %d", DHCP_SERVER_PORT);

    /* Log startup to server.log */
    {
        char server_log[256];
        snprintf(server_log, sizeof(server_log), "%s%s", SERVER_PATH, SERVER_LOG_FILE);
        int log_fd = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            char log_msg[256];
            time_t now = time(NULL);
            struct tm *tm_now = localtime(&now);
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

    syslog(LOG_INFO, "Entering main loop...");

    /* Main server loop */
    char buffer[BUFFER_SIZE];

    /* Control-message buffers — sized for one in_pktinfo cmsg */
    char recv_ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))];
    char send_ctrl[CMSG_SPACE(sizeof(struct in_pktinfo))];

    time_t last_compact = time(NULL);
    const time_t COMPACT_INTERVAL = 86400; /* 24 hours */
    int packet_count = 0;

    while (g_running) {
        /* Service SIGHUP-requested compaction (flag set by signal handler) */
        if (g_compact) {
            g_compact = 0;
            syslog(LOG_INFO, "SIGHUP: compacting lease database");
            compact_lease_database(&g_config);
            last_compact = time(NULL);
        }

        /* Periodic maintenance */
        time_t now = time(NULL);
        if (now - last_compact >= COMPACT_INTERVAL) {
            syslog(LOG_INFO, "Scheduled maintenance: compacting lease database");
            compact_lease_database(&g_config);
            last_compact = now;
        }

        /* ---- receive ---- */
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        memset(buffer,       0, sizeof(buffer));
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
            syslog(LOG_ERR, "recvmsg error: %s", strerror(errno));
            continue;
        }

        /* Extract incoming interface index from IP_PKTINFO */
        int ifindex = 0;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&recv_msg);
             cm;
             cm = CMSG_NXTHDR(&recv_msg, cm)) {
            if (cm->cmsg_level == IPPROTO_IP &&
                cm->cmsg_type  == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
                ifindex = pi->ipi_ifindex;
                break;
            }
        }

        packet_count++;
        syslog(LOG_INFO, "Packet #%d: %zd bytes from %s:%d (ifindex=%d)",
               packet_count, recv_len,
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port),
               ifindex);

        /* ---- parse & validate ---- */
        if ((size_t)recv_len < sizeof(struct dhcp_packet) - DHCP_OPTIONS_LEN) {
            syslog(LOG_WARNING, "Packet too short (%zd bytes), ignoring", recv_len);
            continue;
        }

        struct dhcp_packet *request = (struct dhcp_packet *)buffer;
        struct dhcp_packet  response;
        dhcp_options_t      opts;
        memset(&response, 0, sizeof(response));

        if (parse_dhcp_options(request, &opts) < 0) {
            syslog(LOG_WARNING, "Failed to parse DHCP options");
            continue;
        }

        if (!opts.found_message_type) {
            syslog(LOG_WARNING, "Packet has no message-type option, ignoring");
            continue;
        }

        char mac_str[MAC_STR_LEN];
        format_mac_address(request->chaddr, mac_str, sizeof(mac_str));

        if (is_blacklisted(&g_config, mac_str)) {
            syslog(LOG_WARNING, "Blocked request from blacklisted MAC: %s", mac_str);
            continue;
        }

        /* ---- process ---- */
        size_t pkt_len = 0;
        if (process_dhcp_message(request, &response, &opts, &g_config, &pkt_len) < 0) {
            syslog(LOG_DEBUG, "No response needed for %s", mac_str);
            continue;
        }

        /* ---- Response routing ---- */
        /* options[0]=53 (code), [1]=1 (len), [2]=message type value */
        uint8_t resp_type = response.options[2];

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        if (resp_type == DHCPNAK) {
            /* NAK: relay agent gets unicast on port 67; otherwise broadcast */
            if (response.giaddr != 0) {
                dest_addr.sin_addr.s_addr = response.giaddr;
                dest_addr.sin_port = htons(DHCP_SERVER_PORT);
            } else {
                dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            }
        } else if (opts.message_type == DHCPINFORM) {
            /* INFORM ACK: unicast to the client's current address (ciaddr) */
            dest_addr.sin_addr.s_addr = request->ciaddr;
            dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
        } else {
            /* OFFER / ACK routing per RFC 2131 4.1. */
            if (response.giaddr != 0) {
                /* relay agent: forward to relay on server port */
                dest_addr.sin_addr.s_addr = response.giaddr;
                dest_addr.sin_port = htons(DHCP_SERVER_PORT);
            } else if (request->ciaddr != 0) {
                /* RENEWING/REBINDING: client already has this IP, unicast works */
                dest_addr.sin_addr.s_addr = request->ciaddr;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            } else {
                /* ciaddr == 0: client has no IP yet — always broadcast */
                dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
            }
        }

        syslog(LOG_DEBUG, "Routing response (type=%d) to %s:%d via ifindex=%d, "
               "%zu bytes",
               resp_type,
               inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port),
               ifindex, pkt_len);

        /* ---- send via same interface ---- */
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

        /* Attach IP_PKTINFO so kernel sends on the correct interface */
        struct cmsghdr *scm = CMSG_FIRSTHDR(&send_msg);
        scm->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
        scm->cmsg_level = IPPROTO_IP;
        scm->cmsg_type  = IP_PKTINFO;
        struct in_pktinfo *spi = (struct in_pktinfo *)CMSG_DATA(scm);
        memset(spi, 0, sizeof(*spi));
        spi->ipi_ifindex = ifindex;   /* reply on the same NIC we received on */

        ssize_t sent = sendmsg(g_server_socket, &send_msg, 0);
        if (sent < 0)
            syslog(LOG_ERR, "sendmsg failed: %s", strerror(errno));
        else
            syslog(LOG_INFO, "Sent %zd bytes to %s (type=%d)",
                   sent, mac_str, resp_type);
    }

    syslog(LOG_INFO, "Main loop exited, cleaning up...");
    cleanup_and_exit(0);
    return 0;
}
