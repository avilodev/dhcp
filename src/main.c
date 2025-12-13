#include "config.h"
#include "lease.h"
#include "request.h"
#include "utils.h"

dhcp_config_t g_config;
static int g_server_socket = -1;
static volatile sig_atomic_t g_running = 1;

/* Signal handler for graceful shutdown */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        syslog(LOG_INFO, "Received signal %d, shutting down gracefully...", signum);
        g_running = 0;
    } else if (signum == SIGHUP) {
        syslog(LOG_INFO, "Received SIGHUP, compacting lease database...");
        compact_lease_database(&g_config);
    }
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

    /* Ignore SIGPIPE */
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
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    return 0;
}

/* Remove PID file */
static void remove_pid_file(void) {
    char pid_file[256];
    snprintf(pid_file, sizeof(pid_file), "%s%s", SERVER_PATH, PID_FILE);
    unlink(pid_file);
}

/* Perform graceful shutdown */
static void cleanup_and_exit(int exit_code) {
    syslog(LOG_INFO, "Performing cleanup...");

    /* Compact the lease database one final time */
    compact_lease_database(&g_config);

    /* Close socket */
    if (g_server_socket >= 0) {
        close(g_server_socket);
        g_server_socket = -1;
    }

    /* Free all allocated memory */
    cleanup_config();

    /* Remove PID file */
    remove_pid_file();

    syslog(LOG_INFO, "DHCP server stopped");
    closelog();

    exit(exit_code);
}

int main(int argc, char **argv) {
    /* Initialize syslog */
    openlog("dhcp_server", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "DHCP Server starting...");

    /* Seed random number generator */
    srand(time(NULL));

    /* Setup signal handlers */
    if (setup_signals() < 0) {
        fprintf(stderr, "Failed to setup signal handlers\n");
        return 1;
    }

    /* Initialize configuration */
    if (init_config(argc, argv) < 0) {
        fprintf(stderr, "Failed to initialize configuration\n");
        cleanup_and_exit(1);
    }

    /* Initialize data structures */
    if (init_data_structures() < 0) {
        fprintf(stderr, "Failed to initialize data structures\n");
        cleanup_and_exit(1);
    }

    /* Create server socket */
    g_server_socket = create_server_socket();
    if (g_server_socket < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        cleanup_and_exit(1);
    }

    /* Write PID file */
    if (write_pid_file() < 0) {
        fprintf(stderr, "Failed to write PID file\n");
        cleanup_and_exit(1);
    }

    syslog(LOG_INFO, "DHCP Server started successfully on port %d", DHCP_SERVER_PORT);

    /* Log startup to server.log */
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
        write(log_fd, log_msg, strlen(log_msg));
        close(log_fd);
    }

    syslog(LOG_INFO, "Entering main loop, waiting for DHCP requests...");

    /* Main server loop */
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len;

    /* Schedule periodic maintenance */
    time_t last_compact = time(NULL);
    const time_t COMPACT_INTERVAL = 86400; /* 24 hours */

    int packet_count = 0;
    
    while (g_running) {
        /* Check if it's time to compact */
        time_t now = time(NULL);
        if (now - last_compact >= COMPACT_INTERVAL) {
            syslog(LOG_INFO, "Performing scheduled maintenance...");
            compact_lease_database(&g_config);
            last_compact = now;
        }

        /* Wait for packets (blocking, no timeout for now to debug) */
        addr_len = sizeof(client_addr);
        memset(buffer, 0, sizeof(buffer));
        
        syslog(LOG_DEBUG, "Waiting for DHCP packet...");
        
        ssize_t recv_len = recvfrom(g_server_socket, buffer, BUFFER_SIZE, 0,
                                    (struct sockaddr *)&client_addr, &addr_len);

        if (recv_len < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal - check g_running flag */
                syslog(LOG_DEBUG, "recvfrom interrupted by signal");
                continue;
            }
            syslog(LOG_ERR, "recvfrom error: %s", strerror(errno));
            continue;
        }

        packet_count++;
        syslog(LOG_INFO, "Received packet #%d: %zd bytes from %s:%d", 
               packet_count, recv_len,
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        /* Process the DHCP request */
        struct dhcp_packet *request = (struct dhcp_packet *)buffer;
        struct dhcp_packet response;
        dhcp_options_t opts;

        memset(&response, 0, sizeof(response));
        
        syslog(LOG_DEBUG, "Parsing DHCP options...");
        if (parse_dhcp_options(request, &opts) < 0) {
            syslog(LOG_WARNING, "Failed to parse DHCP options");
            continue;
        }

        /* Check blacklist */
        char mac_str[MAC_STR_LEN];
        format_mac_address(request->chaddr, mac_str, sizeof(mac_str));
        
        syslog(LOG_DEBUG, "Checking blacklist for MAC: %s", mac_str);
        if (is_blacklisted(&g_config, mac_str)) {
            syslog(LOG_WARNING, "Blocked request from blacklisted MAC: %s", mac_str);
            continue;
        }

        syslog(LOG_DEBUG, "Processing DHCP message from %s", mac_str);
        if (process_dhcp_message(request, &response, &opts, &g_config) < 0) {
            syslog(LOG_DEBUG, "No response needed or error occurred for %s", mac_str);
            continue;
        }

        /* Send response */
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
        dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

        syslog(LOG_DEBUG, "Sending DHCP response (%zu bytes)...", sizeof(response));
        ssize_t sent = sendto(g_server_socket, &response, sizeof(response), 0,
                             (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (sent < 0) {
            syslog(LOG_ERR, "Failed to send response: %s", strerror(errno));
        } else {
            syslog(LOG_INFO, "Sent response to %s (%zd bytes)", mac_str, sent);
        }
    }

    /* Clean shutdown */
    syslog(LOG_INFO, "Main loop exited, cleaning up...");
    cleanup_and_exit(0);
    return 0;
}