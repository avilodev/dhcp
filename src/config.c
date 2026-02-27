#define _GNU_SOURCE
#include "config.h"

extern dhcp_config_t g_config;

/* Initialize server configuration */
int init_config(int argc, char **argv) {
    memset(&g_config, 0, sizeof(g_config));
    
    if (argc == 1) {
        g_config.start_ip = strdup("192.168.1.10");
        g_config.end_ip = strdup("192.168.1.254");
    } else if (argc == 3) {
        g_config.start_ip = strdup(argv[1]);
        g_config.end_ip = strdup(argv[2]);
    } else {
        fprintf(stderr, "Usage: %s [start_ip end_ip]\n", argv[0]);
        return -1;
    }

    if (!g_config.start_ip || !g_config.end_ip) {
        fprintf(stderr, "Error: Failed to allocate IP range strings\n");
        return -1;
    }

    /* Set fixed network configuration */
    g_config.server_ip   = strdup("192.168.1.2");
    g_config.subnet_mask = strdup("255.255.255.0");
    g_config.gateway     = strdup("192.168.1.1");
    g_config.domain_name = strdup("avilo");
    g_config.lease_time  = LEASE_TIME;
    
    /* Set DNS server to 192.168.1.2 as requested */
    g_config.dns_servers[0] = strdup("192.168.1.2");
    g_config.dns_count = 1;

    /* Validate all allocations succeeded */
    if (!g_config.server_ip || !g_config.subnet_mask ||
        !g_config.gateway || !g_config.domain_name ||
        !g_config.dns_servers[0]) {
        fprintf(stderr, "Error: Failed to allocate configuration strings\n");
        cleanup_config();
        return -1;
    }

    /* Validate IP addresses */
    if (!validate_ip_address(g_config.start_ip) || 
        !validate_ip_address(g_config.end_ip) ||
        !validate_ip_address(g_config.server_ip)) {
        fprintf(stderr, "Error: Invalid IP address configuration\n");
        cleanup_config();
        return -1;
    } 

    syslog(LOG_INFO, "Configuration initialized successfully");
    syslog(LOG_INFO, "  Start IP: %s", g_config.start_ip);
    syslog(LOG_INFO, "  End IP: %s", g_config.end_ip);
    syslog(LOG_INFO, "  Server IP: %s", g_config.server_ip);
    syslog(LOG_INFO, "  Gateway: %s", g_config.gateway);
    syslog(LOG_INFO, "  DNS: %s", g_config.dns_servers[0]);

    return 0;
}

/* Cleanup configuration memory */
void cleanup_config(void) {
    if (g_config.start_ip) {
        free(g_config.start_ip);
        g_config.start_ip = NULL;
    }
    if (g_config.end_ip) {
        free(g_config.end_ip);
        g_config.end_ip = NULL;
    }
    if (g_config.server_ip) {
        free(g_config.server_ip);
        g_config.server_ip = NULL;
    }
    if (g_config.subnet_mask) {
        free(g_config.subnet_mask);
        g_config.subnet_mask = NULL;
    }
    if (g_config.gateway) {
        free(g_config.gateway);
        g_config.gateway = NULL;
    }
    if (g_config.domain_name) {
        free(g_config.domain_name);
        g_config.domain_name = NULL;
    }
    for (int i = 0; i < g_config.dns_count; i++) {
        if (g_config.dns_servers[i]) {
            free(g_config.dns_servers[i]);
            g_config.dns_servers[i] = NULL;
        }
    }
    if (g_config.ip_table) {
        free_trie(g_config.ip_table);
        g_config.ip_table = NULL;
    }
    if (g_config.mac_table) {
        destroy_tree(g_config.mac_table);
        g_config.mac_table = NULL;
    }
    if (g_config.blacklist) {
        destroy_tree(g_config.blacklist);
        g_config.blacklist = NULL;
    }
}

/* Initialize data structures */
int init_data_structures(void) {
    syslog(LOG_INFO, "Initializing data structures...");
    
    g_config.ip_table = create_trie();
    if (!g_config.ip_table) {
        syslog(LOG_ERR, "Failed to create IP trie");
        return -1;
    }
    syslog(LOG_DEBUG, "  IP trie created");
    
    g_config.mac_table = create_tree();
    if (!g_config.mac_table) {
        syslog(LOG_ERR, "Failed to create MAC tree");
        return -1;
    }
    syslog(LOG_DEBUG, "  MAC tree created");
    
    g_config.blacklist = create_tree();
    if (!g_config.blacklist) {
        syslog(LOG_ERR, "Failed to create blacklist tree");
        return -1;
    }
    syslog(LOG_DEBUG, "  Blacklist tree created");

    /* Load existing leases from file */
    syslog(LOG_INFO, "Loading lease database...");
    if (load_lease_database(&g_config) < 0) {
        syslog(LOG_WARNING, "Failed to load lease database, starting fresh");
    } else {
        syslog(LOG_INFO, "  Lease database loaded");
    }

    /* Load static IP assignments */
    syslog(LOG_INFO, "Loading static assignments...");
    if (load_static_assignments(&g_config) < 0) {
        syslog(LOG_INFO, "No static assignments found");
    } else {
        syslog(LOG_INFO, "  Static assignments loaded");
    }

    /* Load blacklist */
    syslog(LOG_INFO, "Loading blacklist...");
    if (load_blacklist(&g_config) < 0) {
        syslog(LOG_INFO, "No blacklist found");
    } else {
        syslog(LOG_INFO, "  Blacklist loaded");
    }

    syslog(LOG_INFO, "Data structures initialized successfully");
    return 0;
}

/* Validate IP address format */
bool validate_ip_address(const char *ip) {
    if (!ip) return false;
    
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

/* Create and configure server socket */
int create_server_socket(void) {
    int sock;
    struct sockaddr_in server_addr;
    int opt = 1;

    syslog(LOG_INFO, "Creating server socket...");

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    syslog(LOG_DEBUG, "  Socket created");

    /* Allow broadcast packets */
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_BROADCAST: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Allow address reuse */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }
    
    /* Allow reusing the port (important for DHCP) */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        syslog(LOG_WARNING, "Failed to set SO_REUSEPORT: %s (not critical)", strerror(errno));
    }
    
    syslog(LOG_DEBUG, "  Socket options set");

    /* Bind to DHCP server port on ALL interfaces */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;  /* Listen on all interfaces */

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
        fprintf(stderr, "Error: Failed to bind socket on port %d: %s\n", 
                DHCP_SERVER_PORT, strerror(errno));
        fprintf(stderr, "Note: You may need to run as root or with CAP_NET_BIND_SERVICE\n");
        close(sock);
        return -1;
    }
    syslog(LOG_INFO, "Socket bound to 0.0.0.0:%d (all interfaces)", DHCP_SERVER_PORT);
    
    if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set IP_PKTINFO: %s", strerror(errno));
        close(sock);
        return -1;
    }
    syslog(LOG_DEBUG, "  IP_PKTINFO enabled");

    /* Verify socket can receive broadcasts */
    int broadcast_enabled;
    socklen_t blen = sizeof(broadcast_enabled);
    if (getsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enabled, &blen) == 0)
        syslog(LOG_INFO, "Broadcast enabled: %s", broadcast_enabled ? "YES" : "NO");

    return sock;
}
