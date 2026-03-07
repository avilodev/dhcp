#define _GNU_SOURCE
#include "config.h"

extern dhcp_config_t g_config;

/* Default config file location */
#define DEFAULT_CONF_PATH  SERVER_PATH "/misc/dhcp.conf"

/* Parse dhcp.conf — key/value pairs, '#' comments.
 * Overrides only keys that are present; unrecognised keys are warned. */
static int parse_config_file(const char *path, dhcp_config_t *config) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\n') continue;

        char key[64], value[256];
        if (sscanf(p, "%63s %255s", key, value) != 2) continue;

        if      (strcmp(key, "server_ip")   == 0) { free(config->server_ip);   config->server_ip   = strdup(value); }
        else if (strcmp(key, "start_ip")    == 0) { free(config->start_ip);    config->start_ip    = strdup(value); }
        else if (strcmp(key, "end_ip")      == 0) { free(config->end_ip);      config->end_ip      = strdup(value); }
        else if (strcmp(key, "subnet_mask") == 0) { free(config->subnet_mask); config->subnet_mask = strdup(value); }
        else if (strcmp(key, "gateway")     == 0) { free(config->gateway);     config->gateway     = strdup(value); }
        else if (strcmp(key, "domain")      == 0) { free(config->domain_name); config->domain_name = strdup(value); }
        else if (strcmp(key, "lease_db")    == 0) { free(config->lease_db_path);  config->lease_db_path  = strdup(value); }
        else if (strcmp(key, "static")      == 0) { free(config->static_path);    config->static_path    = strdup(value); }
        else if (strcmp(key, "blacklist")   == 0) { free(config->blacklist_path); config->blacklist_path = strdup(value); }
        else if (strcmp(key, "log")         == 0) { free(config->log_path);       config->log_path       = strdup(value); }
        else if (strcmp(key, "pid")         == 0) { free(config->pid_path);       config->pid_path       = strdup(value); }
        else if (strcmp(key, "lease_time")  == 0) {
            unsigned long t = strtoul(value, NULL, 10);
            if (t > 0) config->lease_time = (uint32_t)t;
        }
        else if (strcmp(key, "workers") == 0) {
            int n = atoi(value);
            if (n > 0 && n <= MAX_WORKERS) config->num_workers = n;
            else syslog(LOG_WARNING, "dhcp.conf: workers must be 1–%d", MAX_WORKERS);
        }
        else if (strcmp(key, "dump") == 0) { free(config->dump_path); config->dump_path = strdup(value); }
        else if (strcmp(key, "dns") == 0) {
            if (config->dns_count < 4) {
                free(config->dns_servers[config->dns_count]);
                config->dns_servers[config->dns_count] = strdup(value);
                config->dns_count++;
            }
        }
        else {
            syslog(LOG_WARNING, "dhcp.conf: unknown key '%s'", key);
        }
    }

    fclose(fp);
    return 0;
}

/* Initialize server configuration.
 * Usage: dhcp_server [config_file]
 * If no argument is given, reads DEFAULT_CONF_PATH. */
int init_config(int argc, char **argv) {
    memset(&g_config, 0, sizeof(g_config));

    /* Compile-time defaults for non-DNS settings */
    g_config.server_ip    = strdup("192.168.1.2");
    g_config.start_ip     = strdup("192.168.1.10");
    g_config.end_ip       = strdup("192.168.1.254");
    g_config.subnet_mask  = strdup("255.255.255.0");
    g_config.gateway      = strdup("192.168.1.1");
    g_config.domain_name  = strdup("avilo");
    g_config.lease_time   = LEASE_TIME;
    g_config.dns_count    = 0;          /* populated from file, or defaults below */
    g_config.num_workers    = DEFAULT_WORKERS;
    g_config.lease_db_path  = strdup(SERVER_PATH LEASE_DB_FILE);
    g_config.static_path    = strdup(SERVER_PATH STATIC_FILE);
    g_config.blacklist_path = strdup(SERVER_PATH BLACKLIST_FILE);
    g_config.log_path       = strdup(SERVER_PATH SERVER_LOG_FILE);
    g_config.pid_path       = strdup(SERVER_PATH PID_FILE);
    g_config.dump_path      = strdup(SERVER_PATH DUMP_FILE);

    if (!g_config.server_ip || !g_config.start_ip || !g_config.end_ip ||
        !g_config.subnet_mask || !g_config.gateway || !g_config.domain_name ||
        !g_config.lease_db_path || !g_config.static_path ||
        !g_config.blacklist_path || !g_config.log_path || !g_config.pid_path ||
        !g_config.dump_path) {
        fprintf(stderr, "Error: Failed to allocate default configuration\n");
        cleanup_config();
        return -1;
    }

    const char *conf_path = (argc >= 2) ? argv[1] : DEFAULT_CONF_PATH;
    bool conf_loaded = (parse_config_file(conf_path, &g_config) == 0);
    if (!conf_loaded) {
        if (argc >= 2) {
            fprintf(stderr, "Error: Cannot open config file: %s\n", conf_path);
            cleanup_config();
            return -1;
        }
        syslog(LOG_INFO, "No config file at %s — using built-in defaults",
               conf_path);
    } else {
        syslog(LOG_INFO, "Loaded configuration from %s", conf_path);
    }

    /* If no DNS servers were specified in the config file, apply defaults */
    if (g_config.dns_count == 0) {
        g_config.dns_servers[0] = strdup("192.168.1.2");
        g_config.dns_servers[1] = strdup("192.168.1.3");
        g_config.dns_count = 2;
        if (!g_config.dns_servers[0]) {
            cleanup_config();
            return -1;
        }
    }

    if (!validate_ip_address(g_config.start_ip) ||
        !validate_ip_address(g_config.end_ip)   ||
        !validate_ip_address(g_config.server_ip)) {
        fprintf(stderr, "Error: Invalid IP address in configuration\n");
        cleanup_config();
        return -1;
    }

    syslog(LOG_INFO, "Configuration:");
    syslog(LOG_INFO, "  IP range  : %s – %s", g_config.start_ip, g_config.end_ip);
    syslog(LOG_INFO, "  Server IP : %s",       g_config.server_ip);
    syslog(LOG_INFO, "  Gateway   : %s",       g_config.gateway);
    syslog(LOG_INFO, "  DNS       : %s",       g_config.dns_servers[0]);
    syslog(LOG_INFO, "  Lease     : %us",      g_config.lease_time);
    return 0;
}

/* Cleanup configuration memory */
void cleanup_config(void) {
    free(g_config.start_ip);       g_config.start_ip       = NULL;
    free(g_config.end_ip);         g_config.end_ip         = NULL;
    free(g_config.server_ip);      g_config.server_ip      = NULL;
    free(g_config.subnet_mask);    g_config.subnet_mask    = NULL;
    free(g_config.gateway);        g_config.gateway        = NULL;
    free(g_config.domain_name);    g_config.domain_name    = NULL;
    free(g_config.lease_db_path);  g_config.lease_db_path  = NULL;
    free(g_config.static_path);    g_config.static_path    = NULL;
    free(g_config.blacklist_path); g_config.blacklist_path = NULL;
    free(g_config.log_path);       g_config.log_path       = NULL;
    free(g_config.pid_path);       g_config.pid_path       = NULL;
    free(g_config.dump_path);      g_config.dump_path      = NULL;

    for (int i = 0; i < 4; i++) {
        free(g_config.dns_servers[i]);
        g_config.dns_servers[i] = NULL;
    }
    g_config.dns_count = 0;

    if (g_config.ip_table)  { free_trie(g_config.ip_table);      g_config.ip_table  = NULL; }
    if (g_config.mac_table) { destroy_tree(g_config.mac_table);   g_config.mac_table = NULL; }
    if (g_config.blacklist) { destroy_tree(g_config.blacklist);   g_config.blacklist = NULL; }
}

/* Initialize data structures and load persistent state */
int init_data_structures(void) {
    syslog(LOG_INFO, "Initializing data structures...");

    g_config.ip_table = create_trie();
    if (!g_config.ip_table) {
        syslog(LOG_ERR, "Failed to create IP trie");
        return -1;
    }
    g_config.mac_table = create_tree();
    if (!g_config.mac_table) {
        syslog(LOG_ERR, "Failed to create MAC tree");
        return -1;
    }
    g_config.blacklist = create_tree();
    if (!g_config.blacklist) {
        syslog(LOG_ERR, "Failed to create blacklist tree");
        return -1;
    }

    if (load_lease_database(&g_config) < 0)
        syslog(LOG_WARNING, "Failed to load lease database, starting fresh");

    if (load_static_assignments(&g_config) < 0)
        syslog(LOG_INFO, "No static assignments found");

    if (load_blacklist(&g_config) < 0)
        syslog(LOG_INFO, "No blacklist found");

    syslog(LOG_INFO, "Data structures initialized");
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

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_BROADCAST: %s", strerror(errno));
        close(sock); return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock); return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        syslog(LOG_WARNING, "SO_REUSEPORT not available: %s", strerror(errno));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
        fprintf(stderr, "Error: bind failed on port %d: %s\n",
                DHCP_SERVER_PORT, strerror(errno));
        close(sock); return -1;
    }
    syslog(LOG_INFO, "Socket bound to 0.0.0.0:%d", DHCP_SERVER_PORT);

    if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set IP_PKTINFO: %s", strerror(errno));
        close(sock); return -1;
    }

    /* Wake up every 60 s so the main loop can sweep expired leases even
     * when there is no network traffic. */
    struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        syslog(LOG_WARNING, "SO_RCVTIMEO not set: %s", strerror(errno));

    return sock;
}
