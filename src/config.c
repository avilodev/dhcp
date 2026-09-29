#define _GNU_SOURCE
#include "config.h"
#include "cluster.h"
#include "ha.h"
#include "journal.h"

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

        char key[64], value[256], extra[64] = "";
        if (sscanf(p, "%63s %255s %63s", key, value, extra) < 2) continue;

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
        else if (strcmp(key, "journal")     == 0) { free(config->journal_path);  config->journal_path  = strdup(value); }
        else if (strcmp(key, "node_id")     == 0) { free(config->node_id);       config->node_id       = strdup(value); }
        else if (strcmp(key, "cluster_dir") == 0) { free(config->cluster_dir);   config->cluster_dir   = strdup(value); }
        else if (strcmp(key, "peer_key")    == 0) { free(config->peer_key_path); config->peer_key_path = strdup(value); }
        else if (strcmp(key, "role") == 0) {
            if      (strcmp(value, "node") == 0)       config->role = ROLE_NODE;
            else if (strcmp(value, "controller") == 0) config->role = ROLE_CONTROLLER;
            else syslog(LOG_WARNING, "dhcp.conf: role must be 'node' or 'controller'");
        }
        else if (strcmp(key, "controller") == 0) {
            free(config->controller_ip);
            config->controller_ip = strdup(value);
            if (extra[0]) config->controller_port = atoi(extra);
        }
        else if (strcmp(key, "peer_port") == 0)    config->peer_port    = atoi(value);
        else if (strcmp(key, "probe_timeout_ms") == 0) {
            int ms = atoi(value);
            if (ms >= 0 && ms <= 5000) config->probe_timeout_ms = ms;
            else syslog(LOG_WARNING, "dhcp.conf: probe_timeout_ms must be 0–5000");
        }
        else if (strcmp(key, "mclt") == 0)         config->mclt         = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(key, "peer_timeout") == 0) config->peer_timeout = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(key, "auto_partner_down") == 0)
            config->auto_partner_down = (uint32_t)strtoul(value, NULL, 10);
        else if (strcmp(key, "user") == 0) { free(config->run_as_user); config->run_as_user = strdup(value); }
        else if (strcmp(key, "dns") == 0) {
            if (config->dns_count < 4) {
                free(config->dns_servers[config->dns_count]);
                config->dns_servers[config->dns_count] = strdup(value);
                config->dns_count++;
            }
        }
        else if (strcmp(key, "ntp") == 0) {
            if (config->ntp_count < 4) {
                free(config->ntp_servers[config->ntp_count]);
                config->ntp_servers[config->ntp_count] = strdup(value);
                config->ntp_count++;
            }
        }
        else {
            syslog(LOG_WARNING, "dhcp.conf: unknown key '%s'", key);
        }
    }

    fclose(fp);
    return 0;
}

/* dirname(path) + "/" + leaf — where runtime files go when not configured */
static char *sibling(const char *path, const char *leaf) {
    char buf[4096];
    const char *slash = path ? strrchr(path, '/') : NULL;
    if (slash)
        snprintf(buf, sizeof(buf), "%.*s/%s", (int)(slash - path), path, leaf);
    else
        snprintf(buf, sizeof(buf), "%s", leaf);
    return strdup(buf);
}

/* Initialize server configuration from conf_path (NULL = DEFAULT_CONF_PATH).
 * Flags from the command line override the file. */
int init_config(const cli_options_t *opts) {
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

    g_config.role            = ROLE_NODE;
    g_config.peer_port       = DEFAULT_PEER_PORT;
    g_config.mclt            = DEFAULT_MCLT;
    g_config.peer_timeout    = DEFAULT_PEER_TIMEOUT;
    g_config.probe_timeout_ms = DEFAULT_PROBE_MS;

    const char *conf_path = (opts && opts->conf_path) ? opts->conf_path : DEFAULT_CONF_PATH;
    g_config.conf_path = strdup(conf_path);
    bool conf_loaded = (parse_config_file(conf_path, &g_config) == 0);
    if (!conf_loaded) {
        if (opts && opts->conf_path) {
            fprintf(stderr, "Error: Cannot open config file: %s\n", conf_path);
            cleanup_config();
            return -1;
        }
        syslog(LOG_INFO, "No config file at %s — using built-in defaults",
               conf_path);
    } else {
        syslog(LOG_INFO, "Loaded configuration from %s", conf_path);
    }

    /* Command-line flags win over the file */
    if (opts && opts->node_id) {
        free(g_config.node_id);
        g_config.node_id = strdup(opts->node_id);
    }
    if (opts && opts->controller) g_config.role = ROLE_CONTROLLER;

    /* Runtime files default to living next to the lease file */
    if (!g_config.journal_path)  g_config.journal_path  = sibling(g_config.lease_db_path, "leases.journal");
    if (!g_config.cluster_dir)   g_config.cluster_dir   = sibling(g_config.lease_db_path, "cluster");
    if (!g_config.peer_key_path) g_config.peer_key_path = sibling(g_config.lease_db_path, "peer.key");
    if (!g_config.controller_port) g_config.controller_port = g_config.peer_port;

    if (g_config.node_id && !g_config.node_id[0]) {
        free(g_config.node_id);
        g_config.node_id = NULL;
    }
    if (g_config.node_id && !valid_node_id(g_config.node_id)) {
        fprintf(stderr, "Error: node_id '%s' must be 1–15 characters of A-Z a-z 0-9 _ -\n",
                g_config.node_id);
        cleanup_config();
        return -1;
    }
    if (g_config.role == ROLE_CONTROLLER && !g_config.node_id) {
        fprintf(stderr, "Error: a controller needs a node_id\n");
        cleanup_config();
        return -1;
    }
    if (g_config.peer_port <= 0 || g_config.peer_port > 65535 ||
        g_config.controller_port <= 0 || g_config.controller_port > 65535) {
        fprintf(stderr, "Error: peer_port / controller port must be 1–65535\n");
        cleanup_config();
        return -1;
    }
    if (g_config.controller_ip && !validate_ip_address(g_config.controller_ip)) {
        fprintf(stderr, "Error: Invalid controller address: %s\n", g_config.controller_ip);
        cleanup_config();
        return -1;
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

    /* Validate every IP-valued setting so a typo fails fast at startup
     * instead of silently emitting 255.255.255.255 to clients. */
    const struct { const char *name; const char *val; } ip_settings[] = {
        { "start_ip",    g_config.start_ip    },
        { "end_ip",      g_config.end_ip      },
        { "server_ip",   g_config.server_ip   },
        { "subnet_mask", g_config.subnet_mask },
        { "gateway",     g_config.gateway     },
    };
    for (size_t i = 0; i < sizeof(ip_settings) / sizeof(ip_settings[0]); i++) {
        if (!validate_ip_address(ip_settings[i].val)) {
            fprintf(stderr, "Error: Invalid %s in configuration: %s\n",
                    ip_settings[i].name,
                    ip_settings[i].val ? ip_settings[i].val : "(null)");
            cleanup_config();
            return -1;
        }
    }
    for (int i = 0; i < g_config.dns_count; i++) {
        if (!validate_ip_address(g_config.dns_servers[i])) {
            fprintf(stderr, "Error: Invalid dns address in configuration: %s\n",
                    g_config.dns_servers[i] ? g_config.dns_servers[i] : "(null)");
            cleanup_config();
            return -1;
        }
    }
    for (int i = 0; i < g_config.ntp_count; i++) {
        if (!validate_ip_address(g_config.ntp_servers[i])) {
            fprintf(stderr, "Error: Invalid ntp address in configuration: %s\n",
                    g_config.ntp_servers[i] ? g_config.ntp_servers[i] : "(null)");
            cleanup_config();
            return -1;
        }
    }

    syslog(LOG_INFO, "Configuration:");
    syslog(LOG_INFO, "  IP range  : %s – %s", g_config.start_ip, g_config.end_ip);
    syslog(LOG_INFO, "  Server IP : %s",       g_config.server_ip);
    syslog(LOG_INFO, "  Gateway   : %s",       g_config.gateway);
    syslog(LOG_INFO, "  DNS       : %s",       g_config.dns_servers[0]);
    syslog(LOG_INFO, "  Lease     : %us",      g_config.lease_time);
    if (g_config.node_id)
        syslog(LOG_INFO, "  Cluster   : %s as %s, peer port %d", g_config.node_id,
               g_config.role == ROLE_CONTROLLER ? "controller" : "node",
               g_config.peer_port);
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
    free(g_config.run_as_user);    g_config.run_as_user    = NULL;
    free(g_config.journal_path);   g_config.journal_path   = NULL;
    free(g_config.node_id);        g_config.node_id        = NULL;
    free(g_config.cluster_dir);    g_config.cluster_dir    = NULL;
    free(g_config.controller_ip);  g_config.controller_ip  = NULL;
    free(g_config.peer_key_path);  g_config.peer_key_path  = NULL;
    free(g_config.conf_path);      g_config.conf_path      = NULL;

    for (int i = 0; i < 4; i++) {
        free(g_config.dns_servers[i]);
        g_config.dns_servers[i] = NULL;
    }
    g_config.dns_count = 0;

    for (int i = 0; i < 4; i++) {
        free(g_config.ntp_servers[i]);
        g_config.ntp_servers[i] = NULL;
    }
    g_config.ntp_count = 0;

    if (g_config.ip_table)  { free_trie(g_config.ip_table);      g_config.ip_table  = NULL; }
    if (g_config.mac_table) { destroy_tree(g_config.mac_table);   g_config.mac_table = NULL; }
    if (g_config.blacklist) { destroy_tree(g_config.blacklist);   g_config.blacklist = NULL; }
    if (g_config.ip_owner)  { destroy_tree(g_config.ip_owner);    g_config.ip_owner  = NULL; }
}

/* Initialize data structures and load persistent state.  Order matters:
 * statics first (they win any address), then the journal replays leases. */
int init_data_structures(void) {
    syslog(LOG_INFO, "Initializing data structures...");

    g_config.ip_table  = create_trie();
    g_config.mac_table = create_tree();
    g_config.blacklist = create_tree();
    g_config.ip_owner  = create_tree();
    if (!g_config.ip_table || !g_config.mac_table || !g_config.blacklist ||
        !g_config.ip_owner) {
        syslog(LOG_ERR, "Failed to create lease tables");
        return -1;
    }

    ha_setup(&g_config);
    if (g_config.node_id) {
        /* Shared settings, member list, static list and blacklist all come
         * from cluster_dir.  Missing is OK if a controller will push them. */
        if (cluster_load(&g_config, NULL, NULL, 0) < 0 && !g_config.controller_ip &&
            g_config.role == ROLE_NODE) {
            fprintf(stderr, "Error: cluster mode needs %s/cluster.conf (or a "
                    "'controller' line in dhcp.conf to fetch it from)\n",
                    g_config.cluster_dir);
            return -1;
        }
    } else {
        if (load_static_assignments(&g_config) < 0)
            syslog(LOG_INFO, "No static assignments found");
        if (load_blacklist(&g_config) < 0)
            syslog(LOG_INFO, "No blacklist found");
    }

    if (journal_init(&g_config) < 0) {
        fprintf(stderr, "Error: cannot open lease journal %s\n", g_config.journal_path);
        return -1;
    }

    syslog(LOG_INFO, "Data structures initialized");
    return 0;
}

/* Validate IP address format */
bool validate_ip_address(const char *ip) {
    if (!ip) return false;
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

/* One UDP socket on port 67, bound to addr (INADDR_ANY or one of our own
 * addresses).  quiet: don't log a bind failure (the caller decides). */
static int open_dhcp_socket(uint32_t addr, bool quiet) {
    int opt = 1;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_BROADCAST: %s", strerror(errno));
        close(sock); return -1;
    }
    /* Both reuse options: several servers on one machine all bind 0.0.0.0:67
     * (the kernel hands every one of them a copy of each broadcast). */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock); return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        syslog(LOG_WARNING, "SO_REUSEPORT not available: %s", strerror(errno));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = addr;

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server_addr.sin_addr, addr_str, sizeof(addr_str));
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        int err = errno;
        if (!quiet) {
            syslog(LOG_ERR, "Failed to bind %s:%d: %s", addr_str, DHCP_SERVER_PORT,
                   strerror(err));
            fprintf(stderr, "Error: bind failed on %s:%d: %s\n", addr_str,
                    DHCP_SERVER_PORT, strerror(err));
        }
        close(sock);
        errno = err;
        return -1;
    }
    syslog(LOG_INFO, "Socket bound to %s:%d", addr_str, DHCP_SERVER_PORT);

    if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
        syslog(LOG_ERR, "Failed to set IP_PKTINFO: %s", strerror(errno));
        close(sock); return -1;
    }
    return sock;
}

/* The shared socket: every broadcast DISCOVER/REQUEST arrives here.  The main
 * loop poll()s it with a timeout, so no SO_RCVTIMEO is needed. */
int create_server_socket(void) {
    syslog(LOG_INFO, "Creating server socket...");
    return open_dhcp_socket(INADDR_ANY, false);
}

/* A second socket on our own server_ip.  The kernel delivers packets sent to
 * that address (renewals, relays) only here, and replies sent through it come
 * from server_ip — which is what lets several servers share one machine, each
 * with its own address.  Returns -1 with errno = EADDRNOTAVAIL if server_ip
 * isn't an address of this machine. */
int create_own_socket(const char *server_ip) {
    return open_dhcp_socket(inet_addr(server_ip), true);
}
