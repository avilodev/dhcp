#ifndef TYPES_H
#define TYPES_H

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <syslog.h>

#define MAXLINE 4096

/* DHCP Protocol Constants */
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68
#define DHCP_MAGIC_COOKIE   0x63825363

/* DHCP Message Types (RFC 2132) */
#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8

/* DHCP Packet Structure Sizes */
#define DHCP_CHADDR_LEN     16
#define DHCP_SNAME_LEN      64
#define DHCP_FILE_LEN       128
#define DHCP_OPTIONS_LEN    312

/* Configuration Constants */
#define LEASE_TIME          86400
#define MAX_RETRIES         3
#define BUFFER_SIZE         4096
#define MAC_STR_LEN         18
#define IP_STR_LEN          16

/* File Paths */
#define SERVER_PATH         "/home/avilo/dhcp"
#define LEASE_DB_FILE       "/misc/members.txt"     
#define STATIC_FILE         "/misc/static_list.txt"
#define BLACKLIST_FILE      "/misc/blacklist.txt"
#define PID_FILE            "/misc/server.pid"
#define SERVER_LOG_FILE     "/misc/server.log"

/* DHCP Packet Structure (RFC 2131) */
struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[DHCP_CHADDR_LEN];
    char     sname[DHCP_SNAME_LEN];
    char     file[DHCP_FILE_LEN];
    uint32_t magic_cookie;
    uint8_t  options[DHCP_OPTIONS_LEN];
} __attribute__((packed));

/* DHCP Options Structure */
typedef struct {
    uint8_t message_type;
    uint32_t requested_ip;
    uint32_t server_identifier;
    uint32_t lease_time;
    uint8_t parameter_list[256];
    uint8_t parameter_list_len;
    char hostname[256];
    uint8_t client_id[256];
    uint8_t client_id_len;
    bool found_message_type;
    bool found_requested_ip;
    bool found_server_id;
    bool found_lease_time;
    bool found_hostname;
    bool found_client_id;
} dhcp_options_t;

/* Server Configuration */
typedef struct {
    char *start_ip;
    char *end_ip;
    char *server_ip;
    char *subnet_mask;
    char *gateway;
    char *dns_servers[4];
    int dns_count;
    uint32_t lease_time;
    struct Trie *ip_table;
    struct Tree *mac_table;
    struct Tree *blacklist;
} dhcp_config_t;

/* Lease Information */
typedef struct {
    char mac[MAC_STR_LEN];
    char ip[IP_STR_LEN];
    char hostname[256];
    time_t expires;
    bool is_static;
} lease_entry_t;

void cleanup_config(void);

#endif /* TYPES_H */