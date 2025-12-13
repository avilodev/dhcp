#include "request.h"

/* Log DHCP interaction to server.log */
void log_dhcp_interaction(const char *message_type, const char *mac, 
                                 const char *hostname, const char *ip) {
    char server_log[256];
    snprintf(server_log, sizeof(server_log), "%s%s", SERVER_PATH, SERVER_LOG_FILE);
    
    int fd = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        time_t now = time(NULL);
        struct tm *tm_now = localtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_now); 
        
        char log_entry[512];
        if (hostname && hostname[0] != '\0') {
            if (ip && ip[0] != '\0') {
                snprintf(log_entry, sizeof(log_entry), 
                        "[%s] %s from %s (%s) -> %s\n",
                        timestamp, message_type, mac, hostname, ip);
            } else {
                snprintf(log_entry, sizeof(log_entry), 
                        "[%s] %s from %s (%s)\n",
                        timestamp, message_type, mac, hostname);
            }
        } else {
            if (ip && ip[0] != '\0') { 
                snprintf(log_entry, sizeof(log_entry), 
                        "[%s] %s from %s -> %s\n",
                        timestamp, message_type, mac, ip);
            } else {
                snprintf(log_entry, sizeof(log_entry), 
                        "[%s] %s from %s\n",
                        timestamp, message_type, mac);
            }
        }
        
        write(fd, log_entry, strlen(log_entry));
        close(fd);
    }
}

/* Process DHCP message based on type */
int process_dhcp_message(struct dhcp_packet *request,
                        struct dhcp_packet *response,
                        dhcp_options_t *opts,
                        dhcp_config_t *config) {
    if (!request || !response || !opts || !config) {
        syslog(LOG_ERR, "process_dhcp_message: NULL parameter");
        return -1;
    }

    char mac_str[MAC_STR_LEN];
    format_mac_address(request->chaddr, mac_str, sizeof(mac_str));

    switch (opts->message_type) {
        case DHCPDISCOVER:
            syslog(LOG_INFO, "DHCPDISCOVER from %s%s%s",
                   mac_str,
                   opts->found_hostname ? " (hostname: " : "",
                   opts->found_hostname ? opts->hostname : "");
            
            log_dhcp_interaction("DHCPDISCOVER", mac_str, 
                               opts->found_hostname ? opts->hostname : NULL, 
                               NULL);
            
            if (build_offer(response, request, opts, config) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPOFFER for %s", mac_str);
                return -1;
            }
            
            /* Log the offered IP */
            struct in_addr addr;
            addr.s_addr = response->yiaddr;
            char offered_ip[IP_STR_LEN];
            strncpy(offered_ip, inet_ntoa(addr), IP_STR_LEN - 1);
            offered_ip[IP_STR_LEN - 1] = '\0';
            
            log_dhcp_interaction("DHCPOFFER", mac_str,
                               opts->found_hostname ? opts->hostname : NULL,
                               offered_ip);
            
            syslog(LOG_INFO, "Sending DHCPOFFER to %s", mac_str);
            break;

        case DHCPREQUEST:
            if (opts->found_requested_ip) {
                struct in_addr addr;
                addr.s_addr = opts->requested_ip;
                char requested_ip[IP_STR_LEN];
                strncpy(requested_ip, inet_ntoa(addr), IP_STR_LEN - 1);
                requested_ip[IP_STR_LEN - 1] = '\0';
                
                log_dhcp_interaction("DHCPREQUEST", mac_str,
                                   opts->found_hostname ? opts->hostname : NULL,
                                   requested_ip);
            } else {
                log_dhcp_interaction("DHCPREQUEST", mac_str,
                                   opts->found_hostname ? opts->hostname : NULL,
                                   NULL);
            }
            
            syslog(LOG_INFO, "DHCPREQUEST from %s", mac_str);
            
            if (build_ack(response, request, opts, config) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPACK for %s", mac_str);
                return -1;
            }
            
            /* Update lease database (which now also logs to server.log) */
            if (update_lease_database(mac_str, opts, config) < 0) {
                syslog(LOG_WARNING, "Failed to update lease database for %s", mac_str);
            }
            
            syslog(LOG_INFO, "Sending DHCPACK to %s", mac_str);
            break;

        case DHCPRELEASE:
            syslog(LOG_INFO, "DHCPRELEASE from %s", mac_str);
            log_dhcp_interaction("DHCPRELEASE", mac_str, NULL, NULL);
            release_ip_address(mac_str, config);
            return -1;

        case DHCPDECLINE:
            syslog(LOG_WARNING, "DHCPDECLINE from %s", mac_str);
            log_dhcp_interaction("DHCPDECLINE", mac_str, NULL, NULL);
            if (opts->found_requested_ip) {
                mark_ip_declined(opts->requested_ip, config);
            }
            return -1;

        default:
            syslog(LOG_DEBUG, "Unsupported message type: %d from %s", 
                   opts->message_type, mac_str);
            return -1;
    }

    return 0;
}

/* Parse DHCP options */
int parse_dhcp_options(struct dhcp_packet *packet, dhcp_options_t *opts) {
    if (!packet || !opts) {
        return -1;
    }

    memset(opts, 0, sizeof(dhcp_options_t));
    
    if (ntohl(packet->magic_cookie) != DHCP_MAGIC_COOKIE) {
        syslog(LOG_WARNING, "Invalid magic cookie: 0x%08X", ntohl(packet->magic_cookie));
        return -1;
    }
    
    for (size_t i = 0; i < sizeof(packet->options); ) {
        uint8_t code = packet->options[i++];
        
        if (code == 0xFF) break;
        if (code == 0x00) continue;
        
        if (i >= sizeof(packet->options)) {
            syslog(LOG_WARNING, "Options parsing ran past end of buffer");
            break;
        }
        
        uint8_t len = packet->options[i++];
        
        if (i + len > sizeof(packet->options)) {
            syslog(LOG_WARNING, "Option length exceeds buffer bounds");
            break;
        }
        
        switch (code) {
            case 53: /* DHCP Message Type */
                if (len == 1) {
                    opts->message_type = packet->options[i];
                    opts->found_message_type = true;
                }
                break;
            case 50: /* Requested IP Address */
                if (len == 4) {
                    memcpy(&opts->requested_ip, &packet->options[i], 4);
                    opts->found_requested_ip = true;
                }
                break;
            case 54: /* Server Identifier */
                if (len == 4) {
                    memcpy(&opts->server_identifier, &packet->options[i], 4);
                    opts->found_server_id = true;
                }
                break;
            case 51: /* IP Address Lease Time */
                if (len == 4) {
                    memcpy(&opts->lease_time, &packet->options[i], 4);
                    opts->lease_time = ntohl(opts->lease_time);
                    opts->found_lease_time = true;
                }
                break;
            case 12: /* Hostname */
                memcpy(opts->hostname, &packet->options[i], len);
                opts->hostname[len] = '\0';
                opts->found_hostname = true;
                break;
            case 55: /* Parameter Request List */
                memcpy(opts->parameter_list, &packet->options[i], len);
                opts->parameter_list_len = len;
                break;
            case 61: /* Client Identifier */
                memcpy(opts->client_id, &packet->options[i], len);
                opts->client_id_len = len;
                opts->found_client_id = true;
                break;
        }
        
        i += len;
    }
    
    return 0;
}