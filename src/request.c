#include "request.h"

/* Log DHCP interaction to server.log */
void log_dhcp_interaction(const char *message_type, const char *mac,
                          const char *hostname, const char *ip) {
    char server_log[256];
    snprintf(server_log, sizeof(server_log), "%s%s", SERVER_PATH, SERVER_LOG_FILE);

    int fd = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_now);

    char log_entry[512];
    if (hostname && hostname[0] != '\0') {
        if (ip && ip[0] != '\0')
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] %s from %s (%s) -> %s\n",
                     timestamp, message_type, mac, hostname, ip);
        else
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] %s from %s (%s)\n",
                     timestamp, message_type, mac, hostname);
    } else {
        if (ip && ip[0] != '\0')
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] %s from %s -> %s\n",
                     timestamp, message_type, mac, ip);
        else
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] %s from %s\n",
                     timestamp, message_type, mac);
    }

    if (write(fd, log_entry, strlen(log_entry)) < 0)
        syslog(LOG_WARNING, "Failed to write server log: %s", strerror(errno));
    close(fd);
}

int process_dhcp_message(struct dhcp_packet *request,
                         struct dhcp_packet *response,
                         dhcp_options_t *opts,
                         dhcp_config_t *config,
                         size_t *pkt_len) {
    if (!request || !response || !opts || !config || !pkt_len) {
        syslog(LOG_ERR, "process_dhcp_message: NULL parameter");
        return -1;
    }

    char mac_str[MAC_STR_LEN];
    format_mac_address(request->chaddr, mac_str, sizeof(mac_str));

    /* Resolve the device identifier used for all lease lookups */
    char device_id[256];
    get_device_identifier(mac_str, opts, device_id, sizeof(device_id));

    switch (opts->message_type) {

        case DHCPDISCOVER:
            syslog(LOG_INFO, "DHCPDISCOVER from %s%s%s",
                   mac_str,
                   opts->found_hostname ? " hostname=" : "",
                   opts->found_hostname ? opts->hostname : "");

            log_dhcp_interaction("DHCPDISCOVER", mac_str,
                                 opts->found_hostname ? opts->hostname : NULL,
                                 NULL);

            if (build_offer(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPOFFER for %s", mac_str);
                return -1;
            }

            {
                struct in_addr oa; oa.s_addr = response->yiaddr;
                char offered_ip[IP_STR_LEN];
                strncpy(offered_ip, inet_ntoa(oa), IP_STR_LEN - 1);
                offered_ip[IP_STR_LEN - 1] = '\0';
                log_dhcp_interaction("DHCPOFFER", mac_str,
                                     opts->found_hostname ? opts->hostname : NULL,
                                     offered_ip);
                syslog(LOG_INFO, "Sending DHCPOFFER %s to %s", offered_ip, mac_str);
            }
            break;

        /* ------------------------------------------------------------------ */
        case DHCPREQUEST: {
            syslog(LOG_INFO, "DHCPREQUEST from %s", mac_str);

            uint32_t our_ip = inet_addr(config->server_ip);

            if (opts->found_server_id) {
                /* SELECTING state: client is responding to an OFFER. */
                if (opts->server_identifier != our_ip) {
                    syslog(LOG_DEBUG,
                           "DHCPREQUEST for other server (0x%08X) from %s — discarding",
                           ntohl(opts->server_identifier), mac_str);
                    return -1;
                }

                /* Verify the requested IP matches the lease we issued */
                if (opts->found_requested_ip) {
                    char *expected = find_existing_lease(device_id, config);
                    bool mismatch = (!expected ||
                                    opts->requested_ip != inet_addr(expected));
                    free(expected);
                    if (mismatch) {
                        syslog(LOG_WARNING,
                               "DHCPREQUEST SELECTING: IP mismatch for %s — NAK",
                               mac_str);
                        if (build_nak(response, request, config, pkt_len) < 0)
                            return -1;
                        return 0;
                    }
                }

            } else if (opts->found_requested_ip) {
                /* INIT-REBOOT state: client rebooted and wants to reconfirm its previous address. */
                char *existing = find_existing_lease(device_id, config);
                if (!existing) {
                    syslog(LOG_INFO,
                           "DHCPREQUEST INIT-REBOOT: no record for %s — discarding",
                           mac_str);
                    return -1;
                }
                bool mismatch = (opts->requested_ip != inet_addr(existing));
                free(existing);
                if (mismatch) {
                    syslog(LOG_WARNING,
                           "DHCPREQUEST INIT-REBOOT: IP mismatch for %s — NAK",
                           mac_str);
                    if (build_nak(response, request, config, pkt_len) < 0)
                        return -1;
                    return 0;
                }

            }
            /* else: RENEWING/REBINDING — ciaddr is set, no server_id, no opt 50.
             * Just confirm the existing lease. */

            if (opts->found_requested_ip) {
                struct in_addr ra; ra.s_addr = opts->requested_ip;
                char req_ip[IP_STR_LEN];
                strncpy(req_ip, inet_ntoa(ra), IP_STR_LEN - 1);
                req_ip[IP_STR_LEN - 1] = '\0';
                log_dhcp_interaction("DHCPREQUEST", mac_str,
                                     opts->found_hostname ? opts->hostname : NULL,
                                     req_ip);
            } else {
                log_dhcp_interaction("DHCPREQUEST", mac_str,
                                     opts->found_hostname ? opts->hostname : NULL,
                                     NULL);
            }

            if (build_ack(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPACK for %s", mac_str);
                return -1;
            }

            update_lease_expiry(device_id,
                                time(NULL) + (time_t)config->lease_time,
                                config);

            if (update_lease_database(mac_str, opts, config) < 0)
                syslog(LOG_WARNING, "Failed to update lease database for %s",
                       mac_str);

            syslog(LOG_INFO, "Sending DHCPACK to %s", mac_str);
            break;
        }

        case DHCPRELEASE:
            syslog(LOG_INFO, "DHCPRELEASE from %s (device %s)", mac_str, device_id);
            log_dhcp_interaction("DHCPRELEASE", mac_str, NULL, NULL);
            release_ip_address(device_id, config);
            return -1;   /* no response */

        case DHCPDECLINE:
            syslog(LOG_WARNING, "DHCPDECLINE from %s (device %s)", mac_str, device_id);
            log_dhcp_interaction("DHCPDECLINE", mac_str, NULL, NULL);
            if (opts->found_requested_ip)
                mark_ip_declined(opts->requested_ip, device_id, config);
            return -1;   /* no response */

        case DHCPINFORM:
            syslog(LOG_INFO, "DHCPINFORM from %s", mac_str);
            log_dhcp_interaction("DHCPINFORM", mac_str,
                                 opts->found_hostname ? opts->hostname : NULL,
                                 NULL);
            if (build_inform_ack(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build INFORM ACK for %s", mac_str);
                return -1;
            }
            syslog(LOG_INFO, "Sending INFORM ACK to %s", mac_str);
            break;

        default:
            syslog(LOG_DEBUG, "Unsupported DHCP message type %d from %s",
                   opts->message_type, mac_str);
            return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * parse_dhcp_options
 * -------------------------------------------------------------------------- */
int parse_dhcp_options(struct dhcp_packet *packet, dhcp_options_t *opts) {
    if (!packet || !opts)
        return -1;

    memset(opts, 0, sizeof(dhcp_options_t));

    if (ntohl(packet->magic_cookie) != DHCP_MAGIC_COOKIE) {
        syslog(LOG_WARNING, "Invalid magic cookie: 0x%08X",
               ntohl(packet->magic_cookie));
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
            case 12: /* Hostname — len is uint8_t (max 255); hostname[256] always fits */
                memcpy(opts->hostname, &packet->options[i], len);
                opts->hostname[len] = '\0';
                opts->found_hostname = true;
                break;
            case 55: /* Parameter Request List — parameter_list[256] always fits */
                memcpy(opts->parameter_list, &packet->options[i], len);
                opts->parameter_list_len = len;
                break;
            case 61: /* Client Identifier — client_id[256] always fits */
                memcpy(opts->client_id, &packet->options[i], len);
                opts->client_id_len = len;
                opts->found_client_id = true;
                break;
        }

        i += len;
    }

    return 0;
}
