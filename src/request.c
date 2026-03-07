#include "request.h"

/* Log DHCP interaction to the server log file */
void log_dhcp_interaction(dhcp_config_t *config, const char *message_type,
                          const char *mac, const char *hostname, const char *ip) {
    if (!config || !config->log_path) return;

    int fd = open(config->log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;

    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_now = localtime_r(&now, &tm_buf);
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
                         size_t *pkt_len,
                         dhcp_result_t *result) {
    if (!request || !response || !opts || !config || !pkt_len || !result) {
        syslog(LOG_ERR, "process_dhcp_message: NULL parameter");
        return -1;
    }

    memset(result, 0, sizeof(*result));

    char mac_str[MAC_STR_LEN];
    format_mac_address(request->chaddr, mac_str, sizeof(mac_str));
    snprintf(result->mac, sizeof(result->mac), "%s", mac_str);

    /* Resolve the device identifier used for all lease lookups */
    char device_id[256];
    get_device_identifier(mac_str, opts, device_id, sizeof(device_id));
    snprintf(result->device_id, sizeof(result->device_id), "%s", device_id);

    /* Capture hostname from options if present */
    if (opts->found_hostname && opts->hostname[0] != '\0')
        snprintf(result->hostname, sizeof(result->hostname), "%s", opts->hostname);

    switch (opts->message_type) {

        case DHCPDISCOVER:
            syslog(LOG_INFO, "DHCPDISCOVER from %s%s%s",
                   mac_str,
                   opts->found_hostname ? " hostname=" : "",
                   opts->found_hostname ? opts->hostname : "");

            if (build_offer(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPOFFER for %s", mac_str);
                return -1;
            }

            /* Capture offered IP for post-lock logging */
            {
                struct in_addr oa; oa.s_addr = response->yiaddr;
                inet_ntop(AF_INET, &oa, result->resp_ip, sizeof(result->resp_ip));
            }
            strncpy(result->req_log,  "DHCPDISCOVER", sizeof(result->req_log)  - 1);
            strncpy(result->resp_log, "DHCPOFFER",    sizeof(result->resp_log) - 1);
            syslog(LOG_INFO, "Sending DHCPOFFER %s to %s", result->resp_ip, mac_str);
            break;

        case DHCPREQUEST: {
            syslog(LOG_INFO, "DHCPREQUEST from %s", mac_str);

            uint32_t our_ip = inet_addr(config->server_ip);

            if (opts->found_server_id) {
                /* Client picked an offer — server ID present means SELECTING state */
                if (opts->server_identifier != our_ip) {
                    syslog(LOG_DEBUG,
                           "DHCPREQUEST for other server (0x%08X) from %s — discarding",
                           ntohl(opts->server_identifier), mac_str);
                    return -1;
                }

                /* Make sure it's actually asking for the IP we offered */
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
                /* No server ID but has a requested IP — client is rebooting and
                 * trying to reclaim the address it had before */
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

            } else {
                /* No server ID and no requested IP — client is renewing or rebinding.
                 * ciaddr is its current address; make sure it matches what we have. */
                if (request->ciaddr != 0) {
                    char *existing = find_existing_lease(device_id, config);
                    if (!existing) {
                        syslog(LOG_WARNING,
                               "DHCPREQUEST RENEWING: no lease for %s — NAK",
                               mac_str);
                        if (build_nak(response, request, config, pkt_len) < 0)
                            return -1;
                        return 0;
                    }
                    bool mismatch = (request->ciaddr != inet_addr(existing));
                    free(existing);
                    if (mismatch) {
                        syslog(LOG_WARNING,
                               "DHCPREQUEST RENEWING: ciaddr mismatch for %s — NAK",
                               mac_str);
                        if (build_nak(response, request, config, pkt_len) < 0)
                            return -1;
                        return 0;
                    }
                }
            }

            /* Record the requested IP for the log line */
            if (opts->found_requested_ip) {
                struct in_addr ra; ra.s_addr = opts->requested_ip;
                inet_ntop(AF_INET, &ra, result->req_ip, sizeof(result->req_ip));
            }

            if (build_ack(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build DHCPACK for %s", mac_str);
                return -1;
            }

            /* Grab the confirmed IP for the log and the lease file update */
            {
                struct in_addr ya; ya.s_addr = response->yiaddr;
                inet_ntop(AF_INET, &ya, result->resp_ip, sizeof(result->resp_ip));
            }

            /* Stamp the confirmed expiry time and hostname while we still hold the lock */
            update_lease_expiry(device_id,
                                time(NULL) + (time_t)config->lease_time,
                                config);
            update_node_hostname(config->mac_table, device_id,
                                 result->hostname[0] ? result->hostname : NULL);

            strncpy(result->req_log,  "DHCPREQUEST", sizeof(result->req_log)  - 1);
            strncpy(result->resp_log, "DHCPACK",     sizeof(result->resp_log) - 1);
            result->write_lease_db = true;
            syslog(LOG_INFO, "Sending DHCPACK %s to %s", result->resp_ip, mac_str);
            break;
        }

        case DHCPRELEASE:
            syslog(LOG_INFO, "DHCPRELEASE from %s (device %s)", mac_str, device_id);
            release_ip_address(device_id, config);
            strncpy(result->req_log, "DHCPRELEASE", sizeof(result->req_log) - 1);
            result->remove_lease_db = true;
            return -1;   /* no reply needed; the log entry goes out via req_log */

        case DHCPDECLINE:
            syslog(LOG_WARNING, "DHCPDECLINE from %s (device %s)", mac_str, device_id);
            if (opts->found_requested_ip)
                mark_ip_declined(opts->requested_ip, device_id, config);
            strncpy(result->req_log, "DHCPDECLINE", sizeof(result->req_log) - 1);
            return -1;   /* no reply needed */

        case DHCPINFORM:
            syslog(LOG_INFO, "DHCPINFORM from %s", mac_str);
            if (build_inform_ack(response, request, opts, config, pkt_len) < 0) {
                syslog(LOG_ERR, "Failed to build INFORM ACK for %s", mac_str);
                return -1;
            }
            strncpy(result->req_log,  "DHCPINFORM", sizeof(result->req_log)  - 1);
            strncpy(result->resp_log, "DHCPACK",    sizeof(result->resp_log) - 1);
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

    if (packet->op != 1) {
        syslog(LOG_WARNING, "Rejected non-BOOTREQUEST packet (op=%d)", packet->op);
        return -1;
    }

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
