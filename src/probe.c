#define _GNU_SOURCE
#include "probe.h"
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/ioctl.h>

// ARP payload for IPv4 over Ethernet (the kernel adds the Ethernet header)
struct arp_ipv4 {
	uint16_t htype, ptype;
	uint8_t hlen, plen;
	uint16_t op;
	uint8_t sha[6];
	uint8_t spa[4];
	uint8_t tha[6];
	uint8_t tpa[4];
} __attribute__((packed));

int probe_open(probe_ctx_t *p, int worker_index) {
	p->arp_fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ARP));
	p->icmp_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	p->ping_id = (uint16_t)((getpid() << 4) ^ worker_index);

	if(p->arp_fd < 0 && p->icmp_fd < 0) {
		if(worker_index == 0) {
			syslog(LOG_WARNING, "Conflict check unavailable (needs root / "
								"CAP_NET_RAW): %s — offering addresses unchecked",
				   strerror(errno));
		}

		return -1;
	}

	if(p->arp_fd < 0 && worker_index == 0) {
		syslog(LOG_WARNING, "ARP conflict check unavailable: %s — using ping only",
			   strerror(errno));
	}

	return 0;
}

void probe_close(probe_ctx_t *p) {
	if(p->arp_fd >= 0) {
		close(p->arp_fd);
		p->arp_fd = -1;
	}
	if(p->icmp_fd >= 0) {
		close(p->icmp_fd);
		p->icmp_fd = -1;
	}
}

static long now_ms(void) {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

// Drop queued ARP and ICMP packets.
static void drain(int fd) {
	char buf[1500];

	while(recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
	}
}

static int arp_probe(probe_ctx_t *p, uint32_t ip, int ifindex, int timeout_ms,
					 char *who, size_t wholen) {
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	if(!if_indextoname((unsigned)ifindex, ifr.ifr_name))
		return -1;
	if(ioctl(p->arp_fd, SIOCGIFHWADDR, &ifr) < 0)
		return -1;
	if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return -1; // e.g. loopback

	struct arp_ipv4 req;
	memset(&req, 0, sizeof(req));
	req.htype = htons(ARPHRD_ETHER);
	req.ptype = htons(ETH_P_IP);
	req.hlen = 6;
	req.plen = 4;
	req.op = htons(ARPOP_REQUEST);
	memcpy(req.sha, ifr.ifr_hwaddr.sa_data, 6);
	// spa stays 0.0.0.0: a probe, so nobody's ARP cache learns anything
	memcpy(req.tpa, &ip, 4);

	struct sockaddr_ll to;
	memset(&to, 0, sizeof(to));
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(ETH_P_ARP);
	to.sll_ifindex = ifindex;
	to.sll_halen = 6;
	memset(to.sll_addr, 0xff, 6);

	drain(p->arp_fd);
	long deadline = now_ms() + timeout_ms;
	// Two probes, half the timeout apart: Wi-Fi drops broadcasts now and then
	int sent = 0;
	long next_send = 0;

	for(;;) {
		long t = now_ms();

		if(sent < 2 && t >= next_send) {
			if(sendto(p->arp_fd, &req, sizeof(req), 0,
					  (struct sockaddr *)&to, sizeof(to)) < 0)
				return -1;
			sent++;
			next_send = t + timeout_ms / 2;
		}

		long wait = (sent < 2 ? next_send : deadline) - t;
		if(t >= deadline)
			return 0;
		if(wait > deadline - t)
			wait = deadline - t;
		if(wait < 1)
			wait = 1;

		struct pollfd pfd = {.fd = p->arp_fd, .events = POLLIN};
		if(poll(&pfd, 1, (int)wait) <= 0)
			continue;

		struct arp_ipv4 rep;
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(p->arp_fd, &rep, sizeof(rep), 0,
							 (struct sockaddr *)&from, &fl);
		if(n < (ssize_t)sizeof(rep) || rep.plen != 4 || rep.hlen != 6)
			continue;
		if(from.sll_pkttype == PACKET_OUTGOING)
			continue; // our own probe
		// A reply from the address — or its owner announcing/probing it
		if(memcmp(rep.spa, &ip, 4) != 0)
			continue;
		snprintf(who, wholen, "%02X:%02X:%02X:%02X:%02X:%02X",
				 rep.sha[0], rep.sha[1], rep.sha[2], rep.sha[3], rep.sha[4], rep.sha[5]);

		return 1;
	}
}

static uint16_t csum(const void *data, size_t len) {
	const uint16_t *w = data;
	uint32_t sum = 0;

	for(; len > 1; len -= 2)
		sum += *w++;
	if(len)
		sum += *(const uint8_t *)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	return (uint16_t)~sum;
}

static int ping_probe(probe_ctx_t *p, uint32_t ip, int timeout_ms,
					  char *who, size_t wholen) {
	struct {
		struct icmphdr h;
		char payload[16];
	} echo;

	memset(&echo, 0, sizeof(echo));
	static uint16_t seq_counter;
	uint16_t seq = __atomic_add_fetch(&seq_counter, 1, __ATOMIC_RELAXED);
	echo.h.type = ICMP_ECHO;
	echo.h.un.echo.id = htons(p->ping_id);
	echo.h.un.echo.sequence = htons(seq);
	snprintf(echo.payload, sizeof(echo.payload), "dhcp-probe");
	echo.h.checksum = csum(&echo, sizeof(echo));

	struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = ip};
	drain(p->icmp_fd);
	if(sendto(p->icmp_fd, &echo, sizeof(echo), 0, (struct sockaddr *)&to, sizeof(to)) < 0)
		return -1;

	long deadline = now_ms() + timeout_ms;

	for(;;) {
		long left = deadline - now_ms();
		if(left <= 0)
			return 0;
		struct pollfd pfd = {.fd = p->icmp_fd, .events = POLLIN};
		if(poll(&pfd, 1, (int)left) <= 0)
			continue;

		char buf[1500];
		struct sockaddr_in from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(p->icmp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
		if(n < (ssize_t)sizeof(struct iphdr))
			continue;
		const struct iphdr *iph = (const struct iphdr *)buf;
		size_t hl = (size_t)iph->ihl * 4;
		if((size_t)n < hl + sizeof(struct icmphdr))
			continue;
		const struct icmphdr *r = (const struct icmphdr *)(buf + hl);
		if(r->type != ICMP_ECHOREPLY || from.sin_addr.s_addr != ip)
			continue;
		if(ntohs(r->un.echo.id) != p->ping_id || ntohs(r->un.echo.sequence) != seq)
			continue;
		inet_ntop(AF_INET, &from.sin_addr, who, (socklen_t)wholen);

		return 1;
	}
}

int probe_address(probe_ctx_t *p, uint32_t ip, int ifindex, bool on_link,
				  int timeout_ms, char *who, size_t wholen) {
	if(!p || timeout_ms <= 0)
		return -1;
	if(on_link && ifindex > 0 && p->arp_fd >= 0) {
		int r = arp_probe(p, ip, ifindex, timeout_ms, who, wholen);
		if(r >= 0)
			return r;
	}
	if(p->icmp_fd >= 0)
		return ping_probe(p, ip, timeout_ms, who, wholen);

	return -1;
}
