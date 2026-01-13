#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
	char *packet_buf;
	int total_len;

	if (type == ICMP_ECHOREPLY) {
		struct icmphdr *in_icmp = (struct icmphdr *)IP_DATA(in_ip);
		int icmp_data_len = len - IP_HDR_SIZE(in_ip) - ETHER_HDR_SIZE;
		total_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_data_len;
		
		packet_buf = (char *)malloc(total_len);
		if (!packet_buf) return;

		struct icmphdr *new_icmp = (struct icmphdr *)(packet_buf + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
		memcpy(new_icmp, in_icmp, icmp_data_len);
		new_icmp->type = type;
		new_icmp->code = code;
		new_icmp->checksum = icmp_checksum(new_icmp, icmp_data_len);

		struct iphdr *new_ip = (struct iphdr *)(packet_buf + ETHER_HDR_SIZE);
		ip_init_hdr(new_ip, ntohl(in_ip->daddr), ntohl(in_ip->saddr), total_len - ETHER_HDR_SIZE, IPPROTO_ICMP);
		
		ip_send_packet(packet_buf, total_len);

	} else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		int ip_h_len = IP_HDR_SIZE(in_ip);
		int icmp_body_len = ip_h_len + 8;
		int icmp_total_len = ICMP_HDR_SIZE + icmp_body_len;
		total_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_total_len;

		packet_buf = (char *)malloc(total_len);
		if (!packet_buf) return;
		memset(packet_buf, 0, total_len);

		struct icmphdr *new_icmp = (struct icmphdr *)(packet_buf + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
		new_icmp->type = type;
		new_icmp->code = code;
		
		char *icmp_data_ptr = (char *)new_icmp + ICMP_HDR_SIZE;
		memcpy(icmp_data_ptr, in_ip, icmp_body_len);
		
		new_icmp->checksum = icmp_checksum(new_icmp, icmp_total_len);

		u32 target_ip = ntohl(in_ip->saddr);
		rt_entry_t *route = longest_prefix_match(target_ip);
		if (!route) {
			free(packet_buf);
			return;
		}

		struct iphdr *new_ip = (struct iphdr *)(packet_buf + ETHER_HDR_SIZE);
		ip_init_hdr(new_ip, route->iface->ip, target_ip, total_len - ETHER_HDR_SIZE, IPPROTO_ICMP);
		
		ip_send_packet(packet_buf, total_len);
	}
}
