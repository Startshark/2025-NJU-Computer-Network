#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// If the packet is ICMP echo request and the destination IP address is equal to the IP address of the iface, send ICMP echo reply.
// Otherwise, forward the packet.
// Tips:
// You can use struct iphdr *ip = packet_to_ip_hdr(packet); in ip.h to get the ip header in a packet.
// You can use struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip); in ip.h to get the icmp header in a packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 dest_ip = ntohl(ip_hdr->daddr);

	if (dest_ip == iface->ip) {
		if (ip_hdr->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + IP_HDR_SIZE(ip_hdr));
			if (icmp_hdr->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
				return;
			}
		}
		free(packet);
	} else {
		ip_forward_packet(dest_ip, packet, len);
	}
}

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);

	if (ip_hdr->ttl <= 1) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return;
	}

	ip_hdr->ttl--;
	ip_hdr->checksum = ip_checksum(ip_hdr);

	rt_entry_t *route = longest_prefix_match(ip_dst);
	if (!route) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return;
	}

	u32 next_hop = route->gw ? route->gw : ip_dst;
	iface_send_packet_by_arp(route->iface, next_hop, packet, len);
}