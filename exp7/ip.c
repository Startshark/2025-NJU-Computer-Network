// #include "ip.h"
// #include "icmp.h"
// #include "arpcache.h"
// #include "rtable.h"
// #include "arp.h"

// #include "mospf_proto.h"
// #include "mospf_daemon.h"

// #include "log.h"

// #include <stdlib.h>
// #include <assert.h>

// // handle ip packet
// //
// // If the packet is ICMP echo request and the destination IP address is equal to
// // the IP address of the iface, send ICMP echo reply; otherwise, forward the
// // packet.
// void handle_ip_packet(iface_info_t *iface, char *packet, int len)
// {
// 	struct iphdr *ip = packet_to_ip_hdr(packet);
// 	u32 daddr = ntohl(ip->daddr);
// 	if (daddr == iface->ip) {
// 		if (ip->protocol == IPPROTO_ICMP) {
// 			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
// 			if (icmp->type == ICMP_ECHOREQUEST) {
// 				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
// 			}
// 		}
// 		else if (ip->protocol == IPPROTO_MOSPF) {
// 			handle_mospf_packet(iface, packet, len);
// 		}

// 		free(packet);
// 	}
// 	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
// 		assert(ip->protocol == IPPROTO_MOSPF);
// 		handle_mospf_packet(iface, packet, len);

// 		free(packet);
// 	}
// 	else {
// 		ip_forward_packet(daddr, packet, len);
// 	}
// }


// // TODO - implement this function
// void ip_forward_packet(u32 ip_dst, char *packet, int len)
// {
// 	//ip_dst已经是主机序了
// 	//log(DEBUG, "ip_forward_packet: got ip packet, len: %d", len);
// 	struct iphdr *ip = packet_to_ip_hdr(packet);
// 	ip->ttl--;
// 	if(ip->ttl <= 0){
// 		//log(DEBUG, "ip_forward_packet: ttl expired");
// 		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
// 		return;
// 	}
// 	//log(DEBUG, "hhh");
// 	rt_entry_t *entry = longest_prefix_match(ip_dst);
// 	//log(DEBUG, "ip_forward_packet: longest prefix match entry: %s", entry->iface->name);
// 	if(entry == NULL){
// 		//log(DEBUG, "ip_forward_packet: no route to network");
// 		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
// 		return;
// 	}
// 	//log(DEBUG, "ip_forward_packet: longest prefix match entry: %s", entry->iface->name);
// 	ip->checksum = 0;
// 	ip->checksum = ip_checksum(ip);
// 	if(entry->gw){
// 		//log(DEBUG, "ip_forward_packet: send packet by gw");
// 		iface_send_packet_by_arp(entry->iface, entry->gw, packet, len);
// 	}else{
// 		iface_send_packet_by_arp(entry->iface, ip_dst, packet, len);
// 	}
// 	//assert(0 && "TODO: function ip_forward_packet not implemented!");
// }

#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	//log(DEBUG, "handle_ip_packet: got ip packet, len: %d", len);
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			//log(DEBUG, "handle_ip_packet: got icmp packet");
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}

		free(packet); //说明是处理后被释放
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		//log(DEBUG, "MOSPF_all packet received");
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		if(ip->protocol == IPPROTO_ICMP){
			iface_info_t *iface_tmp = NULL;
			list_for_each_entry(iface_tmp, &instance->iface_list, list){
				if(iface_tmp->ip == daddr){//是路由器自身接口，只不过不是直连的那一个
					struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
					if(icmp->type == ICMP_ECHOREQUEST){
						icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
						free(packet);
						return;
					}
				}
			}
		}
		ip_forward_packet(daddr, packet, len);
	}
}

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	//ip_dst已经是主机序了
	//log(DEBUG, "ip_forward_packet: got ip packet, len: %d", len);
	struct iphdr *ip = packet_to_ip_hdr(packet);
	ip->ttl--;
	if(ip->ttl <= 0){
		//log(DEBUG, "ip_forward_packet: ttl expired");
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return;
	}
	//log(DEBUG, "hhh");
	rt_entry_t *entry = longest_prefix_match(ip_dst);
	//log(DEBUG, "ip_forward_packet: longest prefix match entry: %s", entry->iface->name);
	if(entry == NULL){
		//log(DEBUG, "ip_forward_packet: no route to network");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return;
	}
	//log(DEBUG, "ip_forward_packet: longest prefix match entry: %s", entry->iface->name);
	ip->checksum = 0;
	ip->checksum = ip_checksum(ip);
	if(entry->gw){
		//log(DEBUG, "ip_forward_packet: send packet by gw");
		iface_send_packet_by_arp(entry->iface, entry->gw, packet, len);
	}else{
		iface_send_packet_by_arp(entry->iface, ip_dst, packet, len);
	}
	//assert(0 && "TODO: function ip_forward_packet not implemented!");
}
