#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	u32 target_ip = ntohl(arp_hdr->arp_tpa);

	if (target_ip != iface->ip) {
		free(packet);
		return;
	}

	u16 op_code = ntohs(arp_hdr->arp_op);
	if (op_code == ARPOP_REQUEST) {
		arp_send_reply(iface, arp_hdr);
	}
	
	arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);
	free(packet);
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char *reply_packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	if (!reply_packet) {
		perror("Failed to malloc reply packet");
		return;
	}

	struct ether_header *eth_h = (struct ether_header *)reply_packet;
	memcpy(eth_h->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eth_h->ether_shost, iface->mac, ETH_ALEN);
	eth_h->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp_h = (struct ether_arp *)(reply_packet + ETHER_HDR_SIZE);
	arp_h->arp_hrd = htons(ARPHRD_ETHER);
	arp_h->arp_pro = htons(ETH_P_IP);
	arp_h->arp_hln = ETH_ALEN;
	arp_h->arp_pln = 4;
	arp_h->arp_op = htons(ARPOP_REPLY);
	memcpy(arp_h->arp_sha, iface->mac, ETH_ALEN);
	arp_h->arp_spa = htonl(iface->ip);
	memcpy(arp_h->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	arp_h->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, reply_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dest_ip)
{
	char *req_packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	if (!req_packet) {
		perror("Failed to malloc request packet");
		return;
	}

	struct ether_header *eth_h = (struct ether_header *)req_packet;
	memset(eth_h->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth_h->ether_shost, iface->mac, ETH_ALEN);
	eth_h->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp_h = (struct ether_arp *)(req_packet + ETHER_HDR_SIZE);
	arp_h->arp_hrd = htons(ARPHRD_ETHER);
	arp_h->arp_pro = htons(ETH_P_IP);
	arp_h->arp_hln = ETH_ALEN;
	arp_h->arp_pln = 4;
	arp_h->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp_h->arp_sha, iface->mac, ETH_ALEN);
	arp_h->arp_spa = htonl(iface->ip);
	memset(arp_h->arp_tha, 0, ETH_ALEN);
	arp_h->arp_tpa = htonl(dest_ip);

	iface_send_packet(iface, req_packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send (IP) packet through arpcache lookup 
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dest_ip, char *packet, int len)
{
	u8 mac[ETH_ALEN];
	if (arpcache_lookup(dest_ip, mac)) {
		struct ether_header *eth_h = (struct ether_header *)packet;
		memcpy(eth_h->ether_dhost, mac, ETH_ALEN);
		memcpy(eth_h->ether_shost, iface->mac, ETH_ALEN);
		eth_h->ether_type = htons(ETH_P_IP);
		iface_send_packet(iface, packet, len);
	} else {
		arpcache_append_packet(iface, dest_ip, packet, len);
	}
}


// void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
// {
// 	int len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
// 	char *packet = malloc(len);
// 	struct ether_header *eh = (struct ether_header *)packet;
// 	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
// 	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
// 	eh->ether_type = htons(ETH_P_ARP);
// 	struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
// 	arp->arp_hrd = htons(ARPHRD_ETHER);
// 	arp->arp_pro = htons(ETH_P_IP);
// 	arp->arp_hln = ETH_ALEN;
// 	arp->arp_pln = 4;
// 	arp->arp_op = htons(ARPOP_REPLY);
// 	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
// 	arp->arp_spa = htonl(iface->ip);
// 	memcpy(arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
// 	arp->arp_tpa = req_hdr->arp_spa;
// 	log(DEBUG, "handle_arp_packet: send ARP reply.");
// 	iface_send_packet(iface, packet, len);
// }


// void arp_send_request(iface_info_t *iface, u32 dst_ip)
// {
// 	log(DEBUG, "arp_send_request: send ARP request.");
// 	int len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
// 	char* packet = malloc(len);
// 	struct ether_header *eh = (struct ether_header *)packet;
// 	memset(eh->ether_dhost, 0xFF, ETH_ALEN);
// 	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
// 	eh->ether_type = htons(ETH_P_ARP);
// 	struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
// 	arp->arp_hrd = htons(ARPHRD_ETHER);
// 	arp->arp_pro = htons(ETH_P_IP);
// 	arp->arp_hln = ETH_ALEN;
// 	arp->arp_pln = 4;
// 	arp->arp_op = htons(ARPOP_REQUEST);
// 	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
// 	arp->arp_spa = htonl(iface->ip);
// 	memset(arp->arp_tha, 0x00, ETH_ALEN);
// 	arp->arp_tpa = htonl(dst_ip);
// 	iface_send_packet(iface, packet, len);
// }


// void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
// {
// 	u8 dst_mac[ETH_ALEN];
// 	if(arpcache_lookup(dst_ip, dst_mac)){
// 		log(DEBUG, "找到了");
// 		struct ether_header *eh = (struct ether_header *)packet;
// 		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
// 		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
// 		eh->ether_type = htons(ETH_P_IP);
// 		iface_send_packet(iface, packet, len);
// 	}else{
// 		log(DEBUG, "没有找到");
// 		arpcache_append_packet(iface, dst_ip, packet, len);
// 	}
// }
