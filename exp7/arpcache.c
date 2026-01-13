#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include <log.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	int found = 0;
	pthread_mutex_lock(&arpcache.lock);
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		struct arp_cache_entry *entry = &arpcache.entries[i];
		if (entry->valid && entry->ip4 == ip4) {
			memcpy(mac, entry->mac, ETH_ALEN);
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return found;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	
	int idx = -1;
	int empty_idx = -1;
	
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid) {
			if (arpcache.entries[i].ip4 == ip4) {
				idx = i;
				break;
			}
		} else if (empty_idx == -1) {
			empty_idx = i;
		}
	}

	if (idx == -1) {
		idx = (empty_idx != -1) ? empty_idx : (rand() % MAX_ARP_SIZE);
		arpcache.entries[idx].valid = 1;
		arpcache.entries[idx].ip4 = ip4;
	}

	memcpy(arpcache.entries[idx].mac, mac, ETH_ALEN);
	arpcache.entries[idx].added = time(NULL);

	struct arp_req *req, *req_next;
	list_for_each_entry_safe(req, req_next, &arpcache.req_list, list) {
		if (req->ip4 == ip4) {
			struct cached_pkt *pkt, *pkt_next;
			list_for_each_entry_safe(pkt, pkt_next, &req->cached_packets, list) {
				struct ether_header *eth = (struct ether_header *)pkt->packet;
				memcpy(eth->ether_dhost, mac, ETH_ALEN);
				memcpy(eth->ether_shost, req->iface->mac, ETH_ALEN);
				iface_send_packet(req->iface, pkt->packet, pkt->len);
				
				list_delete_entry(&pkt->list);
				free(pkt);
			}
			list_delete_entry(&req->list);
			free(req);
		}
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	pthread_mutex_lock(&arpcache.lock);

	struct cached_pkt *pkt = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	pkt->packet = malloc(len);
	memcpy(pkt->packet, packet, len);
	pkt->len = len;
	init_list_head(&pkt->list);

	struct arp_req *req = NULL;
	int found = 0;
	list_for_each_entry(req, &arpcache.req_list, list) {
		if (req->ip4 == ip4 && req->iface == iface) {
			found = 1;
			break;
		}
	}

	if (found) {
		list_add_tail(&pkt->list, &req->cached_packets);
	} else {
		req = (struct arp_req *)malloc(sizeof(struct arp_req));
		req->iface = iface;
		req->ip4 = ip4;
		req->sent = time(NULL);
		req->retries = 1;
		init_list_head(&req->list);
		init_list_head(&req->cached_packets);
		
		list_add_tail(&pkt->list, &req->cached_packets);
		list_add_tail(&req->list, &arpcache.req_list);
		
		arp_send_request(iface, ip4);
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		time_t now = time(NULL);

		for (int i = 0; i < MAX_ARP_SIZE; i++) {
			if (arpcache.entries[i].valid && (now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)) {
				arpcache.entries[i].valid = 0;
			}
		}

		struct arp_req *req, *req_next;
		list_for_each_entry_safe(req, req_next, &arpcache.req_list, list) {
			if (now - req->sent >= 1) {
				if (req->retries >= ARP_REQUEST_MAX_RETRIES) {
					struct cached_pkt *pkt, *pkt_next;
					list_for_each_entry_safe(pkt, pkt_next, &req->cached_packets, list) {
						pthread_mutex_unlock(&arpcache.lock);
						icmp_send_packet(pkt->packet, pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						pthread_mutex_lock(&arpcache.lock);
						
						list_delete_entry(&pkt->list);
						free(pkt->packet);
						free(pkt);
					}
					list_delete_entry(&req->list);
					free(req);
				} else {
					arp_send_request(req->iface, req->ip4);
					req->sent = now;
					req->retries++;
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}
	return NULL;
}
