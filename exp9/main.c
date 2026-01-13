#include "base.h"
#include "ether.h"
#include "mac.h"
#include "utils.h"

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// handle packet
// 1. if the dest mac address is found in mac_port table, forward it; otherwise, 
// broadcast it.
// 2. put the src mac -> iface mapping into mac hash table.
void handle_packet(iface_info_t *iface, char *packet, int len)
{
	// TODO: implement the packet forwarding process here
	struct ether_header *header = (struct ether_header *)packet;
	u8 *s_addr = header->ether_shost;
	u8 *d_addr = header->ether_dhost;
	
	insert_mac_port(s_addr, iface);
	
	int is_broadcast_req = (memcmp(d_addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0);
	
	iface_info_t *target_iface = NULL;
	if (!is_broadcast_req) {
		target_iface = lookup_port(d_addr);
	}
	
	if (target_iface != NULL && target_iface != iface) {
		iface_send_packet(target_iface, packet, len);
	} else {
		broadcast_packet(iface, packet, len);
	}

	free(packet);
}

// run user stack, receive packet on each interface, and handle those packet
// like normal switch
void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;

	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, while we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					if (!iface) 
						continue;

					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
}

int main(int argc, const char **argv)
{
	if (getuid() && geteuid()) {
		printf("Permission denied, should be superuser!\n");
		exit(1);
	}

	init_ustack();

	init_mac_port_table();

	pthread_t t;
	pthread_create(&t, NULL, sweeping_mac_port_thread, NULL);

	ustack_run();

	return 0;
}
