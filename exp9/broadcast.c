#include "base.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet 
	iface_info_t *tx_port;
	
	list_for_each_entry(tx_port, &instance->iface_list, list) {
		if (tx_port != iface) {
			char *pkt_copy = malloc(len);
			memcpy(pkt_copy, packet, len);
			iface_send_packet(tx_port, pkt_copy, len);
			free(pkt_copy);
		}
	}
}
