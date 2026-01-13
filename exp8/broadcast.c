#include "base.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// Skip work when there is nothing meaningful to forward.
	if (!packet || len <= 0)
		return;

	iface_info_t *entry = NULL;
	list_for_each_entry(entry, &instance->iface_list, list) {
		if (entry == iface)
			continue;

		size_t bytes = (size_t)len;
		char *dup = malloc(bytes);
		if (!dup)
			continue;

		memcpy(dup, packet, bytes);
		iface_send_packet(entry, dup, len);
		free(dup);
	}
}
