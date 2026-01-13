// #include "mospf_daemon.h"
// #include "mospf_proto.h"
// #include "mospf_nbr.h"
// #include "mospf_database.h"

// #include "ip.h"

// #include "list.h"
// #include "log.h"

// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <pthread.h>
// #include "rtable.h"

// extern ustack_t *instance;

// pthread_mutex_t mospf_lock;

// void mospf_init()
// {
// 	pthread_mutex_init(&mospf_lock, NULL);

// 	instance->area_id = 0;
// 	// get the ip address of the first interface
// 	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
// 	instance->router_id = iface->ip;
// 	instance->sequence_num = 0;
// 	instance->lsuint = MOSPF_DEFAULT_LSUINT;

// 	iface = NULL;
// 	list_for_each_entry(iface, &instance->iface_list, list) {
// 		iface->helloint = MOSPF_DEFAULT_HELLOINT;
// 		init_list_head(&iface->nbr_list);
// 	}

// 	init_mospf_db();
// }

// void *sending_mospf_hello_thread(void *param);
// void *sending_mospf_lsu_thread(void *param);
// void *checking_nbr_thread(void *param);
// void *checking_database_thread(void *param);

// void mospf_run()
// {
// 	pthread_t hello, lsu, nbr, db;
// 	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
// 	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
// 	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
// 	pthread_create(&db, NULL, checking_database_thread, NULL);
// }

// void *sending_mospf_hello_thread(void *param)
// {
// 	// TODO - finish me
// 	struct iphdr *ip;
// 	struct mospf_hdr *mospf;
// 	struct mospf_hello *hello;
// 	iface_info_t *iface = NULL;
// 	while(1){
// 		pthread_mutex_lock(&mospf_lock);
// 		//log(DEBUG, "Sending hello");
// 		list_for_each_entry(iface, &instance->iface_list, list){
// 			int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
// 			//log(DEBUG, "len is %d", packet_len);
// 			char *packet = (char *)malloc(packet_len);
// 			memset(packet, 0, packet_len);
// 			ip = packet_to_ip_hdr(packet);
// 			u32 dst_ip = MOSPF_ALLSPFRouters;
// 			ip_init_hdr(ip, iface->ip, dst_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
// 			//mospf = (struct mospf_hdr*)IP_DATA(ip); 这里不能用这个宏，因为ip未初始化，ihl=0，cnm必须先初始化ip
// 			//log(DEBUG, "ip->ihl is %d", ip->ihl);
// 			mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
// 			mospf->version = MOSPF_VERSION;
// 			mospf->type = MOSPF_TYPE_HELLO;
// 			mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
// 			mospf->rid = htonl(instance->router_id);
// 			mospf->aid = htonl(instance->area_id);
// 			mospf->checksum = 0;
// 			hello = (struct mospf_hello*)((char*)mospf + MOSPF_HDR_SIZE);
// 			hello->mask = htonl(iface->mask);
// 			hello->helloint = htons(MOSPF_DEFAULT_HELLOINT);
// 			hello->padding = 0;
// 			mospf->checksum = mospf_checksum(mospf);
// 			u32 daddr = ntohl(ip->daddr);
// 			u8 dmac[ETH_ALEN];
// 			dmac[0] = 0x01;
// 			dmac[1] = 0x00;
// 			dmac[2] = 0x5e;
// 			dmac[3] = (daddr >> 16) & 0x7f;
// 			dmac[4] = (daddr >> 8) & 0xff;
// 			dmac[5] = daddr & 0xff;
// 			struct ether_header *eh = (struct ether_header *)packet;
// 			memcpy(eh->ether_dhost, dmac, ETH_ALEN);
// 			memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
// 			eh->ether_type = htons(ETH_P_IP);
// 			iface_send_packet(iface, packet, packet_len);
// 		}
// 		pthread_mutex_unlock(&mospf_lock);
// 		sleep(MOSPF_DEFAULT_HELLOINT);
// 	}
// }

// void *checking_nbr_thread(void *param)
// {
// 	// TODO - finish me
// 	while(1){
// 		sleep(1);
// 		int change = 0;
// 		pthread_mutex_lock(&mospf_lock);
// 		iface_info_t *iface;
// 		list_for_each_entry(iface, &instance->iface_list, list){
// 			mospf_nbr_t *nbr, *tmp;
// 			list_for_each_entry_safe(nbr, tmp, &iface->nbr_list, list){
// 				nbr->alive++;
// 				if(nbr->alive >= MOSPF_HELLO_TIMEOUT){
// 					//log(DEBUG, "delete neighbor %x from interface %s", nbr->nbr_id, iface->name);
// 					list_delete_entry(&nbr->list);
// 					free(nbr);
// 					iface->num_nbr--;
// 					change = 1;
// 				}
// 			}
// 		}
// 		if(change){
// 			instance->sequence_num++;
// 			int nadv = 0;
// 			list_for_each_entry(iface, &instance->iface_list, list){
// 				mospf_nbr_t *nbr;
// 				list_for_each_entry(nbr, &iface->nbr_list, list){
// 					nadv++;
// 				}
// 				if(iface->num_nbr == 0){
// 					nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
// 				}
// 			}
			
// 			if(nadv > 0){
// 				struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
// 				int lsa_index = 0;
// 				list_for_each_entry(iface, &instance->iface_list, list){
// 					mospf_nbr_t *nbr;
// 					list_for_each_entry(nbr, &iface->nbr_list, list){
// 						lsas[lsa_index].network = htonl(iface->ip & iface->mask);
// 						lsas[lsa_index].mask = htonl(iface->mask);
// 						lsas[lsa_index].rid = htonl(nbr->nbr_id); //lsa里面的路由器id是网络字节序，nbr里面的路由器id是主机字节序
// 						lsa_index++;
// 					}
// 					if(iface->num_nbr == 0) {
// 						lsas[lsa_index].network = htonl(iface->ip & iface->mask);
// 						lsas[lsa_index].mask = htonl(iface->mask);
// 						lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
// 						lsa_index++;
// 					}
// 				}
				
// 				list_for_each_entry(iface, &instance->iface_list, list){
// 					mospf_nbr_t *nbr;
// 					list_for_each_entry(nbr, &iface->nbr_list, list){
// 						int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
// 						char *packet = (char *)malloc(packet_len);
// 						memset(packet, 0, packet_len);
// 						struct iphdr *ip = packet_to_ip_hdr(packet);
// 						ip_init_hdr(ip, iface->ip, nbr->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF); //这里也是初始化，cnm
// 						struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
// 						struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
// 						mospf->version = MOSPF_VERSION;
// 						mospf->type = MOSPF_TYPE_LSU;
// 						mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
// 						mospf->rid = htonl(instance->router_id);
// 						mospf->aid = htonl(instance->area_id);
// 						mospf->checksum = 0;
// 						lsu->seq = htons(instance->sequence_num);
// 						lsu->ttl = MOSPF_MAX_LSU_TTL;
// 						lsu->unused = 0;
// 						lsu->nadv = htonl(nadv);
// 						memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
// 						mospf->checksum = mospf_checksum(mospf);
// 						ip_send_packet(packet, packet_len);
// 						//log(DEBUG, "MOSPF: Sending updated LSU to neighbor %x via interface %s", nbr->nbr_id, iface->name);
// 					}
// 				}
// 				free(lsas);
// 			}
// 			mospf_db_dijkstra();
// 		}
// 		pthread_mutex_unlock(&mospf_lock);
// 	}
// 	return NULL;
// }

// void *checking_database_thread(void *param)
// {
// 	// TODO - finish me
// 	while(1){
// 		sleep(1);
// 		int change = 0;
// 		pthread_mutex_lock(&mospf_lock);
// 		mospf_db_entry_t *entry, *tmp;
// 		list_for_each_entry_safe(entry, tmp, &mospf_db, list){
// 			if(entry->rid == instance->router_id){
// 				continue;
// 			}
// 			entry->alive++;
// 			if(entry->alive >= MOSPF_DATABASE_TIMEOUT){
// 				//log(DEBUG, "MOSPF: database entry from router %x timeout", entry->rid);
// 				list_delete_entry(&entry->list);
// 				if(entry->array) free(entry->array);
// 				free(entry);
// 				change = 1;
// 			}
// 		}
// 		if(change){
// 			mospf_db_dijkstra();
// 		}
// 		pthread_mutex_unlock(&mospf_lock);
// 	}
// 	return NULL;
// }

// void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
// {
// 	// TODO - finish me
// 	struct iphdr *ip = packet_to_ip_hdr(packet);
// 	struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
// 	struct mospf_hello *hello = (struct mospf_hello*)((char*)mospf + MOSPF_HDR_SIZE);
// 	u32 src_ip = ntohl(ip->saddr);
// 	u32 rid = ntohl(mospf->rid);
// 	pthread_mutex_lock(&mospf_lock);
// 	mospf_nbr_t *nbr = NULL;
// 	int flag = 0;
// 	list_for_each_entry(nbr, &iface->nbr_list, list){
// 		if(nbr->nbr_id == rid){
// 			nbr->nbr_ip = src_ip;
// 			nbr->nbr_mask = hello->mask;
// 			nbr->alive = 0;
// 			flag = 1;
// 			break;
// 		}
// 	}
// 	if(!flag){
// 		nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
// 		nbr->nbr_id = rid;
// 		nbr->nbr_ip = src_ip;
// 		nbr->nbr_mask = hello->mask;
// 		nbr->alive = 0;
// 		list_add_tail(&nbr->list, &iface->nbr_list);
// 		iface->num_nbr++;
// 		//log(DEBUG, "add new neighbor to interface %s", iface->name);
// 		instance->sequence_num++;
// 		int nadv = 0;
// 		iface_info_t *iface_tmp;
// 		list_for_each_entry(iface_tmp, &instance->iface_list, list){
// 			mospf_nbr_t *nbr_tmp;
// 			list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list){
// 				nadv++; //邻居数量就是LSA数量
// 			}
// 			if(iface_tmp->num_nbr == 0) {
// 				nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
// 			}
// 		}
// 		if(nadv > 0){
// 			struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
// 			int lsa_index = 0;
// 			list_for_each_entry(iface_tmp, &instance->iface_list, list){
// 				mospf_nbr_t *nbr_tmp;
// 				list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list){
// 					lsas[lsa_index].network = htonl(iface_tmp->ip & iface_tmp->mask);
// 					lsas[lsa_index].mask = htonl(iface_tmp->mask);
// 					lsas[lsa_index].rid = htonl(nbr_tmp->nbr_id);
// 					lsa_index++;
// 				}
// 				if(iface_tmp->num_nbr == 0) {
// 					lsas[lsa_index].network = htonl(iface_tmp->ip & iface_tmp->mask);
// 					lsas[lsa_index].mask = htonl(iface_tmp->mask);
// 					lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
// 					lsa_index++;
// 				}
// 			}
				
// 			list_for_each_entry(iface_tmp, &instance->iface_list, list){
// 				mospf_nbr_t *nbr_tmp;
// 				list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list) {
// 					int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
// 					char *packet = (char *)malloc(packet_len);
// 					if (!packet) continue;
// 					memset(packet, 0, packet_len);
// 					struct iphdr *ip = packet_to_ip_hdr(packet);
// 					ip_init_hdr(ip, iface_tmp->ip, nbr_tmp->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
// 					struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
// 					struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
// 					mospf->version = MOSPF_VERSION;
// 					mospf->type = MOSPF_TYPE_LSU;
// 					mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
// 					mospf->rid = htonl(instance->router_id);
// 					mospf->aid = htonl(instance->area_id);
// 					mospf->checksum = 0;
// 					lsu->seq = htons(instance->sequence_num);
// 					lsu->ttl = MOSPF_MAX_LSU_TTL;
// 					lsu->unused = 0;
// 					lsu->nadv = htonl(nadv);
// 					memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
// 					mospf->checksum = mospf_checksum(mospf);
// 					ip_send_packet(packet, packet_len);
// 				}
// 			}
// 			free(lsas);
// 		}
// 		mospf_db_dijkstra();
// 	}
// 	pthread_mutex_unlock(&mospf_lock);
// }

// void *sending_mospf_lsu_thread(void *param)
// {
// 	// TODO - finish me
// 	while(1){
// 		sleep(MOSPF_DEFAULT_LSUINT);
// 		pthread_mutex_lock(&mospf_lock);
// 		int nadv = 0;
// 		iface_info_t *iface;
// 		list_for_each_entry(iface, &instance->iface_list, list){
// 			mospf_nbr_t *nbr;
// 			list_for_each_entry(nbr, &iface->nbr_list, list){ //找邻居数量
// 				nadv++;
// 			}
// 			if(iface->num_nbr == 0) {
// 				nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
// 			}
// 		}
// 		if(nadv == 0){
// 			pthread_mutex_unlock(&mospf_lock);
// 			continue;
// 		}
// 		instance->sequence_num++;
// 		struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
// 		int lsa_index = 0;
// 		list_for_each_entry(iface, &instance->iface_list, list){
// 			mospf_nbr_t *nbr;
// 			list_for_each_entry(nbr, &iface->nbr_list, list){
// 				lsas[lsa_index].network = htonl(iface->ip & iface->mask);
// 				lsas[lsa_index].mask = htonl(iface->mask);
// 				lsas[lsa_index].rid = htonl(nbr->nbr_id);
// 				lsa_index++;
// 			}
// 			if(iface->num_nbr == 0) {
// 				lsas[lsa_index].network = htonl(iface->ip & iface->mask);
// 				lsas[lsa_index].mask = htonl(iface->mask);
// 				lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
// 				lsa_index++;
// 			}
// 		}

// 		list_for_each_entry(iface, &instance->iface_list, list){
// 			mospf_nbr_t *nbr;
// 			list_for_each_entry(nbr, &iface->nbr_list, list){
// 				int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
// 				char *packet = (char *)malloc(packet_len);
// 				memset(packet, 0, packet_len);
// 				struct iphdr *ip = packet_to_ip_hdr(packet);
// 				ip_init_hdr(ip, iface->ip, nbr->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
// 				//先初始化ip头部，再初始化mospf头部
// 				struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
// 				struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
// 				mospf->version = MOSPF_VERSION;
// 				mospf->type = MOSPF_TYPE_LSU;
// 				mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
// 				mospf->rid = htonl(instance->router_id);
// 				mospf->aid = htonl(instance->area_id);
// 				mospf->checksum = 0;
// 				lsu->seq = htons(instance->sequence_num);
// 				lsu->ttl = MOSPF_MAX_LSU_TTL;
// 				lsu->unused = 0;
// 				lsu->nadv = htonl(nadv);
// 				memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
// 				mospf->checksum = mospf_checksum(mospf);
// 				//log(DEBUG, "MOSPF: Sending LSU to neighbor %x via interface %s", nbr->nbr_id, iface->name);
// 				ip_send_packet(packet, packet_len);
// 			}
// 		}
// 		free(lsas);
// 		pthread_mutex_unlock(&mospf_lock);
// 	}
// 	return NULL;
// }

// void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
// {
// 	// TODO - finish me
// 	struct iphdr *ip = packet_to_ip_hdr(packet);
// 	struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
// 	struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
// 	u32 rid = ntohl(mospf->rid);
// 	u16 seq = ntohs(lsu->seq);
// 	u32 nadv = ntohl(lsu->nadv);
// 	int flag = 0;
// 	int found = 0;
// 	pthread_mutex_lock(&mospf_lock);
// 	mospf_db_entry_t *db_entry = NULL;
// 	list_for_each_entry(db_entry, &mospf_db, list){
// 		if(db_entry->rid == rid){
// 			if(db_entry->seq < seq){
// 				db_entry->seq = seq;
// 				db_entry->alive = 0;
// 				db_entry->nadv = nadv;
// 				if(db_entry->array != NULL){
// 					free(db_entry->array);
// 					db_entry->array = NULL;
// 				}
// 				db_entry->array = (struct mospf_lsa *)malloc(sizeof(struct mospf_lsa) * nadv);
// 				memcpy(db_entry->array, (char *)lsu + MOSPF_LSU_SIZE, sizeof(struct mospf_lsa) * nadv);
// 				flag = 1;
// 			}
// 			found = 1;
// 			break;
// 		}
// 	}
// 	if(!found){ //更新数据库
// 		db_entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
// 		db_entry->rid = rid;
// 		db_entry->seq = seq;
// 		db_entry->alive = 0;
// 		db_entry->nadv = nadv;
// 		db_entry->array = (struct mospf_lsa *)malloc(sizeof(struct mospf_lsa) * nadv);
// 		memcpy(db_entry->array, (char *)lsu + MOSPF_LSU_SIZE, sizeof(struct mospf_lsa) * nadv);
// 		list_add_tail(&db_entry->list, &mospf_db);
// 		flag = 1;
// 	}
// 	if(flag){ //转发LSU到邻居
// 		mospf_db_dijkstra();

// 		lsu->ttl -= 1;
// 		if(lsu->ttl > 0) {
// 			u32 src_ip = ntohl(ip->saddr);
// 			mospf->checksum = 0;
// 			mospf->checksum = mospf_checksum(mospf);
// 			iface_info_t *iface_to_send;
// 			list_for_each_entry(iface_to_send, &instance->iface_list, list){
// 				if (iface_to_send == iface) continue; // 避免在同一接口转发导致广播风暴
// 				mospf_nbr_t *nbr;
// 				list_for_each_entry(nbr, &iface_to_send->nbr_list, list){
// 					if(nbr->nbr_ip == src_ip){ //如果是邻居发来的LSU，就不转发给它
// 						continue;
// 					}
// 					char* send_packet = (char *)malloc(len);
// 					memcpy(send_packet, packet, len);
// 					struct iphdr *ip_send = packet_to_ip_hdr(send_packet);
// 					ip_send->saddr = htonl(iface_to_send->ip);
// 					ip_send->daddr = htonl(nbr->nbr_ip);
// 					ip_send_packet(send_packet, len);
// 					//log(DEBUG, "handle lsu: send lsu to %x", nbr->nbr_ip);
// 				}
// 			}
// 		}
// 	}
// 	//free(packet); //不知道后面有没有函数会free它，先放在这，在ip.c中会free，所有发来处理的包都不需要free
// 	pthread_mutex_unlock(&mospf_lock);
// 	return;
// }

// void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
// {
// 	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
// 	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

// 	if (mospf->version != MOSPF_VERSION) {
// 		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
// 		return ;
// 	}
// 	if (mospf->checksum != mospf_checksum(mospf)) {
// 		log(ERROR, "received mospf packet with incorrect checksum");
// 		return ;
// 	}
// 	if (ntohl(mospf->aid) != instance->area_id) {
// 		log(ERROR, "received mospf packet with incorrect area id");
// 		return ;
// 	}

// 	switch (mospf->type) {
// 		case MOSPF_TYPE_HELLO:
// 			handle_mospf_hello(iface, packet, len);
// 			break;
// 		case MOSPF_TYPE_LSU:
// 			handle_mospf_lsu(iface, packet, len);
// 			break;
// 		default:
// 			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
// 			break;
// 	}
// }

// // TODO - you can add more functions if needed
// #define RT_OSPF_ROUTE 9
// extern struct list_head rtable;
// extern pthread_mutex_t rt_lock;
// void mospf_db_dijkstra(){
// 	pthread_mutex_lock(&rt_lock);
// 	log(DEBUG, "dijkstra");
// 	rt_entry_t *rt_entry, *q;
// 	list_for_each_entry_safe(rt_entry, q, &rtable, list){
// 		//log(DEBUG, "rt_entry->dest is %x", rt_entry->dest);
// 		if(rt_entry->flags != RT_OSPF_ROUTE) continue;
// 		list_delete_entry(&rt_entry->list);
// 		free(rt_entry);
// 		//log(DEBUG, "delete ospf route %x", rt_entry->dest);
// 	}
// 	int router_ids[100]; // 增加容量
// 	int router_num = 0;
// 	int src_idx = -1;
// 	router_ids[router_num] = instance->router_id;
// 	router_num++;
// 	src_idx = 0;
// 	mospf_db_entry_t *db_entry;
// 	list_for_each_entry(db_entry, &mospf_db, list){
// 		if(db_entry->rid == instance->router_id) continue;
// 		router_ids[router_num] = db_entry->rid;
// 		router_num++;
// 	}
// 	int graph[100][100]; // 增加容量
// 	for(int i = 0; i < router_num; i++){
// 		for(int j = 0; j < router_num; j++){
// 			graph[i][j] = 0xfffffff;
// 			if(i == j) graph[i][j] = 0;
// 		}
// 	}
// 	iface_info_t *iface;
// 	list_for_each_entry(iface, &instance->iface_list, list){
// 		mospf_nbr_t *nbr;
// 		list_for_each_entry(nbr, &iface->nbr_list, list){
// 			for(int i = 0; i < router_num; i++){
// 				if(router_ids[i] == nbr->nbr_id){
// 					graph[src_idx][i] = 1;
// 					graph[i][src_idx] = 1;
// 					break;
// 				}
// 			}
// 		}
// 	}

// 	list_for_each_entry(db_entry, &mospf_db, list){
// 		int s = -1, d = -1;
// 		for(int i = 0; i < router_num; i++){
// 			if(router_ids[i] == db_entry->rid){
// 				s = i;
// 				break;
// 			}
// 		}
// 		if(s == -1) continue;
// 		for(int i = 0; i < db_entry->nadv; i++){ // 修正循环边界
// 			u32 nbr_rid = ntohl(db_entry->array[i].rid);
// 			if (nbr_rid == 0) continue; // 忽略主机节点
// 			for(int j = 0; j < router_num; j++){
// 				if(router_ids[j] == nbr_rid){
// 					d = j;
// 					break;
// 				}
// 			}
// 			if(d == -1) continue;
// 			graph[s][d] = 1;
// 			graph[d][s] = 1;
// 		}
// 	}

// 	int dist[100];
// 	int prev[100];
// 	int visited[100];
// 	int stack[100];
// 	for(int i = 0; i < router_num; i++){
// 		dist[i] = 0xfffffff;
// 		prev[i] = -1;
// 		visited[i] = 0;
// 		stack[i] = -1;
// 	}
// 	dist[src_idx] = 0;

// 	for(int i = 0; i < router_num; i++){
// 		int min_dist = 0xfffffff;
// 		int min_idx = -1;
// 		for(int j = 0; j < router_num; j++){
// 			if(!visited[j] && dist[j] < min_dist){
// 				min_dist = dist[j];
// 				min_idx = j;
// 			}
// 		}
// 		if(min_idx == -1) break;
// 		stack[i] = min_idx;
// 		visited[min_idx] = 1;
// 		for(int j = 0; j < router_num; j++){
// 			if(!visited[j] && dist[min_idx] + graph[min_idx][j] < dist[j]){
// 				dist[j] = dist[min_idx] + graph[min_idx][j];
// 				prev[j] = min_idx;
// 			}
// 		}
// 	}

// 	/*for(int i = 1; i < router_num; i++){
// 		log(DEBUG, "stack[%d] is %d, router id is %x, dist = %d", i, stack[i], router_ids[stack[i]], dist[stack[i]]);
// 	}*/

// 	for(int i = 1; i < router_num; i++){
// 		int index = stack[i];
// 		//log(DEBUG, "index is %d", index);
// 		if(index == -1) break;
// 		u32 dst_rid = router_ids[index]; //这个是主机字节序
// 		list_for_each_entry(db_entry, &mospf_db, list){
// 			if(db_entry->rid == dst_rid){
// 				//log(DEBUG, "find the entry %x", db_entry->rid);
// 				for(int j = 0; j < db_entry->nadv; j++){
// 					u32 network = ntohl(db_entry->array[j].network);
// 					u32 mask = ntohl(db_entry->array[j].mask);
// 					u32 nbr_rid = ntohl(db_entry->array[j].rid);
// 					int found = 0;
// 					list_for_each_entry(iface, &instance->iface_list, list){
// 						if((iface->ip & iface->mask) == (network & mask)){
// 							found = 1;
// 							break;
// 						}
// 					} //直连，我这里默认本地路由表项已经包含
// 					if(found) continue;
// 					list_for_each_entry(rt_entry, &rtable, list){
// 						if(rt_entry->dest == network && rt_entry->mask == mask){
// 							found = 1;
// 							break;
// 						}
// 					} //前面已经添加了的表项，stack的顺序可以保证最短一定最先添加
// 					if(found) continue;
// 					//log(DEBUG, "hhh");
// 					int next_hop = index;
// 					while(prev[next_hop] != src_idx && prev[next_hop] != -1){
// 						next_hop = prev[next_hop];
// 					}
// 					//log(DEBUG, "next hop is %x", router_ids[next_hop]);
// 					if(prev[next_hop] == src_idx){
// 						u32 next_rid = router_ids[next_hop];
// 						iface_info_t *out_iface = NULL;
// 						u32 gw_ip = 0;
// 						list_for_each_entry(iface, &instance->iface_list, list){
// 							mospf_nbr_t *nbr;
// 							list_for_each_entry(nbr, &iface->nbr_list, list){
// 								if(nbr->nbr_id == next_rid){
// 									out_iface = iface; //这个是本路由器的出口
// 									gw_ip = nbr->nbr_ip; //这个是下一个路由器接口的ip，gw是不会为0的
// 									break;
// 								}
// 							}
// 							if(out_iface != NULL) break;
// 						}
// 						if(out_iface){
// 							rt_entry_t *entry = new_rt_entry(network, mask, gw_ip, out_iface);
// 							entry->flags = RT_OSPF_ROUTE;
// 							list_add_tail(&entry->list, &rtable);
// 						}
// 					}
// 					//log(DEBUG, "hhhhh");
// 				}
// 				break;
// 			}
// 		}
// 	}
// 	log(DEBUG, "dijkstra end");
// 	pthread_mutex_unlock(&rt_lock);
// 	//print_lsdb();
// 	//print_rtable();
// }
#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "rtable.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	struct iphdr *ip;
	struct mospf_hdr *mospf;
	struct mospf_hello *hello;
	iface_info_t *iface = NULL;
	while(1){
		pthread_mutex_lock(&mospf_lock);
		//log(DEBUG, "Sending hello");
		list_for_each_entry(iface, &instance->iface_list, list){
			int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
			//log(DEBUG, "len is %d", packet_len);
			char *packet = (char *)malloc(packet_len);
			memset(packet, 0, packet_len);
			ip = packet_to_ip_hdr(packet);
			u32 dst_ip = MOSPF_ALLSPFRouters;
			ip_init_hdr(ip, iface->ip, dst_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
			//mospf = (struct mospf_hdr*)IP_DATA(ip); 这里不能用这个宏，因为ip未初始化，ihl=0，cnm必须先初始化ip
			//log(DEBUG, "ip->ihl is %d", ip->ihl);
			mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
			mospf->version = MOSPF_VERSION;
			mospf->type = MOSPF_TYPE_HELLO;
			mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			mospf->rid = htonl(instance->router_id);
			mospf->aid = htonl(instance->area_id);
			mospf->checksum = 0;
			hello = (struct mospf_hello*)((char*)mospf + MOSPF_HDR_SIZE);
			hello->mask = htonl(iface->mask);
			hello->helloint = htons(MOSPF_DEFAULT_HELLOINT);
			hello->padding = 0;
			mospf->checksum = mospf_checksum(mospf);
			u32 daddr = ntohl(ip->daddr);
			u8 dmac[ETH_ALEN];
			dmac[0] = 0x01;
			dmac[1] = 0x00;
			dmac[2] = 0x5e;
			dmac[3] = (daddr >> 16) & 0x7f;
			dmac[4] = (daddr >> 8) & 0xff;
			dmac[5] = daddr & 0xff;
			struct ether_header *eh = (struct ether_header *)packet;
			memcpy(eh->ether_dhost, dmac, ETH_ALEN);
			memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
			eh->ether_type = htons(ETH_P_IP);
			iface_send_packet(iface, packet, packet_len);
		}
		pthread_mutex_unlock(&mospf_lock);
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
}

void *checking_nbr_thread(void *param)
{
	while(1){
		sleep(1);
		int change = 0;
		pthread_mutex_lock(&mospf_lock);
		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list){
			mospf_nbr_t *nbr, *tmp;
			list_for_each_entry_safe(nbr, tmp, &iface->nbr_list, list){
				nbr->alive++;
				if(nbr->alive >= MOSPF_HELLO_TIMEOUT){
					//log(DEBUG, "delete neighbor %x from interface %s", nbr->nbr_id, iface->name);
					list_delete_entry(&nbr->list);
					free(nbr);
					iface->num_nbr--;
					change = 1;
				}
			}
		}
		if(change){
			instance->sequence_num++;
			int nadv = 0;
			list_for_each_entry(iface, &instance->iface_list, list){
				mospf_nbr_t *nbr;
				list_for_each_entry(nbr, &iface->nbr_list, list){
					nadv++;
				}
				if(iface->num_nbr == 0){
					nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
				}
			}
			
			if(nadv > 0){
				struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
				int lsa_index = 0;
				list_for_each_entry(iface, &instance->iface_list, list){
					mospf_nbr_t *nbr;
					list_for_each_entry(nbr, &iface->nbr_list, list){
						lsas[lsa_index].network = htonl(iface->ip & iface->mask);
						lsas[lsa_index].mask = htonl(iface->mask);
						lsas[lsa_index].rid = htonl(nbr->nbr_id); //lsa里面的路由器id是网络字节序，nbr里面的路由器id是主机字节序
						lsa_index++;
					}
					if(iface->num_nbr == 0) {
						lsas[lsa_index].network = htonl(iface->ip & iface->mask);
						lsas[lsa_index].mask = htonl(iface->mask);
						lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
						lsa_index++;
					}
				}
				
				list_for_each_entry(iface, &instance->iface_list, list){
					mospf_nbr_t *nbr;
					list_for_each_entry(nbr, &iface->nbr_list, list){
						int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
						char *packet = (char *)malloc(packet_len);
						memset(packet, 0, packet_len);
						struct iphdr *ip = packet_to_ip_hdr(packet);
						ip_init_hdr(ip, iface->ip, nbr->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF); //这里也是初始化，cnm
						struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
						struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
						mospf->version = MOSPF_VERSION;
						mospf->type = MOSPF_TYPE_LSU;
						mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
						mospf->rid = htonl(instance->router_id);
						mospf->aid = htonl(instance->area_id);
						mospf->checksum = 0;
						lsu->seq = htons(instance->sequence_num);
						lsu->ttl = MOSPF_MAX_LSU_TTL;
						lsu->unused = 0;
						lsu->nadv = htonl(nadv);
						memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
						mospf->checksum = mospf_checksum(mospf);
						ip_send_packet(packet, packet_len);
						//log(DEBUG, "MOSPF: Sending updated LSU to neighbor %x via interface %s", nbr->nbr_id, iface->name);
					}
				}
				free(lsas);
			}
			mospf_db_dijkstra();
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{
	while(1){
		sleep(1);
		int change = 0;
		pthread_mutex_lock(&mospf_lock);
		mospf_db_entry_t *entry, *tmp;
		list_for_each_entry_safe(entry, tmp, &mospf_db, list){
			if(entry->rid == instance->router_id){
				continue;
			}
			entry->alive++;
			if(entry->alive >= MOSPF_DATABASE_TIMEOUT){
				//log(DEBUG, "MOSPF: database entry from router %x timeout", entry->rid);
				list_delete_entry(&entry->list);
				if(entry->array) free(entry->array);
				free(entry);
				change = 1;
			}
		}
		if(change){
			mospf_db_dijkstra();
		}
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
	struct mospf_hello *hello = (struct mospf_hello*)((char*)mospf + MOSPF_HDR_SIZE);
	u32 src_ip = ntohl(ip->saddr);
	u32 rid = ntohl(mospf->rid);
	pthread_mutex_lock(&mospf_lock);
	mospf_nbr_t *nbr = NULL;
	int flag = 0;
	list_for_each_entry(nbr, &iface->nbr_list, list){
		if(nbr->nbr_id == rid){
			nbr->nbr_ip = src_ip;
			nbr->nbr_mask = hello->mask;
			nbr->alive = 0;
			flag = 1;
			break;
		}
	}
	if(!flag){
		nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		nbr->nbr_id = rid;
		nbr->nbr_ip = src_ip;
		nbr->nbr_mask = hello->mask;
		nbr->alive = 0;
		list_add_tail(&nbr->list, &iface->nbr_list);
		iface->num_nbr++;
		//log(DEBUG, "add new neighbor to interface %s", iface->name);
		instance->sequence_num++;
		int nadv = 0;
		iface_info_t *iface_tmp;
		list_for_each_entry(iface_tmp, &instance->iface_list, list){
			mospf_nbr_t *nbr_tmp;
			list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list){
				nadv++; //邻居数量就是LSA数量
			}
			if(iface_tmp->num_nbr == 0) {
				nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
			}
		}
		if(nadv > 0){
			struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
			int lsa_index = 0;
			list_for_each_entry(iface_tmp, &instance->iface_list, list){
				mospf_nbr_t *nbr_tmp;
				list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list){
					lsas[lsa_index].network = htonl(iface_tmp->ip & iface_tmp->mask);
					lsas[lsa_index].mask = htonl(iface_tmp->mask);
					lsas[lsa_index].rid = htonl(nbr_tmp->nbr_id);
					lsa_index++;
				}
				if(iface_tmp->num_nbr == 0) {
					lsas[lsa_index].network = htonl(iface_tmp->ip & iface_tmp->mask);
					lsas[lsa_index].mask = htonl(iface_tmp->mask);
					lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
					lsa_index++;
				}
			}
				
			list_for_each_entry(iface_tmp, &instance->iface_list, list){
				mospf_nbr_t *nbr_tmp;
				list_for_each_entry(nbr_tmp, &iface_tmp->nbr_list, list) {
					int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
					char *packet = (char *)malloc(packet_len);
					if (!packet) continue;
					memset(packet, 0, packet_len);
					struct iphdr *ip = packet_to_ip_hdr(packet);
					ip_init_hdr(ip, iface_tmp->ip, nbr_tmp->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
					struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
					struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
					mospf->version = MOSPF_VERSION;
					mospf->type = MOSPF_TYPE_LSU;
					mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
					mospf->rid = htonl(instance->router_id);
					mospf->aid = htonl(instance->area_id);
					mospf->checksum = 0;
					lsu->seq = htons(instance->sequence_num);
					lsu->ttl = MOSPF_MAX_LSU_TTL;
					lsu->unused = 0;
					lsu->nadv = htonl(nadv);
					memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
					mospf->checksum = mospf_checksum(mospf);
					ip_send_packet(packet, packet_len);
				}
			}
			free(lsas);
		}
		mospf_db_dijkstra();
	}
	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	while(1){
		sleep(MOSPF_DEFAULT_LSUINT);
		pthread_mutex_lock(&mospf_lock);
		int nadv = 0;
		iface_info_t *iface;
		list_for_each_entry(iface, &instance->iface_list, list){
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list){ //找邻居数量
				nadv++;
			}
			if(iface->num_nbr == 0) {
				nadv++; //主机本身也算一个“邻居”，根据手册来看rid为0
			}
		}
		if(nadv == 0){
			pthread_mutex_unlock(&mospf_lock);
			continue;
		}
		instance->sequence_num++;
		struct mospf_lsa *lsas = (struct mospf_lsa*)malloc(nadv * sizeof(struct mospf_lsa));
		int lsa_index = 0;
		list_for_each_entry(iface, &instance->iface_list, list){
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list){
				lsas[lsa_index].network = htonl(iface->ip & iface->mask);
				lsas[lsa_index].mask = htonl(iface->mask);
				lsas[lsa_index].rid = htonl(nbr->nbr_id);
				lsa_index++;
			}
			if(iface->num_nbr == 0) {
				lsas[lsa_index].network = htonl(iface->ip & iface->mask);
				lsas[lsa_index].mask = htonl(iface->mask);
				lsas[lsa_index].rid = 0;  // 使用0表示这是主机网络，不是路由器
				lsa_index++;
			}
		}

		list_for_each_entry(iface, &instance->iface_list, list){
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface->nbr_list, list){
				int packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa);
				char *packet = (char *)malloc(packet_len);
				memset(packet, 0, packet_len);
				struct iphdr *ip = packet_to_ip_hdr(packet);
				ip_init_hdr(ip, iface->ip, nbr->nbr_ip, packet_len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
				//先初始化ip头部，再初始化mospf头部
				struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
				struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
				mospf->version = MOSPF_VERSION;
				mospf->type = MOSPF_TYPE_LSU;
				mospf->len = htons(MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nadv * sizeof(struct mospf_lsa));
				mospf->rid = htonl(instance->router_id);
				mospf->aid = htonl(instance->area_id);
				mospf->checksum = 0;
				lsu->seq = htons(instance->sequence_num);
				lsu->ttl = MOSPF_MAX_LSU_TTL;
				lsu->unused = 0;
				lsu->nadv = htonl(nadv);
				memcpy((char *)lsu + MOSPF_LSU_SIZE, lsas, nadv * sizeof(struct mospf_lsa));
				mospf->checksum = mospf_checksum(mospf);
				//log(DEBUG, "MOSPF: Sending LSU to neighbor %x via interface %s", nbr->nbr_id, iface->name);
				ip_send_packet(packet, packet_len);
			}
		}
		free(lsas);
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	//log(DEBUG, "handle mospf lsu");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct mospf_hdr *mospf = (struct mospf_hdr*)IP_DATA(ip);
	struct mospf_lsu *lsu = (struct mospf_lsu*)((char *)mospf + MOSPF_HDR_SIZE);
	u32 rid = ntohl(mospf->rid);
	u16 seq = ntohs(lsu->seq);
	u32 nadv = ntohl(lsu->nadv);
	int flag = 0;
	int found = 0;
	pthread_mutex_lock(&mospf_lock);
	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list){
		if(db_entry->rid == rid){
			if(db_entry->seq < seq){
				db_entry->seq = seq;
				db_entry->alive = 0;
				db_entry->nadv = nadv;
				if(db_entry->array != NULL){
					free(db_entry->array);
					db_entry->array = NULL;
				}
				db_entry->array = (struct mospf_lsa *)malloc(sizeof(struct mospf_lsa) * nadv);
				memcpy(db_entry->array, (char *)lsu + MOSPF_LSU_SIZE, sizeof(struct mospf_lsa) * nadv);
				flag = 1;
			}
			found = 1;
			break;
		}
	}
	if(!found){ //更新数据库
		db_entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
		db_entry->rid = rid;
		db_entry->seq = seq;
		db_entry->alive = 0;
		db_entry->nadv = nadv;
		db_entry->array = (struct mospf_lsa *)malloc(sizeof(struct mospf_lsa) * nadv);
		memcpy(db_entry->array, (char *)lsu + MOSPF_LSU_SIZE, sizeof(struct mospf_lsa) * nadv);
		list_add_tail(&db_entry->list, &mospf_db);
		flag = 1;
	}
	if(flag){ //转发LSU到邻居
		lsu->ttl -= 1;
		if(lsu->ttl <= 0) return;
		u32 src_ip = ntohl(ip->saddr);
		mospf->checksum = 0;
		mospf->checksum = mospf_checksum(mospf);
		iface_info_t *iface_to_send;
		list_for_each_entry(iface_to_send, &instance->iface_list, list){
			mospf_nbr_t *nbr;
			list_for_each_entry(nbr, &iface_to_send->nbr_list, list){
				if(nbr->nbr_ip == src_ip){ //如果是邻居发来的LSU，就不转发给它
					continue;
				}
				char* send_packet = (char *)malloc(len);
				memcpy(send_packet, packet, len);
				struct iphdr *ip_send = packet_to_ip_hdr(send_packet);
				ip_send->saddr = htonl(iface_to_send->ip);
				ip_send->daddr = htonl(nbr->nbr_ip);
				ip_send_packet(send_packet, len);
				//log(DEBUG, "handle lsu: send lsu to %x", nbr->nbr_ip);
			}
		}
		mospf_db_dijkstra();
	}
	//free(packet); //不知道后面有没有函数会free它，先放在这，在ip.c中会free，所有发来处理的包都不需要free
	pthread_mutex_unlock(&mospf_lock);
	return;
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	//log(DEBUG, "handle mospf packet");

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		//log(ERROR, "mospf packet type: %d", mospf->type);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

#define RT_OSPF_ROUTE 9
extern struct list_head rtable;
extern pthread_mutex_t rt_lock;
void mospf_db_dijkstra(){
	pthread_mutex_lock(&rt_lock);
	log(DEBUG, "dijkstra");
	rt_entry_t *rt_entry, *q;
	list_for_each_entry_safe(rt_entry, q, &rtable, list){
		//log(DEBUG, "rt_entry->dest is %x", rt_entry->dest);
		if(rt_entry->flags != RT_OSPF_ROUTE) continue;
		list_delete_entry(&rt_entry->list);
		free(rt_entry);
		//log(DEBUG, "delete ospf route %x", rt_entry->dest);
	}
	int router_ids[10]; //这个是映射，图序号到router_id
	int router_num = 0;
	int src_idx = -1;
	router_ids[router_num] = instance->router_id;
	router_num++;
	src_idx = 0;
	mospf_db_entry_t *db_entry;
	list_for_each_entry(db_entry, &mospf_db, list){
		if(db_entry->rid == instance->router_id) continue;
		router_ids[router_num] = db_entry->rid;
		router_num++;
	}
	int graph[10][10];
	for(int i = 0; i < router_num; i++){
		for(int j = 0; j < router_num; j++){
			graph[i][j] = 0xfffffff;
			if(i == j) graph[i][j] = 0;
		}
	}
	iface_info_t *iface;
	list_for_each_entry(iface, &instance->iface_list, list){
		mospf_nbr_t *nbr;
		list_for_each_entry(nbr, &iface->nbr_list, list){
			for(int i = 0; i < router_num; i++){
				if(router_ids[i] == nbr->nbr_id){
					graph[src_idx][i] = 1;
					graph[i][src_idx] = 1;
					break;
				}
			}
		}
	}

	list_for_each_entry(db_entry, &mospf_db, list){
		int s, d = -1;
		for(int i = 0; i < router_num; i++){
			if(router_ids[i] == db_entry->rid){
				s = i;
				break;
			}
		}
		if(s == -1) continue;
		for(int i = 0; i < router_num - 1; i++){ //这里不包含自身
			u32 nbr_rid = ntohl(db_entry->array[i].rid);
			for(int j = 0; j < router_num; j++){
				if(router_ids[j] == nbr_rid){
					d = j;
					break;
				}
			}
			if(d == -1) continue;
			graph[s][d] = 1;
			graph[d][s] = 1;
		}
	}

	int dist[10];
	int prev[10];
	int visited[10];
	int stack[10];
	for(int i = 0; i < router_num; i++){
		dist[i] = 0xfffffff;
		prev[i] = -1;
		visited[i] = 0;
		stack[i] = -1;
	}
	dist[src_idx] = 0;

	for(int i = 0; i < router_num; i++){
		int min_dist = 0xfffffff;
		int min_idx = -1;
		for(int j = 0; j < router_num; j++){
			if(!visited[j] && dist[j] < min_dist){
				min_dist = dist[j];
				min_idx = j;
			}
		}
		if(min_idx == -1) break;
		stack[i] = min_idx;
		visited[min_idx] = 1;
		for(int j = 0; j < router_num; j++){
			if(!visited[j] && dist[min_idx] + graph[min_idx][j] < dist[j]){
				dist[j] = dist[min_idx] + graph[min_idx][j];
				prev[j] = min_idx;
			}
		}
	}

	/*for(int i = 1; i < router_num; i++){
		log(DEBUG, "stack[%d] is %d, router id is %x, dist = %d", i, stack[i], router_ids[stack[i]], dist[stack[i]]);
	}*/

	for(int i = 1; i < router_num; i++){
		int index = stack[i];
		//log(DEBUG, "index is %d", index);
		if(index == -1) break;
		u32 dst_rid = router_ids[index]; //这个是主机字节序
		list_for_each_entry(db_entry, &mospf_db, list){
			if(db_entry->rid == dst_rid){
				//log(DEBUG, "find the entry %x", db_entry->rid);
				for(int j = 0; j < db_entry->nadv; j++){
					u32 network = ntohl(db_entry->array[j].network);
					u32 mask = ntohl(db_entry->array[j].mask);
					u32 nbr_rid = ntohl(db_entry->array[j].rid);
					int found = 0;
					list_for_each_entry(iface, &instance->iface_list, list){
						if((iface->ip & iface->mask) == (network & mask)){
							found = 1;
							break;
						}
					} //直连，我这里默认本地路由表项已经包含
					if(found) continue;
					list_for_each_entry(rt_entry, &rtable, list){
						if(rt_entry->dest == network && rt_entry->mask == mask){
							found = 1;
							break;
						}
					} //前面已经添加了的表项，stack的顺序可以保证最短一定最先添加
					if(found) continue;
					//log(DEBUG, "hhh");
					int next_hop = index;
					while(prev[next_hop] != src_idx && prev[next_hop] != -1){
						next_hop = prev[next_hop];
					}
					//log(DEBUG, "next hop is %x", router_ids[next_hop]);
					if(prev[next_hop] == src_idx){
						u32 next_rid = router_ids[next_hop];
						iface_info_t *out_iface = NULL;
						u32 gw_ip = 0;
						list_for_each_entry(iface, &instance->iface_list, list){
							mospf_nbr_t *nbr;
							list_for_each_entry(nbr, &iface->nbr_list, list){
								if(nbr->nbr_id == next_rid){
									out_iface = iface; //这个是本路由器的出口
									gw_ip = nbr->nbr_ip; //这个是下一个路由器接口的ip，gw是不会为0的
									break;
								}
							}
							if(out_iface != NULL) break;
						}
						if(out_iface){
							rt_entry_t *new_rt_entry = (rt_entry_t *)malloc(sizeof(rt_entry_t));
							memset(new_rt_entry, 0, sizeof(rt_entry_t));
							new_rt_entry->dest = network;
							new_rt_entry->mask = mask;
							new_rt_entry->gw = gw_ip;
							new_rt_entry->iface = out_iface;
							new_rt_entry->flags = RT_OSPF_ROUTE;
							//log(DEBUG, "is here");
							strncpy(new_rt_entry->if_name, out_iface->name, sizeof(new_rt_entry->if_name) - 1);
							//log(DEBUG, "add new route: dest %x mask %x gw %x iface %s", network, mask, gw_ip, out_iface->name);
							list_add_tail(&new_rt_entry->list, &rtable);
						}
					}
					//log(DEBUG, "hhhhh");
				}
				break;
			}
		}
	}
	log(DEBUG, "dijkstra end");
	pthread_mutex_unlock(&rt_lock);
	//print_lsdb();
	//print_rtable();
}
