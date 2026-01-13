#include "mospf_database.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct list_head mospf_db;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

void print_lsdb(){
	printf("LSDB:\n");
	printf("--------------------------------------\n");
	printf("Router\t\tNetwork\t\tMask\t\tNeighbor\tSeq\n");
    mospf_db_entry_t* lsas;
    list_for_each_entry(lsas, &mospf_db, list){
        for (int i = 0; i < lsas->nadv; ++i){
            u32 rid = lsas->rid;
            u32 network = ntohl(lsas->array[i].network);
            u32 mask = ntohl(lsas->array[i].mask);
            u32 nbr_rid = ntohl(lsas->array[i].rid);
            
            // 打印为点分十进制格式
            printf("%d.%d.%d.%d\t", (rid >> 24) & 0xFF, (rid >> 16) & 0xFF, 
                                   (rid >> 8) & 0xFF, rid & 0xFF);
            printf("%d.%d.%d.%d\t", (network >> 24) & 0xFF, (network >> 16) & 0xFF, 
                                   (network >> 8) & 0xFF, network & 0xFF);
            printf("%d.%d.%d.%d\t", (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, 
                                   (mask >> 8) & 0xFF, mask & 0xFF);
            printf("%d.%d.%d.%d\t", (nbr_rid >> 24) & 0xFF, (nbr_rid >> 16) & 0xFF, 
                                   (nbr_rid >> 8) & 0xFF, nbr_rid & 0xFF);
            printf("%d\n", lsas->seq);
        }
		printf("--------------------------------------\n");
	}
}
