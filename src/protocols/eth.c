#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "eth.h"
#include "ip.h"

//TODO: __thread
//TODO: collision !

inline uint32_t hash_eth(u_char *src, u_char *dst){
	return ((src[3]<<24 | src[2]<<16 | src[1]<<8 | src[0]) ^ (dst[3]<<24 | dst[2]<<16 | dst[1]<<8 | dst[0])) & PROTO_HASH_SIZE;
}

eth_context *get_eth_context(u_char *src, u_char *dst, eth_context **eth_context_list){
	uint32_t cur_eth_hash = hash_eth(src, dst);

	eth_context *cur_eth_context = eth_context_list[cur_eth_hash];
	while(cur_eth_context){
		//TODO: find a better way : 
		if((memcmp(src, cur_eth_context->src, 6) == 0 && memcmp(dst, cur_eth_context->src, 6) == 0)
		|| (memcmp(dst, cur_eth_context->src, 6) == 0 && memcmp(src, cur_eth_context->src, 6) == 0)){ // 200 OK
			//Remove from list...
			cur_eth_context->previous_eth_context->next_eth_context = cur_eth_context->next_eth_context;
			cur_eth_context->next_eth_context->previous_eth_context = cur_eth_context->previous_eth_context;
			
			//Place this context at the head...
			cur_eth_context->next_eth_context = eth_context_list[cur_eth_hash];
			eth_context_list[cur_eth_hash]->previous_eth_context = cur_eth_context;
			eth_context_list[cur_eth_hash] = cur_eth_context;
			cur_eth_context->previous_eth_context = NULL;
			break;
		}
		cur_eth_context = cur_eth_context->next_eth_context;
	}
	
	if(cur_eth_context == NULL){//404 Not Found !
		cur_eth_context = (eth_context*)malloc(sizeof(eth_context));
		cur_eth_context->previous_eth_context = NULL;
		cur_eth_context->next_eth_context = eth_context_list[cur_eth_hash];
		if(eth_context_list[cur_eth_hash]){
			eth_context_list[cur_eth_hash]->previous_eth_context = cur_eth_context;
		}
		eth_context_list[cur_eth_hash] = cur_eth_context;
	
		int i;
		for(i=0; i<COUNT_PROTO; i++){
			cur_eth_context->next_context[i] = (void**)calloc(PROTO_HASH_SIZE, sizeof(void*));
		}
		
		memcpy(cur_eth_context->src, src, 6);
		memcpy(cur_eth_context->dst, dst, 6);
	}
	
	//Always at the head !
	return eth_context_list[cur_eth_hash];
}

void process_eth(u_char *pkt, uint32_t pkt_len, void **eth_context_list){
	//TODO: check ! CHECK ! CHECK !

	u_char eth_src[6];
	memcpy(eth_src, pkt, 6);
	u_char eth_dst[6];
	memcpy(eth_dst, pkt+6, 6);
	
	eth_context *cur_eth_context = get_eth_context(eth_src, eth_dst, eth_context_list);
	
	call_callback(ETH_SRC_ADDR, eth_src, cur_eth_context->user_context);
	call_callback(ETH_DST_ADDR, eth_dst, cur_eth_context->user_context);
	
	int ether_type = ((int)(pkt[12]) << 8) | (int)pkt[13];
	if(ether_type == ETHER_TYPE_IP){
		process_ip(pkt+14, pkt_len-14, cur_eth_context->next_context[IP_PROTO]);
	}
}

