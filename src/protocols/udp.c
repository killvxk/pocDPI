#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "udp.h"
#include "dns.h"
#include "ip.h"

//TODO: collision

inline uint16_t hash_udp(uint16_t src, uint16_t dst){
	return (src^dst) & PROTO_HASH_SIZE;
}

//TODO: make it generic...
udp_context* get_udp_context(uint16_t src, uint16_t dst, udp_context **udp_context_list){
	//TODO: collision!
	uint16_t cur_udp_hash = hash_udp(src, dst);
	if(udp_context_list[cur_udp_hash] ==  NULL){
		udp_context_list[cur_udp_hash] = (udp_context*)malloc(sizeof(udp_context));
		
		udp_context_list[cur_udp_hash]->user_context = (generic_context*)malloc(sizeof(generic_context));
		udp_context_list[cur_udp_hash]->user_context->previous_context = ((ip_context*)udp_context_list)->user_context;;
		
		int i;
		for(i=0; i<COUNT_PROTO; i++){
			udp_context_list[cur_udp_hash]->next_context[i] = (void**)calloc(PROTO_HASH_SIZE, sizeof(void*));
		}
	}
	//printf(">>>>>>>>>> cur_udp_hash %04x in %p %p\n", cur_udp_hash, udp_context_list, udp_context_list[cur_udp_hash]);
	return udp_context_list[cur_udp_hash];
}

void process_udp(u_char *pkt, uint32_t pkt_len, void **udp_context_list){
	//TODO: Check Check... !
	//DEBUG_HERE();
	//debug_pkt(pkt, pkt_len);
	//printf("udp_context_list %p\n", udp_context_list);
	
	uint16_t src_udp_port = pkt[0]<<8 | pkt[1];
	uint16_t dst_udp_port = pkt[2]<<8 | pkt[3];

	udp_context *cur_udp_context = get_udp_context(src_udp_port, dst_udp_port, (udp_context**)udp_context_list);
	
	call_callback(UDP_SRC_PORT, &src_udp_port, cur_udp_context->user_context);
	call_callback(UDP_DST_PORT, &dst_udp_port, cur_udp_context->user_context);

	//printf("cur_udp_context %p\n", cur_udp_context);

	//TODO: Dynamic Protocol Detection
	//TODO: Create context
	process_dns(pkt+8, pkt_len-8, (void**)cur_udp_context);
	
}
