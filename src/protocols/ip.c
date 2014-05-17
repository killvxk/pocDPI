#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../libredpi.h"

#include "ip.h"
#include "udp.h"

//TODO: __thread
//TODO: collision !

inline uint32_t hash_ip(uint32_t src, uint32_t dst){
	return (src^dst) & PROTO_HASH_SIZE;
}

ip_context* get_ip_context(uint32_t src, uint32_t dst, ip_context **ip_context_list){
	//TODO: collision!
	uint32_t cur_ip_hash = hash_ip(src, dst);
	if(ip_context_list[cur_ip_hash] ==  NULL){
		ip_context_list[cur_ip_hash] = (ip_context*)malloc(sizeof(ip_context));
		ip_context_list[cur_ip_hash]->user_context = (generic_context*)malloc(sizeof(generic_context));
		
		int i;
		for(i=0; i<COUNT_PROTO; i++){
			ip_context_list[cur_ip_hash]->next_context[i] = (void**)calloc(PROTO_HASH_SIZE, sizeof(void*));
		}
	}
	return ip_context_list[cur_ip_hash];
}

void process_ip(u_char *pkt, uint32_t pkt_len, void **ip_context_list){
	//printf("ip_context_list %p\n", ip_context_list);
	//TODO: check !
	//DEBUG_HERE();
	//debug_pkt(pkt, pkt_len);
	int ip_header_len = (pkt[0] & 0x0F)*4;

	uint32_t src_ip_addr = pkt[12]<<24 | pkt[13]<<16 | pkt[14]<<8 | pkt[15];
	uint32_t dst_ip_addr = pkt[16]<<24 | pkt[17]<<16 | pkt[18]<<8 | pkt[19];
	
	ip_context *cur_ip_context = get_ip_context(src_ip_addr, dst_ip_addr, (ip_context**)ip_context_list);
	
	//TODO: CLIENT_ADDR, SERVER_ADDR
	call_callback(IP_SRC_ADDR, &src_ip_addr, cur_ip_context->user_context);
	call_callback(IP_DST_ADDR, &dst_ip_addr, cur_ip_context->user_context);

	
	int ip_protocol = pkt[9];
	if(ip_protocol == IP_TYPE_UDP){
		process_udp(pkt+ip_header_len, pkt_len-ip_header_len, (void**)cur_ip_context);
	}
}
