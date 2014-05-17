#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "dns.h"
#include "udp.h"

//TODO: collision


inline uint16_t hash_dns(uint16_t transaction_id){
	return (transaction_id) & PROTO_HASH_SIZE;
}

dns_context* get_dns_context(uint16_t transaction_id, dns_context **dns_context_list){
	//TODO: collision!
	uint16_t cur_dns_hash = hash_dns(transaction_id);
	if(dns_context_list[cur_dns_hash] ==  NULL){
		dns_context_list[cur_dns_hash] = (dns_context*)malloc(sizeof(dns_context));
		dns_context_list[cur_dns_hash]->user_context = (generic_context*)malloc(sizeof(generic_context));
		
		dns_context_list[cur_dns_hash]->user_context->previous_context = ((udp_context*)dns_context_list)->user_context;
		
		/*int i;
		for(i=0; i<COUNT_PROTO; i++){
			dns_context_list[cur_dns_hash]->next_context[i] = (void*)malloc(sizeof(void*));
		}*/
	}
	return dns_context_list[cur_dns_hash];
}



#define DNS_RESPONSE_FLAG 0x8000
void process_dns(u_char *pkt, uint32_t pkt_len, void **dns_context_list){
	//TODO: Check Check... !
	DEBUG_HERE();
	debug_pkt(pkt, pkt_len);

	uint16_t transaction_id = pkt[0]<<8 | pkt[1];

	//printf("transaction_id %04x\n", transaction_id);
	dns_context *cur_dns_context = get_dns_context(transaction_id, (dns_context**)dns_context_list);

	uint16_t flags = pkt[2]<<8 | pkt[3];
	//printf("flags %04x\n", flags);
	uint16_t questions = pkt[4]<<8 | pkt[5];
	uint16_t answer_rrs = pkt[6]<<8 | pkt[7];
	uint16_t authority_rrs = pkt[8]<<8 | pkt[9];
	uint16_t additional_rrs = pkt[10]<<9 | pkt[11];
	
	if(!(flags & DNS_RESPONSE_FLAG)){//Querie
		call_callback(DNS_QUERIE_START, cur_dns_context->user_context);
	}else{//Response
		call_callback(DNS_RESPONSE_START, cur_dns_context->user_context);
	}
	
	int i;
	int cur_index = 12;
	for(i=0; i<questions; i++){
		//TODO: questions types !
		char *querie_data = (char*)(pkt+cur_index);
		int querie_data_len = strlen(querie_data)+1;
		
		call_callback(DNS_QUERIE_DATA, querie_data, cur_dns_context->user_context);
		
		cur_index+=querie_data_len;
		uint16_t querie_type = pkt[cur_index++]<<8 | pkt[cur_index++];
		call_callback(DNS_QUERIE_TYPE, &querie_type, cur_dns_context->user_context);
		
		uint16_t querie_class = pkt[cur_index++]<<8 | pkt[cur_index++];
		
		//printf("%04x\n", querie_class);
	}
	
	printf("answer_rrs %d\n", answer_rrs);
	for(i=0; i<answer_rrs; i++){
		uint16_t answer_name = pkt[cur_index++]<<8 | pkt[cur_index++];
		uint16_t answer_type = pkt[cur_index++]<<8 | pkt[cur_index++];
		uint16_t answer_class = pkt[cur_index++]<<8 | pkt[cur_index++];
		uint32_t answer_ttl = pkt[cur_index++]<<24 | pkt[cur_index++]<<16 | pkt[cur_index++]<<8 | pkt[cur_index++];
		uint16_t answer_data_len = pkt[cur_index++]<<8 | pkt[cur_index++];
#define DNS_ANSWER_TXT_TYPE 0x0010
#define DNS_ANSWER_MX_TYPE 0x000F
#define DNS_ANSWER_PTR_TYPE 0x000c
#define DNS_ANSWER_A_TYPE 0x0001
#define DNS_ANSWER_AAAA_TYPE 0x001c
		if(answer_type == DNS_ANSWER_TXT_TYPE){
			uint16_t answer_txt_len = pkt[cur_index++];
			//char *answer_txt_data = 
			cur_index += answer_txt_len;
			//printf("answer_txt_len %d\n", answer_txt_len);
		}else if(answer_type == DNS_ANSWER_MX_TYPE){
			//printf("MX\n");
			uint16_t answer_preference = pkt[cur_index++]<<8 | pkt[cur_index++];
			//char *answer_mx_data = 
			cur_index += answer_data_len-2;
		}else if(answer_type == DNS_ANSWER_PTR_TYPE){
			//char *answer_ptr_data = 
			cur_index += answer_data_len;
		}else if(answer_type == DNS_ANSWER_A_TYPE){
			uint32_t answer_addr = pkt[cur_index++]<<24 | pkt[cur_index++]<<16 | pkt[cur_index++]<<8 | pkt[cur_index++];
		}else if(answer_type == DNS_ANSWER_A_TYPE){
			//char *answer_aaaa_data = 
			cur_index += answer_data_len;
		}else{
			//printf("Unknown dns answer type !\n");
		}
	}
	
	if(!(flags & DNS_RESPONSE_FLAG)){//Querie
		call_callback(DNS_QUERIE_END, cur_dns_context->user_context);
	}else{//Response
		call_callback(DNS_RESPONSE_END, cur_dns_context->user_context);
	}

	//TODO: Dynamic Protocol Detection
	//TODO: Create context
}
