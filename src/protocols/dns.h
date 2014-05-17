#ifndef __DNS_H__
#define __DNS_H__

#include "../libredpi.h"

//TODO: collision

typedef struct {
	//TODO: ...
	void **next_context[COUNT_PROTO];
	
	//generic_context *previous_context;
	
	//void *user_data;
	generic_context *user_context;
} dns_context;


void process_dns(u_char *pkt, uint32_t pkt_len, void **dns_context_list);

#endif //__DNS_H__
