#ifndef __ETH_H__
#define __ETH_H__

#include "libredpi.h"

//TODO: try to make it generic, macro...
typedef struct eth_context eth_context;
struct eth_context {
	//TODO: rename as next_layer_context
	void **next_context[COUNT_PROTO];
	generic_context *user_context;
	
	//identifier data
	u_char src[6];
	u_char dst[6];
	
	//Chain list for collision
	eth_context* next_eth_context;
	eth_context* previous_eth_context;
};

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

void process_eth(u_char *pkt, uint32_t pkt_len, void **eth_context_list);

#endif //__ETH_H__
