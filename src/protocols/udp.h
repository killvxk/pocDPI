#ifndef __UDP_H__
#define __UDP_H__

#include "libredpi.h"

//TODO: unic hash_size !
#define UDP_HASH_SIZE 0xFF

//TODO: transforme into generic proto_context !
//This is a session_context ...
typedef struct {
	//TODO: ...
	void **next_context[COUNT_PROTO];
	//TODO: This is not a user_context !
	//This is a layer_context !
	generic_context *user_context;
} udp_context;


void process_udp(u_char *pkt, uint32_t pkt_len, void **udp_context_list);

#endif //__UDP_H__
