#ifndef __IP_H__
#define __IP_H__

typedef struct ip_context ip_context;
struct ip_context{
	//TODO: ...
	void **next_context[COUNT_PROTO];
	generic_context *user_context;
	
	//identifier data
	uint32_t src;
	uint32_t dst;
	
	//Chain list for collision
	ip_context* next_ip_context;
	ip_context* previous_ip_context;
};

#define IP_TYPE_UDP 17

void process_ip(u_char *pkt, uint32_t pkt_len, void **ip_context_list);

#endif //__IP_H__
