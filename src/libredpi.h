#ifndef __LIBREDPI_H__
#define __LIBREDPI_H__

typedef enum {
#include "protocols/eth.evt"
#include "protocols/ip.evt"
#include "protocols/udp.evt"
#include "protocols/dns.evt"
	COUNT_EVT
} DPI_EVT;

#define PROTO_HASH_SIZE 0xFF

typedef enum {
	ETH_PROTO,
	IP_PROTO,
	UDP_PROTO,
	DNS_PROTO,
	COUNT_PROTO
} DPI_PROTOCOL;

typedef struct {
	void *previous_context;
	void *user_data;
} generic_context;

typedef struct {
	//TODO: ...
	void **next_context[COUNT_PROTO];
	
	generic_context context;
} root_context;

#define call_callback(evt, args ...) if(activated_evt[evt]){ \
			activated_evt[evt](args); \
		}

void (*activated_evt[COUNT_EVT])();

#define DEBUG_HERE() printf("%s:%d\n", __FUNCTION__, __LINE__);
void debug_pkt(u_char *pkt, uint32_t pkt_len);

void ldpi_init();
void ldpi_register_evt(DPI_EVT event, void (*callback)());
void ldpi_process_pkt(u_char *pkt, uint32_t pkt_len);

#endif //__LIBREDPI_H__
