#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

#include "libredpi.h"


//TODO: make a library
//TODO: make a test directory
//TODO: make a protocols/tcp.c
//TODO: TODOs
//TODO: rename libreDPI to simpleDPI ?
void print_ip(uint32_t ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void eth_src_get(u_char *data){
	DEBUG_HERE();
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			data[0],
			data[1],
			data[2],
			data[3],
			data[4],
			data[5]);
}

void eth_dst_get(u_char *data){
	DEBUG_HERE();
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			data[0],
			data[1],
			data[2],
			data[3],
			data[4],
			data[5]);
}


typedef struct{
	uint32_t src_addr;
	uint32_t dst_addr;
}my_ip_context;

void ip_src_addr(uint32_t *src_addr, generic_context *context){
	context->user_data = (void*)malloc(sizeof(my_ip_context));
	((my_ip_context*)context->user_data)->src_addr = *src_addr;
}

void ip_dst_addr(uint32_t *dst_addr, generic_context *context){
	((my_ip_context*)context->user_data)->dst_addr = *dst_addr;
}

typedef struct{
	uint16_t src_port;
	uint16_t dst_port;
}my_udp_context;

void udp_src_port(uint16_t *src_port, generic_context *context){
	context->user_data = (void*)malloc(sizeof(my_udp_context));
	((my_udp_context*)context->user_data)->src_port = *src_port;
}

void udp_dst_port(uint16_t *dst_port, generic_context *context){
	((my_udp_context*)context->user_data)->dst_port = *dst_port;
}

typedef struct{
	char *querie_data;
	uint16_t querie_type;
}my_dns_context;

void dns_querie_start(generic_context *context){
	DEBUG_HERE();
	printf("context %p\n", context);
	context->user_data = (void*)malloc(sizeof(my_dns_context));
}

void dns_querie_end(generic_context *context){
	DEBUG_HERE();
	//printf("context %p\n", context);
	my_dns_context *tmp_dns_context = (my_dns_context*)context->user_data;
	
	//printf("context->previous_context %p\n", context->previous_context);
	
	generic_context *previous_context = (generic_context *)context->previous_context;
	my_udp_context *tmp_udp_context = (my_udp_context *)(previous_context->user_data);
	
	previous_context = previous_context->previous_context;
	my_ip_context *tmp_ip_context = (my_ip_context *)(previous_context->user_data);
	print_ip(tmp_ip_context->src_addr);
	printf(" ");
	print_ip(tmp_ip_context->dst_addr);

	printf(" %d %d ", tmp_udp_context->src_port, tmp_udp_context->dst_port);
	
	printf("%s %d\n", tmp_dns_context->querie_data, tmp_dns_context->querie_type);

	
	//exit(0);
}

void dns_querie_data(char *data, generic_context *context){
	//printf("%s\n", data);
	//printf("context %p\n", context);
	if((my_dns_context*)context->user_data){
		((my_dns_context*)context->user_data)->querie_data = strdup(data);
	}
}

void dns_querie_type(uint16_t *type, generic_context *context){
	if((my_dns_context*)context->user_data){
		((my_dns_context*)context->user_data)->querie_type = *type;
	}
}

//------------------------------------------------------------------- 
int main(int argc, char **argv) 
{ 
	unsigned int pkt_counter=0;
	unsigned long byte_counter=0;
	unsigned long cur_counter=0;
	struct pcap_pkthdr header;
	const u_char *packet;
	
	if (argc < 2) { 
		fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
		exit(1); 
	}
	
	ldpi_init();
	//ldpi_register_evt(ETH_SRC_ADDR, eth_src_get);
	//ldpi_register_evt(ETH_DST_ADDR, eth_dst_get);
	
	ldpi_register_evt(IP_SRC_ADDR, ip_src_addr);
	ldpi_register_evt(IP_DST_ADDR, ip_dst_addr);
	
	ldpi_register_evt(UDP_SRC_PORT, udp_src_port);
	ldpi_register_evt(UDP_DST_PORT, udp_dst_port);
	
	ldpi_register_evt(DNS_QUERIE_START, dns_querie_start);
	ldpi_register_evt(DNS_QUERIE_END, dns_querie_end);
	ldpi_register_evt(DNS_QUERIE_DATA, dns_querie_data);
	ldpi_register_evt(DNS_QUERIE_TYPE, dns_querie_type);
	
	int fnum;
	for (fnum=1; fnum < argc; fnum++) {  
		pcap_t *handle; 
		char errbuf[PCAP_ERRBUF_SIZE];
		handle = pcap_open_offline(argv[fnum], errbuf);
	 
		if (handle == NULL) { 
			fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[fnum], errbuf); 
			return(2); 
		} 
	 
	 
		while ((packet = pcap_next(handle,&header))) { 

			ldpi_process_pkt((u_char *)packet, header.len);
			
			
	 
			cur_counter += header.len; 
			byte_counter += header.len;
			pkt_counter++;
			
			if(pkt_counter == 4){
				//exit(0);
			}
	 
		}
	 
		pcap_close(handle);
	}
 
	printf("Processed %d packets and %lu Bytes, in %d files\n", pkt_counter, byte_counter, argc-1);
	return 0;
}
