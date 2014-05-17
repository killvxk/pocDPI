#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "libredpi.h"
#include "protocols/eth.h"

void *root_context_list[COUNT_PROTO];

//TODO: list of context
//TODO: thread remove expirated context, free...
pthread_t gc_thread;
int running;

void debug_pkt(u_char *pkt, uint32_t pkt_len){
	printf("-------------------------\n");
	int i;
	for(i=0; i<pkt_len; i++){
		printf("%02x ", pkt[i]);
		if(i%12 == 11){
			printf("\n");
		}
	}
	printf("\n-------------------------\n\n");
	
	
}

void* ldpi_gc_main(void* args){
	int i;
	while( running ){
		for(i=0; i<PROTO_HASH_SIZE; i++){
			//TODO: foreach root proto context...
		}
	}
	return NULL;
}


void ldpi_init(){
	int i;
	for(i=0; i<COUNT_EVT; i++){
		activated_evt[i] = NULL;
	}
	
	for(i=0; i<COUNT_PROTO; i++){
		root_context_list[i] = NULL;
	}
	
	running = 1;
	//create garbage thread
	int err = pthread_create(&gc_thread, NULL, &ldpi_gc_main, NULL);
	if (err != 0){
		running = 0;
		//error
	}
}


void ldpi_register_evt(DPI_EVT event, void (*callback)()){
	activated_evt[event] = callback;
	printf("activation %d\n", event);
}

void ldpi_process_pkt(u_char *pkt, uint32_t pkt_len){
	//DEBUG_HERE();
	//debug_pkt(pkt, pkt_len);
	
	printf("%d\n", COUNT_EVT);
	//TODO: Guest root protocol
	int curr_proto = ETH_PROTO;
	if(root_context_list[curr_proto] == NULL){
		root_context_list[curr_proto] = (void **)malloc(sizeof(void*)*PROTO_HASH_SIZE);
	}
	process_eth(pkt, pkt_len, root_context_list[curr_proto]);
	
	
	//exit(0);
}
