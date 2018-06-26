#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <asm/byteorder.h>

#include "arguments.h"
#include "raw.h"
#include "hexdump.h"
#include "checksums.h"

/*====================================TODO===================================*/
/* Put your required struct definitions */

uint8_t mymac[ETH_ALEN];

typedef struct ethertype {
	uint16_t type;
	int frames;
	int bytes;
} Ethertype;

/* Put your ancillary functions here*/

int isBroadcast(uint8_t address[]) {
    for(int i = 0; i < ETH_ALEN; i++) {
		if(address[i] != 0xff)
		    return 0;
	}

	return 1;
}

int cmp (const void * a, const void * b) {
    const Ethertype *a1 = (Ethertype *) a;
	const Ethertype *a2 = (Ethertype *) b;

    return a1->type - a2->type;
}

Ethertype* append(Ethertype *elist, int len, Ethertype *etype) {
    if(elist == NULL)
		elist = (Ethertype *) malloc(sizeof(Ethertype));
	else
        elist = (Ethertype *) realloc(elist,  len * sizeof(Ethertype));
	elist[len-1] = *etype;

	return elist;
}

/*===========================================================================*/

void assignment2(int fd, int frames)
{
	unsigned int timeout = 10000;
	uint8_t recbuffer[1514];
	size_t ret;

/*====================================TODO===================================*/
	/* If you want to set up any data/counters before the receive loop,
	 * this is the right location
	 */

	memcpy(&mymac, grnvs_get_hwaddr(fd), ETH_ALEN);
	uint8_t destmac[ETH_ALEN];
	Ethertype *ethertypes;	

	int n_frames = 0;
	int my_frames = 0;
	int multicast_frames = 0;
	int ipv4 = 0;
	int ipv6 = 0;
	int total_bytes = 0;
    int n_types = 0;
	ethertypes = NULL;


/*===========================================================================*/

	/* This is the ready marker! do not remove! */
	fprintf(stdout, "I am ready!\n");

/*====================================TODO===================================*/
	/* Update the loop condition */
	while(n_frames < frames) {
/*===========================================================================*/
		ret = grnvs_read(fd, recbuffer, sizeof(recbuffer), &timeout);
		if (ret == 0) {
			fprintf(stderr, "Timed out, this means there was nothing to receive. Do you have a sender set up?\n");
			break;
		}

/*====================================TODO===================================*/
	/* This is the receive loop, 'recbuffer' will contain the received
	 * frame. 'ret' tells you the length of what you received.
	 * Anything that should be done with every frame that's received
	 * should be done here.
	 */
		memcpy(&destmac, &recbuffer, ETH_ALEN);
		if(!memcmp(&mymac, &destmac, sizeof(mymac))) {
		    my_frames++;
		}
		else if(isBroadcast(destmac) || (destmac[0] & 1)) {
		    multicast_frames++;
		}

		uint16_t type = recbuffer[13] | recbuffer[12] << 8;
		int found = 0;

		for(int i = 0; i < n_types; i++) {
		    if(ethertypes == NULL)
				break;
		    if(ethertypes[i].type == type) {
				found = 1;
				ethertypes[i].frames++;
				ethertypes[i].bytes += ret;
				break;
			}
		}
		
		if(!found) {
		    Ethertype newType = {type, 1, ret};
			n_types++;
		    ethertypes = append(ethertypes, n_types, &newType);
		}

		total_bytes += ret;

		if(type == 0x0800)
		    ipv4 += ret;
		else if(type == 0x86dd)
		    ipv6 += ret;

		n_frames++;
/*===========================================================================*/
	}

/*====================================TODO===================================*/
	/* Print your summary here */
    qsort(ethertypes, n_types, sizeof(Ethertype), cmp);

    for(int i = 0; i < n_types; i++) {
		printf("0x%04x: %d frames, %d bytes\n", ethertypes[i].type, ethertypes[i].frames, ethertypes[i].bytes);
	}
	
	printf("%d of them were for me\n", my_frames);
	printf("%d of them were multicast\n", multicast_frames);

	double pct4 = total_bytes ? 100.0f * ipv4 / total_bytes : 0.0f;
	double pct6 = total_bytes ? 100.0f * ipv6 / total_bytes: 0.0f;
	printf("IPv4 accounted for %.1f%% and IPv6 for %.1f%% of traffic\n", pct4, pct6);
    
	// Free allocated memory
	free(ethertypes);
	ethertypes = NULL;
/*===========================================================================*/
}

int main(int argc, char ** argv)
{
	struct arguments args;
	int sock;

	setvbuf(stdout, NULL, _IOLBF, 0);

	if ( parse_args(&args, argc, argv) < 0 ) {
		fprintf(stderr, "Failed to parse arguments, call with "
			"--help for more information\n");
		return -1;
	}

	if ( (sock = grnvs_open(args.interface, SOCK_RAW)) < 0 ) {
		fprintf(stderr, "grnvs_open() failed: %s\n", strerror(errno));
		return -1;
	}

	assignment2(sock, args.frames);

	grnvs_close(sock);

	return 0;
}
