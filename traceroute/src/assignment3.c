#include <netinet/ether.h>
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

#include "traceroute.h"
#include "raw.h"
#include "hexdump.h"
#include "checksums.h"

/*
 * We do not use the kernel's definition of the IPv6 header (struct ipv6hdr)
 * because the definition there is slightly different from what we would expect
 * (the problem is the 20bit flow label - 20bit is brain-damaged).
 *
 * Instead, we provide you struct that directly maps to the RFCs and lecture
 * slides below.
 */

struct ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint32_t tc1:4, version:4, flow_label1:4, tc2:4, flow_label2:16;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint32_t version:4, tc1:4, tc2:4, flow_label1:4, flow_label2:16;
#else
#error "You did something wrong"
#endif
	uint16_t plen;
	uint8_t nxt;
	uint8_t hlim;
	struct in6_addr src;
	struct in6_addr dst;
} __attribute__((packed));


void build_ipv6_header(struct ipv6_hdr *header, int hoplimit, struct in6_addr *srcip, struct in6_addr *dstip) {
	memset(header, 0, 40);
    
	// Version: IPv6
	header->version = 6;
	
	// Payload Length: 8
	header->plen = (uint16_t) htons(8);

	// Next Header: ICMPv6
	header->nxt = 0x3a;

	// Hop Limit:
	header->hlim = hoplimit;

	// Source Address:
	memcpy(&header->src, srcip, sizeof(struct in6_addr));

	// Destination Address:
	memcpy(&header->dst, dstip, sizeof(struct in6_addr));
}

void build_icmpv6(uint8_t *packet, int ident, int seq) {
	memset(packet, 0, 8);
	
	// Type, Code: Echo Request
	packet[0] = 128;
	packet[1] = 0;
	
	// Indentifier:
	packet[4] = (uint8_t) (ident >> 8);
	packet[5] = (uint8_t) ident;

	// Sequence Number:
	packet[6] = (uint8_t) (seq >> 8);
	packet[7] = (uint8_t) seq;

}

int check_data(struct ipv6_hdr *header_sent, struct icmp6_hdr *payload_rec) {
    // Hop limit of the copy header will always be 1
    uint8_t hlim = header_sent->hlim;
    header_sent->hlim = 1;
    int ret = (memcmp(header_sent, payload_rec+1, 48) == 0);
    header_sent->hlim = hlim;
    
    return ret;
}

int check_ident_seq(struct icmp6_hdr *payload_sent, struct icmp6_hdr *payload_rec) {
    return (memcmp(payload_sent->icmp6_data16, payload_rec->icmp6_data16, 4) == 0);
}

int ip6addr_cmp(struct in6_addr *addr1, struct in6_addr *addr2) {
    return (memcmp(addr1, addr2, sizeof(struct in6_addr)) == 0);
}

int verify_checksum(struct ipv6_hdr *header_rec, struct icmp6_hdr *payload_rec, uint16_t length) {
    uint16_t cksum = payload_rec->icmp6_cksum;
    
    // Checksum must be zero for calculation
    payload_rec->icmp6_cksum = 0;
    
    uint16_t cksum_comp = icmp6_checksum((struct ip6_hdr *) header_rec, (uint8_t *) payload_rec, length);
    
    payload_rec->icmp6_cksum = cksum;
    
    return cksum == cksum_comp;
}

uint8_t * traverse_ext_header(uint8_t *ext_header, uint16_t * ext_length) {
    // Search until we find something else
    while(ext_header[0] == 0x00 || ext_header[0] == 0x2b || ext_header[0] == 0x3c) {
        *ext_length += (8 + ext_header[1] * 8);
        ext_header += (8 + ext_header[1] * 8);
    }
    
    return ext_header;
}

int process_icmp6(struct ipv6_hdr *header_sent, struct ipv6_hdr *header_rec, struct icmp6_hdr *payload_sent, struct icmp6_hdr *payload_rec) {

    // Destination unreachable
    if(payload_rec->icmp6_type == 1 && check_data(header_sent, payload_rec)) {
        return 1;
    }

    // Time Exceeded in transit
    if(payload_rec->icmp6_type == 3
        && payload_rec->icmp6_code == 0
        && check_data(header_sent, payload_rec)) {
        return 3;
    }

    // Echo Reply
    if(payload_rec->icmp6_type == 129
        && payload_rec->icmp6_code == 0
        && check_ident_seq(payload_sent, payload_rec)
        && ip6addr_cmp(&header_sent->dst, &header_rec->src)) {
        return 129;
    }
    
    return 0;
}

int process_packet(struct ipv6_hdr *header_sent, struct ipv6_hdr *header_rec, struct icmp6_hdr *payload_sent, struct icmp6_hdr *payload_rec) {

	// Only handle IPv6
	if(header_rec->version != 6) {
		return 0;
	}
    
    // ICMP6 or traverse extension headers, ignore all others
	if(header_rec->nxt == 0x3a) {
        // Verify ICMP6 checksum
        if(!verify_checksum(header_rec, payload_rec, ntohs(header_rec->plen))) {
            return 0;
        }
        return process_icmp6(header_sent, header_rec, payload_sent, payload_rec);
	}
    else if(header_rec->nxt == 0x00 || header_rec->nxt == 0x2b || header_rec->nxt == 0x3c) {
        uint8_t *ext_header = (uint8_t *) (payload_rec);
        uint16_t ext_length = 0;
        
        // Find out if there is an ICMP6 header at the end of the extension headers
        // Add up total extension header length
        ext_header = traverse_ext_header(ext_header, &ext_length);
        if(ext_header[0] == 0x3a) {
            ext_length += (8 + ext_header[1] * 8);
            ext_header += (8 + ext_header[1] * 8);

            if(!verify_checksum(header_rec, (struct icmp6_hdr *) ext_header, ntohs(header_rec->plen) - ext_length)) {
                return 0;
            }
            return process_icmp6(header_sent, header_rec, payload_sent, (struct icmp6_hdr *) ext_header);
        }
    }

	return 0;
}

void run(int fd, const char *ipaddr, int timeoutval, int attempts,
         int maxhoplimit)
{
	char ipname[INET6_ADDRSTRLEN];
	struct in6_addr dstip;
	struct in6_addr srcip;
	uint8_t packet[1514];
    uint8_t rec[1514];
	size_t length = 48;
	int seq = 0;
	int ident = 0;
	int hoplimit = 1;
	int REACHED = 0;
	int UNREACHABLE = 0;
	ssize_t ret;

	srcip = *grnvs_get_ip6addr(fd);
	if(inet_pton(AF_INET6, ipaddr, &dstip) != 1) {
		fprintf(stderr, "Parsing failed - incorrect IPv6 format\n");
		return;
	}
 
    struct ipv6_hdr *header_sent = (struct ipv6_hdr *) packet;
    struct icmp6_hdr *payload_sent = (struct icmp6_hdr *) (packet + 40);
    struct ipv6_hdr *header_rec = (struct ipv6_hdr *) rec;
    struct icmp6_hdr *payload_rec = (struct icmp6_hdr *) (rec + 40);

	while (hoplimit <= maxhoplimit && !REACHED && !UNREACHABLE) {
		
		printf("%d", hoplimit);

		// Initialize IPv6 header		
		build_ipv6_header(header_sent, hoplimit, &srcip, &dstip);

		
		for(int i = 0; i < attempts; i++) {
			// Build payload: ICMPv6 Echo Request
			build_icmpv6(packet + 40, ident, seq);
			
            // Place checksum into packet
			uint16_t cksum = icmp6_checksum((struct ip6_hdr *) packet, packet + 40, length - 40);
			packet[42] = (uint8_t) cksum;
			packet[43] = (uint8_t) (cksum >> 8);

			if (( ret = grnvs_write(fd, packet, length)) < 0 ) {
				fprintf(stderr, "grnvs_write() failed: %ld\n", ret);
				hexdump(packet, length);
				exit(-1);
			}
			
			int found = 0;
			unsigned int timeout = 1000 * timeoutval;
            seq++;
   
			while(timeout > 0) {
				memset(rec, 0, sizeof(rec));

				if((ret = grnvs_read(fd, rec, 2*length, &timeout)) < 0) {
					fprintf(stderr, "grnvs_read() failed: %ld\n", ret);
					hexdump(rec, length);
					exit(-1);
				}
				
				inet_ntop(AF_INET6, rec+24, ipname, INET6_ADDRSTRLEN);

				if(memcmp(rec + 24, srcip.s6_addr, sizeof(srcip.s6_addr)) == 0) {
					found = 1;
					break;
				}
			}
            
			if(!found) {
				printf("  *");
				continue;
			}


			inet_ntop(AF_INET6, rec+8, ipname, INET6_ADDRSTRLEN);
			switch(process_packet(header_sent, header_rec, payload_sent, payload_rec)) {
				case 0:
					printf("  *");
					break;
                case 1:
                    UNREACHABLE = 1;
                    printf("  %s!X", ipname);
                    break;
                case 3:
                    printf("  %s", ipname);
                    break;
                case 129:
                    REACHED = 1;
                    printf("  %s", ipname);
                    break;
				default:
					printf("  *");
					break;
			}
            
		}
        
	    hoplimit++;
		printf("\n");
    }

/*===========================================================================*/
}

int main(int argc, char ** argv)
{
	struct arguments args;
	int sock;

	if ( parse_args(&args, argc, argv) < 0 ) {
		fprintf(stderr, "Failed to parse arguments, call with "
			"--help for more information\n");
		return -1;
	}

	if ( (sock = grnvs_open(args.interface, SOCK_DGRAM)) < 0 ) {
		fprintf(stderr, "grnvs_open() failed: %s\n", strerror(errno));
		return -1;
	}

	setbuf(stdout, NULL);

	run(sock, args.dst, args.timeout, args.attempts, args.hoplimit);

	grnvs_close(sock);

	return 0;
}
