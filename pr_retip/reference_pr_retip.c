/* MWE
 *
 * This is an abstraction of pr_retip() from ping.c.
 * `buf` is the raw packet, generated using pinger.py
 */

#include <sys/param.h>		/* NB: we rely on this for <sys/types.h> */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

int
main(void)
{
	/* --special udp */
	//
	// IP header
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver= 4 |IHL= 5 |Type of Service|        Total Length = 56      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Identification = 1       |Flg=0|   Fragment Offset = 0   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Time = 64   |  Protocol = 1 |        header checksum        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         source address                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      destination address                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// ICMP header
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Type = 3    |   Code = 1    |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Identifier          |        Sequence Number        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// original IP header
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver= 4 |IHL=5  |Type of Service|        Total Length = 28      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Identification = 1       |Flg=0|   Fragment Offset = 0   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Time = 64   |  Protocol = 17|        header checksum        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         source address                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      destination address                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// original UDP header
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Source Port = 1234       |    Destination Port = 5678    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |            Length             |           Checksum            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     data octets ...
	// +-+-+-+-+-
	char buf[1000] = "\x45\x00\x00\x38" // begin IP header
	                 "\x00\x01\x00\x00"
	                 "\x40\x01\xF6\xC0"
	                 "\xC0\x00\x02\x02"
	                 "\xC0\x00\x02\x01"
	                 "\x03\x01\x81\x1C" // begin ICMP header
	                 "\x00\x00\x00\x00"
	                 "\x45\x00\x00\x1C" // begin original IP header
	                 "\x00\x01\x00\x00"
	                 "\x40\x11\xF6\xCC"
	                 "\xC0\x00\x02\x01"
	                 "\xC0\x00\x02\x02"
	                 "\x04\xD2\x16\x2E" // begin original UDP header
	                 "\x00\x08\x60\xDA"
	                 "\0";

	int hlen;
	struct ip *ip;
	struct icmp *icp;
	u_char *cp;

	/* Check the IP header */
	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;
	icp = (struct icmp *)(buf + hlen);

	ip = (struct ip *)icp->icmp_data;

	cp = (u_char *)ip + hlen;

	if (ip->ip_p == IPPROTO_TCP)
		printf("TCP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
	else if (ip->ip_p == IPPROTO_UDP)
		printf("UDP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));

	return (0);
}
