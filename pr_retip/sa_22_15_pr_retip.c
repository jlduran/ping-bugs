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
#include <stddef.h>
#include <err.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define	ICMP_MINLEN	8		/* abs minimum */

#define	DEFDATALEN	56		/* default data length */

static int datalen = DEFDATALEN;
static int phdr_len = 0;

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
	u_char buf[1000] = "\x45\x00\x00\x38" // begin IP header
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

	int cc;

	u_char l;
	const u_char *icmp_data_raw;
	ssize_t icmp_data_raw_len;
	uint8_t hlen;
	struct ip oip;
	u_char oip_header_len;
	const u_char *oicmp_raw;

	struct ip *ip;
	const u_char *cp;

	cc = ICMP_MINLEN + phdr_len + datalen;

	/*
	 * Get size of IP header of the received packet.
	 * The header length is contained in the lower four bits of the first
	 * byte and represents the number of 4 byte octets the header takes up.
	 *
	 * The IHL minimum value is 5 (20 bytes) and its maximum value is 15
	 * (60 bytes).
	 */
	memcpy(&l, buf, sizeof(l));
	hlen = (l & 0x0f) << 2;

	icmp_data_raw_len = cc - (hlen + offsetof(struct icmp, icmp_data));
	icmp_data_raw = buf + hlen + offsetof(struct icmp, icmp_data);

	/*
	 * If we don't have enough bytes for a quoted IP header and an
	 * ICMP header then stop.
	 */
	if (icmp_data_raw_len <
			(ssize_t)(sizeof(struct ip) + sizeof(struct icmp))) {
		if (1)
			warnx("quoted data too short (%zd bytes) from %s",
				icmp_data_raw_len, "192.0.2.2");
		return (1);
	}

	memcpy(&oip_header_len, icmp_data_raw, sizeof(oip_header_len));
	oip_header_len = (oip_header_len & 0x0f) << 2;

	memcpy(&oip, icmp_data_raw, sizeof(struct ip));
	oicmp_raw = icmp_data_raw + oip_header_len;

	ip = &oip;
	cp = oicmp_raw;

	if (ip->ip_p == 6)
		(void)printf("TCP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
	else if (ip->ip_p == 17)
		(void)printf("UDP: from port %u, to port %u (decimal)\n",
			(*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));

	return (0);
}
