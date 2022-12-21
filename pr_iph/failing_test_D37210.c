/* MWE
 *
 * This is an abstraction of pr_iph() from ping.c.
 * `buf` is the raw packet, generated using pinger.py
 */

#include <sys/param.h>		/* NB: we rely on this for <sys/types.h> */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

static void pr_iph(struct ip *);

int
main(void)
{
	/* --opts NOP-40 --flags DF */
	//
	// IP header
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver= 4 |IHL= 5 |Type of Service|        Total Length = 152     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Identification = 1       |Flg=2|   Fragment Offset = 0   |
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
	// |Ver= 4 |IHL=15 |Type of Service|        Total Length = 124     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Identification = 1       |Flg=2|   Fragment Offset = 0   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Time = 64   |  Protocol = 1 |        header checksum        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         source address                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      destination address                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 | Opt. Code = 1 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// original ICMP header
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Type = 8    |   Code = 0    |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Identifier          |        Sequence Number        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Data ...
	// +-+-+-+-+-
	u_char buf[1000] = "\x45\x00\x00\x98" // begin IP header
	                   "\x00\x01\x40\x00"
	                   "\x40\x01\xB6\x60"
	                   "\xC0\x00\x02\x02"
	                   "\xC0\x00\x02\x01"
	                   "\x03\x01\xFC\xFE" // begin ICMP header
	                   "\x00\x00\x00\x00"
	                   "\x4F\x00\x00\x7C" // begin original IP header
	                   "\x00\x01\x40\x00"
	                   "\x40\x01\x98\x68"
	                   "\xC0\x00\x02\x01"
	                   "\xC0\x00\x02\x02"
	                   "\x01\x01\x01\x01" // original IP header options
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x01\x01\x01\x01"
	                   "\x08\x00\x61\x72" // original ICMP header
	                   "\xA2\x18\x00\x00"
	                   "\x00\x01\xCD\x27\x03\xD2\x38\x77" // original ICMP data
	                   "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	                   "\x10\x11\x12\x13\x14\x15\x16\x17"
	                   "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	                   "\x20\x21\x22\x23\x24\x25\x26\x27"
	                   "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	                   "\x30\x31\x32\x33\x34\x35\x36\x37"
	                   "\0";

	u_char l;
	const u_char *icmp_data_raw;
	uint8_t hlen;
	struct ip oip;
	u_char oip_header_len;

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

	icmp_data_raw = buf + hlen + offsetof(struct icmp, icmp_data);

	memcpy(&oip_header_len, icmp_data_raw, sizeof(oip_header_len));
	memcpy(&oip, icmp_data_raw, sizeof(struct ip));

	pr_iph(&oip);

	return (0);
}

/*
 * pr_iph --
 *	Print an IP header with options.
 */
static void
pr_iph(struct ip *ip)
{
	struct in_addr ina;
	u_char *cp;
	int hlen;

	hlen = ip->ip_hl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	(void)printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n");
	(void)printf(" %1x  %1x  %02x %04x %04x",
	    ip->ip_v, ip->ip_hl, ip->ip_tos, ntohs(ip->ip_len),
	    ntohs(ip->ip_id));
	(void)printf("   %1lx %04lx",
	    (u_long) (ntohl(ip->ip_off) & 0xe000) >> 13,
	    (u_long) ntohl(ip->ip_off) & 0x1fff);
	(void)printf("  %02x  %02x %04x", ip->ip_ttl, ip->ip_p,
							    ntohs(ip->ip_sum));
	memcpy(&ina, &ip->ip_src.s_addr, sizeof ina);
	(void)printf(" %s ", inet_ntoa(ina));
	memcpy(&ina, &ip->ip_dst.s_addr, sizeof ina);
	(void)printf(" %s ", inet_ntoa(ina));
	/* dump any option bytes */
	while (hlen-- > 20) {
		(void)printf("%02x", *cp++);
	}
	(void)putchar('\n');
}
