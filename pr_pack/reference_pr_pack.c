/* MWE
 *
 * This is an abstraction of pr_pack() from ping.c.
 * Definitions are here for convenience.
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
#include <arpa/inet.h>

/*
 * Definitions for options.
 */
#define	IPOPT_EOL		0		/* end of option list */
#define	IPOPT_NOP		1		/* no operation */

#define	IPOPT_RR		7		/* record packet route */
#define	IPOPT_LSRR		131		/* loose source route */
#define	IPOPT_SSRR		137		/* strict source route */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define	IPOPT_OLEN		1		/* option length */
#define	IPOPT_OFFSET		2		/* offset within option */
#define	IPOPT_MINOFF		4		/* min value of above */

#define	MAX_IPOPTLEN		40

#define	INADDR_LEN		4		/* ((int)sizeof(in_addr_t)) */

int
main(void)
{
	/* --opts NOP-40 */
	// char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                  "\x00\x01\x00\x00"
	//                  "\x40\x01\xD8\x68"
	//                  "\xC0\x00\x02\x02"
	//                  "\xC0\x00\x02\x01"
	//                  "\x01\x01\x01\x01" // IP options
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x01\x01\x01\x01"
	//                  "\x00\x00\x78\x9F" // begin ICMP header
	//                  "\x2D\x05\x00\x00"
	//                  "\x00\x01\xAD\xD0\x15\x93\xAB\xF3" // ICMP data
	//                  "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                  "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                  "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                  "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                  "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                  "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                  "\0";

	/* --opts RR */
	// char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                  "\x00\x01\x00\x00"
	//                  "\x40\x01\xF4\x81"
	//                  "\xC0\x00\x02\x02"
	//                  "\xC0\x00\x02\x01"
	//                  "\x07\x27\x28"     // IP options
	//              "\xC0\x00\x02\x0A"
	//              "\xC0\x00\x02\x14"
	//              "\xC0\x00\x02\x1E"
	//              "\xC0\x00\x02\x28"
	//              "\xC0\x00\x02\x32"
	//              "\xC0\x00\x02\x3C"
	//              "\xC0\x00\x02\x46"
	//              "\xC0\x00\x02\x50"
	//              "\xC0\x00\x02\x5A\x00"
	//                  "\x00\x00\x39\x3B" // begin ICMP header
	//                  "\xDF\x23\x00\x00"
	//                  "\x00\x01\xB0\xBE\x16\x8C\x35\x52" // ICMP data
	//                  "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                  "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                  "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                  "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                  "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                  "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                  "\0";

	/* --opts LSRR */
	// char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                  "\x00\x01\x00\x00"
	//                  "\x40\x01\x9C\x81"
	//                  "\xC0\x00\x02\x02"
	//                  "\xC0\x00\x02\x01"
	//                  "\x83\x27\x04"     // IP options
	//              "\xC0\x00\x02\x0A"
	//              "\xC0\x00\x02\x14"
	//              "\xC0\x00\x02\x1E"
	//              "\xC0\x00\x02\x28"
	//              "\xC0\x00\x02\x32"
	//              "\xC0\x00\x02\x3C"
	//              "\xC0\x00\x02\x46"
	//              "\xC0\x00\x02\x50"
	//              "\xC0\x00\x02\x5A\x00"
	//                  "\x00\x00\xC7\x0E" // begin ICMP header
	//                  "\xBB\xD1\x00\x00"
	//                  "\x00\x01\xB3\xFA\x10\x25\xCD\xFB" // ICMP data
	//                  "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                  "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                  "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                  "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                  "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                  "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                  "\0";

	/* --opts SSRR */
	// char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                  "\x00\x01\x00\x00"
	//                  "\x40\x01\x96\x81"
	//                  "\xC0\x00\x02\x02"
	//                  "\xC0\x00\x02\x01"
	//                  "\x89\x27\x04"     // IP options
	//              "\xC0\x00\x02\x0A"
	//              "\xC0\x00\x02\x14"
	//              "\xC0\x00\x02\x1E"
	//              "\xC0\x00\x02\x28"
	//              "\xC0\x00\x02\x32"
	//              "\xC0\x00\x02\x3C"
	//              "\xC0\x00\x02\x46"
	//              "\xC0\x00\x02\x50"
	//              "\xC0\x00\x02\x5A\x00"
	//                  "\x00\x00\x6E\xFF" // begin ICMP header
	//                  "\x99\x57\x00\x00"
	//                  "\x00\x01\xB5\xCD\x1E\x57\x38\x80" // ICMP data
	//                  "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                  "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                  "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                  "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                  "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                  "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                  "\0";

	/* --opts unk-40 */
	// char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                  "\x00\x01\x00\x00"
	//                  "\x40\x01\x74\x04"
	//                  "\xC0\x00\x02\x02"
	//                  "\xC0\x00\x02\x01"
	//                  "\x9F\x9F\x9F\x9F" // IP options
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x9F\x9F\x9F\x9F"
	//                  "\x00\x00\x90\x64" // begin ICMP header
	//                  "\x4B\x34\x00\x00"
	//                  "\x00\x01\xB7\x53\x33\x48\x4E\xC7" // ICMP data
	//                  "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                  "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                  "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                  "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                  "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                  "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                  "\0";

	/* --opts unk */
	//
	// IP header
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Ver= 4 |IHL= 6 |Type of Service|        Total Length = 88      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      Identification = 1       |Flg=0|   Fragment Offset = 0   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Time = 64   |  Protocol = 1 |        header checksum        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         source address                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                      destination address                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Opt. Code =159| Opt. Code = 0 | Opt. Code = 0 | Opt. Code = 0 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//
	// ICMP header
	//
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   Type = 0    |   Code = 0    |          Checksum             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |           Identifier          |        Sequence Number        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     Data ...
	// +-+-+-+-+-
	char buf[1000] = "\x46\x00\x00\x58" // begin IP header
	                 "\x00\x01\x00\x00"
	                 "\x40\x01\x56\xA0"
	                 "\xC0\x00\x02\x02"
	                 "\xC0\x00\x02\x01"
	                 "\x9F\x00\x00\x00" // IP options
	                 "\x00\x00\x28\xDB" // begin ICMP header
	                 "\xC5\x53\x00\x00"
	                 "\x00\x01\xA1\xCE\x0F\x14\x75\xEA" // ICMP data
	                 "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	                 "\x10\x11\x12\x13\x14\x15\x16\x17"
	                 "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	                 "\x20\x21\x22\x23\x24\x25\x26\x27"
	                 "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	                 "\x30\x31\x32\x33\x34\x35\x36\x37"
	                 "\0";

	struct in_addr ina;
	u_char *cp;
	struct ip *ip;
	int hlen, i, j;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	/* Check the IP header */
	ip = (struct ip *)buf;
	hlen = ip->ip_hl << 2;

	/* Display any IP options */
	cp = (u_char *)buf + sizeof(struct ip);

	for (; hlen > (int)sizeof(struct ip); --hlen, ++cp)
		switch (*cp) {
		case IPOPT_EOL:
			hlen = 0;
			break;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			(void)printf(*cp == IPOPT_LSRR ?
			    "\nLSRR: " : "\nSSRR: ");
			j = cp[IPOPT_OLEN] - IPOPT_MINOFF + 1;
			hlen -= 2;
			cp += 2;
			if (j >= INADDR_LEN &&
			    j <= hlen - (int)sizeof(struct ip)) {
				for (;;) {
					bcopy(++cp, &ina.s_addr, INADDR_LEN);
					if (ina.s_addr == 0)
						(void)printf("\t0.0.0.0");
					else
						(void)printf("\t%s",
						     inet_ntoa(ina));
					hlen -= INADDR_LEN;
					cp += INADDR_LEN - 1;
					j -= INADDR_LEN;
					if (j < INADDR_LEN)
						break;
					(void)putchar('\n');
				}
			} else
				(void)printf("\t(truncated route)\n");
			break;
		case IPOPT_RR:
			j = cp[IPOPT_OLEN];		/* get length */
			i = cp[IPOPT_OFFSET];		/* and pointer */
			hlen -= 2;
			cp += 2;
			if (i > j)
				i = j;
			i = i - IPOPT_MINOFF + 1;
			if (i < 0 || i > (hlen - (int)sizeof(struct ip))) {
				old_rrlen = 0;
				continue;
			}
			if (i == old_rrlen
			    && !bcmp((char *)cp, old_rr, i)
			    && 1) {
				(void)printf("\t(same route)");
				hlen -= i;
				cp += i;
				break;
			}
			old_rrlen = i;
			bcopy((char *)cp, old_rr, i);
			(void)printf("\nRR: ");
			if (i >= INADDR_LEN &&
			    i <= hlen - (int)sizeof(struct ip)) {
				for (;;) {
					bcopy(++cp, &ina.s_addr, INADDR_LEN);
					if (ina.s_addr == 0)
						(void)printf("\t0.0.0.0");
					else
						(void)printf("\t%s",
						     inet_ntoa(ina));
					hlen -= INADDR_LEN;
					cp += INADDR_LEN - 1;
					i -= INADDR_LEN;
					if (i < INADDR_LEN)
						break;
					(void)putchar('\n');
				}
			} else
				(void)printf("\t(truncated route)");
			break;
		case IPOPT_NOP:
			(void)printf("\nNOP");
			break;
		default:
			(void)printf("\nunknown option 0x%x", *cp);
			break;
		}
	if (1) {
		(void)putchar('\n');
		(void)fflush(stdout);
	}

	return (0);
}
