/* OpenBSD
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
#include <netdb.h>

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

//#define	NI_MAXHOST		256	/* max host name from getnameinfo (MAXHOSTNAMELEN) */

const char		*pr_addr(struct sockaddr *, socklen_t);

void			 pr_ipopt(int, u_char *);

int
main(void)
{
	/* --opts NOP-40 */
	// u_char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                    "\x00\x01\x00\x00"
	//                    "\x40\x01\xD8\x68"
	//                    "\xC0\x00\x02\x02"
	//                    "\xC0\x00\x02\x01"
	//                    "\x01\x01\x01\x01" // IP options
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x01\x01\x01\x01"
	//                    "\x00\x00\x78\x9F" // begin ICMP header
	//                    "\x2D\x05\x00\x00"
	//                    "\x00\x01\xAD\xD0\x15\x93\xAB\xF3" // ICMP data
	//                    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                    "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                    "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                    "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                    "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                    "\0";

	/* --opts RR */
	// u_char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                    "\x00\x01\x00\x00"
	//                    "\x40\x01\xF4\x81"
	//                    "\xC0\x00\x02\x02"
	//                    "\xC0\x00\x02\x01"
	//                    "\x07\x27\x28"     // IP options
	//                "\xC0\x00\x02\x0A"
	//                "\xC0\x00\x02\x14"
	//                "\xC0\x00\x02\x1E"
	//                "\xC0\x00\x02\x28"
	//                "\xC0\x00\x02\x32"
	//                "\xC0\x00\x02\x3C"
	//                "\xC0\x00\x02\x46"
	//                "\xC0\x00\x02\x50"
	//                "\xC0\x00\x02\x5A\x00"
	//                    "\x00\x00\x39\x3B" // begin ICMP header
	//                    "\xDF\x23\x00\x00"
	//                    "\x00\x01\xB0\xBE\x16\x8C\x35\x52" // ICMP data
	//                    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                    "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                    "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                    "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                    "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                    "\0";

	/* --opts LSRR */
	// u_char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                    "\x00\x01\x00\x00"
	//                    "\x40\x01\x9C\x81"
	//                    "\xC0\x00\x02\x02"
	//                    "\xC0\x00\x02\x01"
	//                    "\x83\x27\x04"     // IP options
	//                "\xC0\x00\x02\x0A"
	//                "\xC0\x00\x02\x14"
	//                "\xC0\x00\x02\x1E"
	//                "\xC0\x00\x02\x28"
	//                "\xC0\x00\x02\x32"
	//                "\xC0\x00\x02\x3C"
	//                "\xC0\x00\x02\x46"
	//                "\xC0\x00\x02\x50"
	//                "\xC0\x00\x02\x5A\x00"
	//                    "\x00\x00\xC7\x0E" // begin ICMP header
	//                    "\xBB\xD1\x00\x00"
	//                    "\x00\x01\xB3\xFA\x10\x25\xCD\xFB" // ICMP data
	//                    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                    "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                    "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                    "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                    "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                    "\0";

	/* --opts SSRR */
	// u_char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                    "\x00\x01\x00\x00"
	//                    "\x40\x01\x96\x81"
	//                    "\xC0\x00\x02\x02"
	//                    "\xC0\x00\x02\x01"
	//                    "\x89\x27\x04"     // IP options
	//                "\xC0\x00\x02\x0A"
	//                "\xC0\x00\x02\x14"
	//                "\xC0\x00\x02\x1E"
	//                "\xC0\x00\x02\x28"
	//                "\xC0\x00\x02\x32"
	//                "\xC0\x00\x02\x3C"
	//                "\xC0\x00\x02\x46"
	//                "\xC0\x00\x02\x50"
	//                "\xC0\x00\x02\x5A\x00"
	//                    "\x00\x00\x6E\xFF" // begin ICMP header
	//                    "\x99\x57\x00\x00"
	//                    "\x00\x01\xB5\xCD\x1E\x57\x38\x80" // ICMP data
	//                    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                    "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                    "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                    "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                    "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                    "\0";

	/* --opts unk-40 */
	// u_char buf[1000] = "\x4F\x00\x00\x7C" // begin IP header
	//                    "\x00\x01\x00\x00"
	//                    "\x40\x01\x74\x04"
	//                    "\xC0\x00\x02\x02"
	//                    "\xC0\x00\x02\x01"
	//                    "\x9F\x9F\x9F\x9F" // IP options
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x9F\x9F\x9F\x9F"
	//                    "\x00\x00\x90\x64" // begin ICMP header
	//                    "\x4B\x34\x00\x00"
	//                    "\x00\x01\xB7\x53\x33\x48\x4E\xC7" // ICMP data
	//                    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
	//                    "\x10\x11\x12\x13\x14\x15\x16\x17"
	//                    "\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
	//                    "\x20\x21\x22\x23\x24\x25\x26\x27"
	//                    "\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
	//                    "\x30\x31\x32\x33\x34\x35\x36\x37"
	//                    "\0";

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
	u_char buf[1000] = "\x46\x00\x00\x58" // begin IP header
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

	struct ip *ip = NULL;
	int hlen = -1;

	/* Check the IP header */
		ip = (struct ip *)buf;
		hlen = ip->ip_hl << 2;

	/* Display any IP options */
	if (1 && hlen > sizeof(struct ip))
		pr_ipopt(hlen, buf);

	return (0);
}

void
pr_ipopt(int hlen, u_char *buf)
{
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];
	struct sockaddr_in s_in;
	in_addr_t l;
	u_int i, j;
	u_char *cp;

	cp = buf + sizeof(struct ip);

	s_in.sin_len = sizeof(s_in);
	s_in.sin_family = AF_INET;

	for (; hlen > (int)sizeof(struct ip); --hlen, ++cp) {
		switch (*cp) {
		case IPOPT_EOL:
			hlen = 0;
			break;
		case IPOPT_LSRR:
			printf("\nLSRR: ");
			hlen -= 2;
			j = *++cp;
			++cp;
			i = 0;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					l = *++cp;
					l = (l<<8) + *++cp;
					l = (l<<8) + *++cp;
					l = (l<<8) + *++cp;
					if (l == 0)
						printf("\t0.0.0.0");
					else {
						s_in.sin_addr.s_addr = ntohl(l);
						printf("\t%s",
						    pr_addr((struct sockaddr*)
						    &s_in, sizeof(s_in)));
					}
					hlen -= 4;
					j -= 4;
					i += 4;
					if (j <= IPOPT_MINOFF)
						break;
					if (i >= MAX_IPOPTLEN) {
						printf("\t(truncated route)");
						break;
					}
					putchar('\n');
				}
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			hlen -= 2;
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				continue;
			if (i == old_rrlen &&
			    cp == buf + sizeof(struct ip) + 2 &&
			    !memcmp(cp, old_rr, i) &&
			    1) {
				printf("\t(same route)");
				i = (i + 3) & ~0x3;
				hlen -= i;
				cp += i;
				break;
			}
			if (i < MAX_IPOPTLEN) {
				old_rrlen = i;
				memcpy(old_rr, cp, i);
			} else
				old_rrlen = 0;

			printf("\nRR: ");
			j = 0;
			for (;;) {
				l = *++cp;
				l = (l<<8) + *++cp;
				l = (l<<8) + *++cp;
				l = (l<<8) + *++cp;
				if (l == 0)
					printf("\t0.0.0.0");
				else {
					s_in.sin_addr.s_addr = ntohl(l);
					printf("\t%s",
					    pr_addr((struct sockaddr*)&s_in,
					    sizeof(s_in)));
				}
				hlen -= 4;
				i -= 4;
				j += 4;
				if (i <= 0)
					break;
				if (j >= MAX_IPOPTLEN) {
					printf("\t(truncated route)");
					break;
				}
				putchar('\n');
			}
			break;
		case IPOPT_NOP:
			printf("\nNOP");
			break;
		default:
			printf("\nunknown option %x", *cp);
			if (cp[IPOPT_OLEN] > 0 && (cp[IPOPT_OLEN] - 1) <= hlen) {
				hlen = hlen - (cp[IPOPT_OLEN] - 1);
				cp = cp + (cp[IPOPT_OLEN] - 1);
			} else
				hlen = 0;
			break;
		}
	}
}

/*
 * pr_addr --
 *	Return address in numeric form or a host name
 */
const char *
pr_addr(struct sockaddr *addr, socklen_t addrlen)
{
	static char buf[NI_MAXHOST];
	int flag = 0;

	if (1)
		flag |= NI_NUMERICHOST;

	if (getnameinfo(addr, addrlen, buf, sizeof(buf), NULL, 0, flag) == 0)
		return (buf);
	else
		return "?";
}
