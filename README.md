# pinger.py mini How-to

## pr_iph

To generate an ICMP host unreachable packet (ICMP type 3, code 1) with
the Don't Fragment bit set:

    # python pinger.py --iface tun0 \
      --src 192.0.2.1 --dst 192.0.2.2 \
      --icmp_type 3 --icmp_code 1 \
      --opts NOP-40 --flags DF

## pr_pack

To generate an ICMP echo reply packet (ICMP type 0, code 0) with an
unknown option in the IP header:

    # python pinger.py --iface tun0 \
      --src 192.0.2.1 --dst 192.0.2.2 \
      --icmp_type 0 --icmp_code 0 \
      --opts unk

## pr_retip

To generate an ICMP host unreachable packet (ICMP type 3, code 1) of a
UDP packet, but originated from ping (I don't know how to craft this
packet organically):

    # python pinger.py --iface tun0 \
      --src 192.0.2.1 --dst 192.0.2.2 \
      --icmp_type 3 --icmp_code 1 \
      --special udp
