# pinger.py mini How-to

## pr_iph

To generate an ICMP host unreachable packet (ICMP type 3, code 1) with
40 NOP options and the Don't Fragment bit set in the original IP header:

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
UDP packet, but originated from ping ~~(I don't know how to craft this
packet organically)~~:

    # python pinger.py --iface tun0 \
      --src 192.0.2.1 --dst 192.0.2.2 \
      --icmp_type 3 --icmp_code 1 \
      --special udp

ping has this ICMP-sniffing capability, where it prints out any ICMP
errors, if invoked with `-v`, better explained in
freebsd/freebsd-src@ef9e6dc7eebe9830511602904d3ef5218d964080, silenced
in part by `-Q`.  After that commit, `pr_retip`'s code in question
became somewhat an appendix.  We'll test it nonetheless and propose a
removal/revival once the tests land.
