#!/usr/bin/env python
from datetime import datetime
from scapy.all import *
import argparse

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

'''
20160406-15:08:49.205618  DNS poisoning attempt
TXID 0x5cce Request www.example.com
Answer1 [List of IP addresses]
Answer2 [List of IP addresses]
'''

old_pkt = None


def get_ips(pkt):
    s = ''
    for i in range(pkt[DNS].ancount):
        s += pkt[DNS].an[i].rdata + ' '

    return s[:-1]


def print_attack(pkt1, pkt2):
    print(datetime.fromtimestamp(pkt1.time).strftime('%Y-%m-%d %H:%M:%S') + ' DNS poisoning attempt')
    print('TXID ' + str(pkt1[1][DNS].id) + ' Request ' + pkt1[1][DNS][DNSRR].rrname[:-1])
    print('Answer1 [' + get_ips(pkt1) + ']')
    print('Answer2 [' + get_ips(pkt2) + ']\n')


def dns_watch(pkt):
    global old_pkt
    if pkt.sport == 53 and UDP in pkt and pkt[1][DNS][DNSRR].type == 1:
        if old_pkt is not None and \
                        old_pkt[1][DNS][DNSRR].rrname == pkt[1][DNS][DNSRR].rrname and \
                        old_pkt[DNS].id == pkt[DNS].id and \
                        get_ips(old_pkt) != get_ips(pkt):
            print_attack(old_pkt, pkt)

        old_pkt = pkt


def main():
    global s, my_ip
    parser = argparse.ArgumentParser(description='DNS spoof detector.')

    parser.add_argument('-i', help='Listen on network device <interface> (e.g., eth0). If not specified,\
                        the program should select a default interface to listen on.',
                        type=str, required=False, default=None)

    parser.add_argument('-r', help='Read packets from <tracefile> (tcpdump format). Useful for detecting\
                        DNS poisoning attacks in existing network traces.',
                        type=str, required=False, default=None)

    parser.add_argument('expression', help="A BPF filter that specifies a subset of the traffic to be\
                        monitored.",
                        type=str, default=None)

    args = parser.parse_args()

    if args.r is None:
        sniff(iface=args.i, filter=args.expression, prn=dns_watch, lfilter=lambda x: x.haslayer(DNSRR))
    else:
        sniff(offline=args.r, filter=args.expression, prn=dns_watch, lfilter=lambda x: x.haslayer(DNSRR))


if __name__ == "__main__":
    main()
