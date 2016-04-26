#!/usr/bin/env python
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

__author__ = 'michael salerno'
# id: 108512298

if not os.geteuid() == 0:
    sys.exit('Script must be run as root')

if len(sys.argv) != 3:
    print 'usage: <hostname> <DNS server>'
    exit(1)

pat = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

ans, unans = sr(IP(dst=sys.argv[2]) / UDP() / DNS(rd=1, qd=DNSQR(qname=sys.argv[1])), multi=1, timeout=1, verbose=0)

count = 0
for p in ans:
    count += 1
    print '\n\n'
    print '{:%^29}'.format('%')
    print '{:%>6}[ Response #{:02} ]{:%<7}'.format('#', count, '#')
    print '{:%^29}\n'.format('%')
    p[1][DNS][DNSRR].show()

if len(unans) > 0:
    print 'ERROR: some queries were unanswered'
