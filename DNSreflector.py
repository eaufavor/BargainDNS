#!/usr/bin/env python2.7

import re
from urllib2 import urlopen
import dnslib
import DNSserver

MY_IP = []

SERVICE = re.compile(r'srv.*\.eaufavor\.info\.')


class DNSreflector(DNSserver.DNSUDPRequestHandler):

    def dns_do_resolve(self, qname, qtype):
        if qtype != dnslib.QTYPE.A:
            ans = []
            code = dnslib.RCODE.NXDOMAIN
        elif not SERVICE.match(qname):
            ans = []
            code = dnslib.RCODE.NXDOMAIN
        else:
            ans = MY_IP
            code = dnslib.RCODE.NOERROR
        addtional = (['aay'], dnslib.RCODE.NOERROR, dnslib.QTYPE.TXT)

        return ((ans, code), [addtional])


if __name__ == '__main__':
    # get my public IP
    MY_IP.append(urlopen('http://ip.42.pl/raw').read())
    print MY_IP
    # start server
    dns_server = DNSserver.DNSserver(port=53, serverClass=DNSreflector)
    dns_server.start_server()
