#!/usr/bin/env python2
import sys
#sys.path.append("./dnspython")
#sys.path.append("./dnslib")
#sys.path.append("./python-daemon")
#sys.path.append("./pylockfile")

#from dns import rdatatype, resolver
import time
#import multiprocessing.pool

import argparse
import datetime
import threading
import traceback
import SocketServer
import dnslib
import os.path
import signal
import daemon
import daemon.pidfile
import logging
import pickle

#from dnslib import *

PORT = 53

PIDFILE = os.path.abspath(r'./server.pid')
CACHE_FILE = os.path.abspath(r"./cache.db")

class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request,\
                                                 client_address, server)
        self.server = server
        return

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        logging.info('Got request: \n\n%s request %s (%s %s):',\
                     self.__class__.__name__[:3],\
                     now, self.client_address[0], self.client_address[1])
        try:
            data = self.get_data()
            logging.debug('RAW data(%d): %s', len(data), data.encode('hex'))
            # repr(data).replace('\\x', '')[1:-1]
            self.process_DNS_query(data)
            #self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)

    def process_DNS_query(self, data):
        # Must be overidden
        pass


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

class DNSUDPRequestHandler(UDPRequestHandler):

    def process_DNS_query(self, data):
        logging.debug("parsing DNS query")
        # parse the request
        request = dnslib.DNSRecord.parse(data)
        logging.info('Lookup request: %s', request)
        # lookup the record
        self.dns_resolve(request)

    def dns_resolve(self, request):
        logging.debug("resolving")
        qname_str = str(request.q.qname)
        qtype = request.q.qtype
        answer, additional_ans = self.dns_do_resolve(qname_str, qtype)
        self.reply_query(answer, request, additional_ans)

    def dns_do_resolve(self, qname, qtype):
        # override
        logging.error('dns_do_resolve not implemented %s, %s', qname, qtype)
        return ((dnslib.RCODE.NOTIMP, []), [])


    def reply_query(self, answer, request, additional_ans=None):
        DNS_response = self.prepare_reply(answer, request, additional_ans)
        self.send_data(DNS_response)


    def prepare_reply(self, answer, request, additional_ans=None, ttl=10):
        # pack anwsers
        qname = request.q.qname
        qtype = request.q.qtype
        qt = dnslib.QTYPE[qtype]
        rcode = answer[1]

        reply = dnslib.DNSRecord(dnslib.DNSHeader(\
                                id=request.header.id, qr=1, aa=1, ra=1,\
                                rcode=rcode), q=request.q)

        record_class = getattr(dnslib, str(qt))
        for a in answer[0]:
            reply.add_answer(dnslib.RR(rname=qname, rtype=qtype,\
                         rclass=1, ttl=ttl, rdata=record_class(a)))

        for ans in additional_ans:
            qtype = ans[2]
            qt = dnslib.QTYPE[qtype]
            rcode = ans[1]
            record_class = getattr(dnslib, str(qt))
            for a in ans[0]:
                reply.add_answer(dnslib.RR(rname=qname, rtype=qtype,\
                             rclass=1, ttl=ttl, rdata=record_class(a)))

        return reply.pack()



class DNSserver(object):
    def __init__(self, port=PORT, serverClass=DNSUDPRequestHandler):
        self.port = port
        self.serverClass = serverClass
        self.cache = {}

    def cache_manager(self):
        # reload cache saved to disk
        if os.path.isfile(CACHE_FILE):
            with open(CACHE_FILE, 'rb') as f:
                file_cache = pickle.load(f)
                for k in file_cache:
                    self.cache[k] = file_cache[k]
            logging.info('Loaded %d cache entries from disk', len(self.cache))

        while True:
            time.sleep(60)
            with open(CACHE_FILE, 'wb+') as f:
                pickle.dump(self.cache, f)
            logging.info('Autosaved %d cache entries to disk', len(self.cache))

    def do_start_server(self, bind_addr='0.0.0.0'):
        logging.info("Starting nameserver...")

        servers = [
            SocketServer.ThreadingUDPServer((bind_addr, self.port),\
                                            self.serverClass),
        ]
        routines = [
            threading.Thread(name='CacheManager', target=self.cache_manager,\
                             args=())
        ]
        for s in servers:
            thread = threading.Thread(target=s.serve_forever)
             # that thread will start one more thread for each request
            thread.daemon = True
            # exit the server thread when the main thread terminates
            thread.start()
            logging.info("%s server loop running in thread: %s",\
                         s.RequestHandlerClass.__name__[:3], thread.name)
        for r in routines:
            r.daemon = True
            r.start()
            logging.info("Routine %s started", r.name)
        try:
            while 1:
                time.sleep(1)
                sys.stderr.flush()
                sys.stdout.flush()

        except KeyboardInterrupt:
            pass
        finally:
            logging.warning('Shutting down servers')
            for s in servers:
                s.shutdown()

    def start_server(self):
        parser = argparse.ArgumentParser(\
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                    description='very fast DNS resolver')
        parser.add_argument('-p', '--port', type=int, default=53,\
                            help='the TCP port number the agent listens')
        parser.add_argument('-d', '--daemon', action='store_true',\
                            default=False, help='run the agent as a daemon')
        parser.add_argument('-l', '--loopback', action='store_true',\
                            default=False, help='bind to 127.0.0.1.')
        parser.add_argument('-k', '--kill', action='store_true',\
                            default=False, help='kill a running daemon')
        parser.add_argument('-q', '--quiet', action='store_true',\
                            default=False, help='only print errors')
        parser.add_argument('-v', '--verbose', action='store_true',\
                            default=False, help='print debug info.')
        args = parser.parse_args()
        if args.quiet:
            level = logging.WARNING
        elif args.verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
        logging.basicConfig(
            format="%(levelname) -10s %(asctime)s\
                    %(threadName)s:%(lineno) -7s %(message)s",
            level=level
        )
        self.port = args.port
        bind_addr = '0.0.0.0'
        if args.loopback:
            bind_addr = '127.0.0.1'

        if args.daemon:
            pidFile = daemon.pidfile.PIDLockFile(PIDFILE)
            pid = pidFile.read_pid()
            if pid is not None:
                logging.critical("Another daemon, PID %d, is running. Quit.",\
                                 pid)
                sys.exit(-1)
            serverLog = open('DNSserver.log', 'a+')
            context = daemon.DaemonContext(stdout=serverLog, stderr=serverLog, pidfile=pidFile)
            context.files_preserve = [serverLog]
            with context:
                logging.info("Starting Daemon on port %d", args.port)
                self.do_start_server(bind_addr)
        elif args.kill:
            pidFile = daemon.pidfile.PIDLockFile(PIDFILE)
            pid = pidFile.read_pid()
            if pid is None:
                logging.error("No daemon found.")
                sys.exit(-1)
            else:
                os.kill(int(pid), signal.SIGINT)
                logging.info("PID %d killed", pid)

        else:
            self.do_start_server(bind_addr)


if __name__ == '__main__':
    dns_server = DNSserver(port=53, serverClass=DNSUDPRequestHandler)
    dns_server.start_server()
