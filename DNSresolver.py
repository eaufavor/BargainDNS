#!/usr/bin/env python2.7

import logging
import time
import Queue
import re
from threading import Thread
from dns import message, query, exception
import dnslib
import DNSserver

WHITE_LIST = re.compile(r'srv.*\.eaufavor\.info\.')
DNSlist = ['8.8.8.8']

class FetchWorker(Thread):
    def __init__(self, query_info):
        Thread.__init__(self)
        self.query_info = query_info

    def run(self):
        query_info = self.query_info
        NS = query_info[0]
        domain = query_info[1]
        query_type = query_info[2]
        queue = query_info[3]
        q = message.make_query(domain, query_type)
        rcode = q.rcode()
        count = 0
        start = time.time()*1000
        while True and count < 3:
            try:
                msg = query.udp(q, NS, timeout=1)
            except exception.Timeout:
                count += 1
                continue
            break
        if count >= 3:
            logging.warning("Worker thread for %s, too many retries", NS)
            queue.put(([], rcode))
            return rcode
        ips = []
        answer = None
        logging.debug("Worker thread for %s gets reply %s", NS, msg.answer)
        for anss in msg.answer:
            #print "Type", rdatatype.to_text(anss.to_rdataset().rdtype)
            if anss.to_rdataset().rdtype == query_type: #match record type
            #    logging.debug("reply %s", anss)
                answer = anss
        if answer is None:
            logging.warning("Worker thread for %s empty response for %s",\
                            NS, domain)
            queue.put(([], rcode))
            return 1
        for ans in answer:
            ips.append(ans.to_text())
        end = time.time()*1000
        logging.debug("Worker thread for %s got answer, delay: %dms",
                      NS, end-start)
        queue.put((ips, rcode))
        #time.sleep(0)
        return 0


class DNSresolver(DNSserver.DNSUDPRequestHandler):

    def dns_do_resolve(self, qname, qtype):
        if qtype != dnslib.QTYPE.A:
            ans = []
            code = dnslib.RCODE.NXDOMAIN
        elif not WHITE_LIST.match(qname):
            ans = []
            code = dnslib.RCODE.NXDOMAIN
            # NOTE: do normal resolving
        else:
            ans, code = self.parallel_resolve(qname)
        #addtional = (['aay'], dnslib.RCODE.NOERROR, dnslib.QTYPE.TXT)

        return ((ans, code), [])

    def get_NS(self, qname):
        # first, get all NS record
        q = message.make_query(qname, dnslib.QTYPE.A)
        IPlist = []
        count = 0
        while True and count < 3:
            try:
                msg = query.udp(q, DNSlist[0], timeout=1)
            except exception.Timeout:
                count += 1
                continue
            break
        if count >= 3:
            logging.warning("Getting NS(A) %s failed, too many retries", qname)
            return ([], dnslib.RCODE.NXDOMAIN)
        answer = None
        for anss in msg.answer:
            #print "Type", rdatatype.to_text(anss.to_rdataset().rdtype)
            if anss.to_rdataset().rdtype == dnslib.QTYPE.A: #match record type
            #    logging.debug("reply %s", anss)
                answer = anss

        if answer is None:
            logging.warning("Getting NS(A) %s failed, no NS(A)", qname)
            return ([], dnslib.RCODE.NXDOMAIN)
        for ans in answer:
            IPlist.append(ans.to_text())
        return IPlist

    def parallel_resolve(self, qname):
        logging.debug("Parallel resolver")
        NSlist = self.get_NS(qname)
        if not NSlist:
            return ([], dnslib.RCODE.NXDOMAIN)
        logging.debug("Ready for parallel query from %s", NSlist)
        start = time.time()*1000
        qtype = dnslib.QTYPE.A

        queue = Queue.Queue()

        # Fire parallel lookups
        workers = []
        for ns in NSlist:
            worker = FetchWorker((ns, qname, qtype, queue))
            worker.daemon = True
            worker.start()
            workers.append(worker)

        end = time.time()*1000
        logging.debug("prepare task, latency: %d ms", (end-start))
        time.sleep(0)
        # get the first response, and reply to client
        logging.debug("waiting for first response")
        start = time.time()*1000
        first_response = queue.get()

        end = time.time()*1000
        #print "parallel_resolve, latency: %d ms"%(end-start)
        logging.info("got first response:%s", first_response)
        return first_response

        '''
        start = time.time()*1000
        #if reply_callback:
        #    reply_query(first_response, request, reply_callback)
        end = time.time()*1000
        #print "Send reply, latency: %d ms"%(end-start)
        # wait for the rest answers

        answers = [first_response]
        for worker in workers:
            worker.join()
        logging.debug("all workers finished")
        while not queue.empty():
            answers.append(queue.get())
        '''




if __name__ == '__main__':
    dns_server = DNSserver.DNSserver(port=53, serverClass=DNSresolver)
    dns_server.start_server()
