
from collections import Counter
import asyncio
import re

# watcher for compute qps
async def watcher(statistics):
    """watcher for statistics"""
    while True:
        # sleep during one second
        await asyncio.sleep(1)
        
        # compute qps every interval
        statistics.compute_qps()
        
class StatsStream:
    def __init__(self, name):
        """constructor"""
        self.name = name

        self.bufq = {}
        self.bufr = {}
        self.bufi = {}

        self.prev_qr = 0
        
        self.cnts = Counter()
        self.cnts_rcode = Counter()
        self.cnts_rrtype = Counter()

    def record(self, tap):
        """record only response dnstap message"""
        qname = tap["qname"]; srcip = tap["source-ip"]; 
        qr = tap["type"]; rcode = tap["rcode"]; rrtype = tap["rrtype"]
        
        # count number of hit and bytes for each source ip
        if srcip not in self.bufi: self.bufi[srcip] = Counter()
        for i in ["hit", "length"]:
            self.bufi[srcip].update({i:tap.get(i, 1)})
        self.cnts["clients"] = len(self.bufi)
        
        # count number of dnstap query or response.
        self.cnts.update({qr:1})
        
        # count number of dnstap according to the protocol and family
        self.cnts.update({"%s/%s" % (qr,tap["protocol"].lower()):1})
        self.cnts.update({"%s/%s" % (qr,tap["family"].lower()):1})

        # prepare the buffer according to the dnstap message
        buf = self.bufq if qr == "query" else self.bufr 
        if qname not in buf: buf[qname] = Counter()

        # count number of hit and byte for each qname
        buf[qname].update({"hit": 1})
        buf[qname].update({"length": tap["length"]})
        
        # count number of rcode and rrtype for each qname
        buf[qname].update({rcode.lower(): 1})
        buf[qname].update({rrtype.lower(): 1})
        
        # count number of rcode and rrtype for each qname
        self.cnts_rcode.update({ "%s/%s" % (qr,rcode.lower()): 1})
        self.cnts_rrtype.update({ "%s/%s" % (qr,rrtype.lower()): 1})

        # finaly count number of unique domains
        qnames = set(self.bufq)
        qnames.update(set(self.bufr))
        self.cnts["domains"] = len(qnames)

    def reset(self):
        """reset the stream"""
        # reset all counters and buffers
        self.bufi.clear()
        self.bufq.clear()
        self.bufr.clear()
        
        self.cnts.clear()
        self.cnts_rcode.clear()
        self.cnts_rrtype.clear()
        
        self.prev_qr = 0

    def compute_qps(self):
        """compute qps query/qps and response/qps"""
        cur_qr = self.cnts.get("query", 0)
        if cur_qr == 0: return

        qps = cur_qr - self.prev_qr
        if qps < 0: qps = 0
        self.cnts["qps"]  = qps
        self.prev_qr = cur_qr
        
class Statistics:
    def __init__(self):
        """constructor"""
        self.streams = {}
        
        # Counter({'query/response': <int>, 'query|response/udp|tcp': <int>, 
        # 'query|response/inet|inet6': <int>, 'domains': <int>, 'clients': <int>})
        self.cnts = Counter()
        # Counter({'query|response/<rcode>': <int>})
        self.cnts_rcode = Counter()
        # Counter({'query|response/<rrtype>': <int>})
        self.cnts_rrtype = Counter()
        
        self.global_qps = Counter()
        
    def record(self, tap):
        """record dnstap message"""
        if tap["identity"] not in self.streams:
            s = StatsStream(name=tap["identity"])
            self.streams[tap["identity"]] = s
        self.streams[tap["identity"]].record(tap=tap)
    
        # update global counters
        self.update_counters()
        
    def update_counters(self):
        """create global counters"""
        # update global counters
        self.cnts.clear()
        self.cnts_rcode.clear()
        self.cnts_rrtype.clear()
        qnames = set()
        ips = set()
        for s in self.streams:
            ips.update(set(self.streams[s].bufi))
            
            qnames.update(set(self.streams[s].bufr))
            qnames.update(set(self.streams[s].bufq))
            
            self.cnts.update(self.streams[s].cnts)
            self.cnts_rcode.update(self.streams[s].cnts_rcode)
            self.cnts_rrtype.update(self.streams[s].cnts_rrtype)
  
        self.cnts["clients"] = len(ips)
        self.cnts["domains"] = len(qnames)
  
    def reset(self):
        """reset all streams"""
        # reset all counters and buffer in all streams
        for s in self.get_streams():
            s.reset()

        # reset global counters
        self.cnts.clear()
        self.cnts_rcode.clear()
        self.cnts_rrtype.clear()
        self.global_qps.clear()

    def get_streams(self, stream=None):
        """return list of stream object"""
        if stream is None:
            return list(self.streams.values())

        s = self.streams.get(stream)
        if s is None:
            return []
        else:
            return [s]
         
    def get_nameslist(self):
        """return stream name in a list"""
        return list(self.streams.keys())

    def compute_qps(self):
        """create some global counters"""
        self.global_qps.clear()
        
        for s in self.get_streams():
            s.compute_qps()
            self.global_qps.update({"qps": s.cnts["qps"]})
        
        self.cnts["qps"] = self.global_qps["qps"]
      
    def get_counters(self, stream=None, filters=[]):
        """return all counters"""
        # get computed counters according to the stream
        # if the stream is not found, return the global counters
        s = self.streams.get(stream)
        _cnt = Counter()
        if s is None:
            _cnt.update(self.cnts)
            _cnt.update(self.cnts_rcode)
            _cnt.update(self.cnts_rrtype)
        else:
            _cnt.update(s.cnts)
            _cnt.update(s.cnts_rcode)
            _cnt.update(s.cnts_rrtype)

        # set counters
        c = {}
        for f in filters:
            c[f] = _cnt.get(f,0)
            
        return c

    def top_dnscode(self, n, stream=None, rcode=True):
        """return top- hit/response|query"""
        top = {}
        s = self.streams.get(stream)
        if rcode:
            cnt = s.cnts_rcode if s is not None else self.cnts_rcode
        else:
            cnt = s.cnts_rrtype if s is not None else self.cnts_rrtype
            
        for qr in [ "query", "response" ]:
            cnt_ = Counter(dict(filter(lambda x:x[0].startswith("%s" % qr), cnt.items())))
            top["hit/%s" % qr] = cnt_.most_common(n)
        return top

    def top_clients(self, n, stream):
        """return top clients"""
        top = {}
        for flag in [ "hit", "length" ]:
            cnt_ = Counter()
            for s in self.get_streams(stream=stream):
                for ip in s.bufi: 
                    cnt_.update({ip:s.bufi[ip][flag]})         
            top["%s/ip" % flag] = cnt_.most_common(n)
        return top
    
    def top_domains(self, n, stream, filters=[]):
        """return top domains"""
        top = {}
        for flag in filters:
            
            if "/" not in flag: break
            by, qr = flag.split("/")
            if qr not in ["query", "response"]: break
            
            top_list = []
            for s in self.get_streams(stream=stream):
                s_ = s.bufq if qr == "query" else s.bufr
                f = filter(lambda x:x[1].get(by, 0) > 0, s_.items())
                top_list.extend( sorted(f, key= lambda x:x[1][by], reverse=True)[:n] )

            # remove duplicate
            cnt_ = Counter()
            for (domain, counters) in top_list:
                cnt_.update({domain: counters[by]})
            top[flag] = cnt_.most_common(n)
        return top