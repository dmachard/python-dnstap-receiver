
from collections import Counter
from collections import defaultdict

import asyncio
import re
from tlds import tld_set

# watcher for compute qps
async def watcher(statistics, start_shutdown):
    """watcher for statistics"""
    while not start_shutdown.is_set():
        # sleep during one second
        await asyncio.sleep(1)
        
        # refresh counters and compute qps every interval
        statistics.update_counters()
        statistics.compute_qps()
        statistics.compute_rps()
        statistics.compute_pps()
        
class StatsStream:
    def __init__(self, name, stats):
        """constructor"""
        self.stats = stats
        self.name = name

        self.bufq = defaultdict(Counter)
        self.bufr = defaultdict(Counter)
        self.bufi = defaultdict(Counter)

        self.prev_qr = 0
        self.prev_rp = 0
        
        self.cnts = Counter()
        self.cnts_rcode = Counter()
        self.cnts_rrtype = Counter()

        self.cnts_tlds = Counter()
        
        self.cnts_latency = Counter()
        
    def record(self, tap):
        """record only response dnstap message"""
        qname = tap["qname"]; srcip = tap["query-ip"]; 
        qr = tap["type"]; rcode = tap["rcode"]; rrtype = tap["rrtype"]
        
        # transform qname to lowercase ?
        if self.stats.cfg["qname-lowercase"]:
            qname = qname.lower()

        # count number of hit and bytes for each query ip
        self.bufi[srcip]["hit"] += 1
        self.bufi[srcip]["length"] += tap["length"]
        self.cnts["clients"] = len(self.bufi)
        
        # count number of dnstap query or response.
        self.cnts[qr] += 1
        
        # count number of dnstap according to the protocol and family
        self.cnts["%s/%s" % (qr,tap["protocol"].lower())] += 1
        self.cnts["%s/%s" % (qr,tap["family"].lower())] += 1

        # count total of bytes
        self.cnts["%s/bytes" % qr] += tap["length"]
        
        # prepare the buffer according to the dnstap message
        buf = self.bufq if qr == "query" else self.bufr 
        
        # count number of hit and byte for each qname
        buf[qname]["hit"] += 1
        buf[qname]["length"] += tap["length"]
        
        # count number of rcode and rrtype for each qname
        buf[qname][rcode.lower()] += 1
        buf[qname][rrtype.lower()] += 1
        
        # count number of rcode and rrtype for each qname
        self.cnts_rcode["%s/%s" % (qr,rcode.lower())] += 1
        self.cnts_rrtype["%s/%s" % (qr,rrtype.lower())] += 1

        # count number of unique domains
        self.cnts["domains"] = len(buf)

        # count tld
        tld_matched = list( filter(lambda x: x in tld_set, qname.rsplit(".", 2)) )
        if len(tld_matched):
            self.cnts_tlds["%s/%s" % (qr,tld_matched[-1])] += 1
        
        # latency
        if isinstance(tap["latency"], float):
            if tap["latency"] <= 0.001:
                self.cnts_latency["%s/latency0_1" % qr ] += 1
            if 0.001 < tap["latency"] <= 0.010 :
                self.cnts_latency["%s/latency1_10" % qr ] += 1
            if 0.010 < tap["latency"] <= 0.050 :
                self.cnts_latency["%s/latency10_50" % qr ] += 1
            if 0.050 < tap["latency"] <= 0.100 :
                self.cnts_latency["%s/latency50_100" % qr ] += 1
            if 0.100 < tap["latency"] <= 1.000 :
                self.cnts_latency["%s/latency100_1000" % qr ] += 1    
            if tap["latency"] > 1.000 :
                self.cnts_latency["%s/latency_slow" % qr ] += 1    
            
    def reset(self):
        """reset the stream"""
        # reset all counters and buffers
        self.bufi.clear()
        self.bufq.clear()
        self.bufr.clear()
        
        self.cnts.clear()
        self.cnts_rcode.clear()
        self.cnts_rrtype.clear()
        
        self.cnts_tlds.clear()
        self.cnts_latency.clear()
        
        self.prev_qr = 0
        self.prev_rp = 0
        
    def compute_qps(self):
        """compute qps query/qps and response/qps"""
        cur_qr = self.cnts.get("query", 0)
        if cur_qr == 0: return

        qps = cur_qr - self.prev_qr
        if qps < 0: qps = 0
        self.cnts["qps"]  = qps
        self.prev_qr = cur_qr
        
    def compute_rps(self):
        """compute response per second"""
        cur_rp = self.cnts.get("response", 0)
        if cur_rp == 0: return

        rps = cur_rp - self.prev_rp
        if rps < 0: rps = 0
        self.cnts["rps"]  = rps
        self.prev_rp = cur_rp
        
    def compute_pps(self):
        self.cnts["pps"]  = self.cnts["qps"] + self.cnts["rps"]
        
class Statistics:
    def __init__(self, cfg):
        """constructor"""
        self.cfg = cfg
        self.streams = {}
        
        # Counter({'query/response': <int>, 'query|response/udp|tcp': <int>, 
        # 'query|response/inet|inet6': <int>, 'domains': <int>, 'clients': <int>})
        self.cnts = Counter()
        # Counter({'query|response/<rcode>': <int>})
        self.cnts_rcode = Counter()
        # Counter({'query|response/<rrtype>': <int>})
        self.cnts_rrtype = Counter()
        
        # Counter({'query|response/<tlds>': <int>})
        self.cnts_tlds = Counter()
        # Counter({'response/latency0_10': <int>})
        self.cnts_latency = Counter()
        
        self.global_qps = Counter()
        self.global_rps = Counter()
        self.global_pps = Counter()
        
    def record(self, tap):
        """record dnstap message"""
        if tap["identity"] not in self.streams:
            s = StatsStream(name=tap["identity"], stats=self)
            self.streams[tap["identity"]] = s
        self.streams[tap["identity"]].record(tap=tap)

    def update_counters(self):
        """create global counters"""
        # update global counters
        self.cnts.clear()
        self.cnts_rcode.clear()
        self.cnts_rrtype.clear()
        self.cnts_tlds.clear()
        self.cnts_latency.clear()
        
        qnames = set()
        ips = set()
        for s in self.streams:
            ips.update(set(self.streams[s].bufi))
            
            qnames.update(set(self.streams[s].bufr))
            qnames.update(set(self.streams[s].bufq))
            
            self.cnts.update(self.streams[s].cnts)
            self.cnts_rcode.update(self.streams[s].cnts_rcode)
            self.cnts_rrtype.update(self.streams[s].cnts_rrtype)
  
            self.cnts_tlds.update(self.streams[s].cnts_tlds)
            self.cnts_latency.update(self.streams[s].cnts_latency)
            
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
        self.global_rps.clear()
        self.global_pps.clear()
        
        self.cnts_tlds.clear()
        self.cnts_latency.clear()
        
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
      
    def compute_rps(self):
        """create some global counters"""
        self.global_rps.clear()
        
        for s in self.get_streams():
            s.compute_rps()
            self.global_rps.update({"rps": s.cnts["rps"]})
        
        self.cnts["rps"] = self.global_rps["rps"]
        
    def compute_pps(self):
        self.global_pps.clear()
        
        for s in self.get_streams():
            s.compute_pps()
            self.global_pps.update({"pps": s.cnts["qps"] + s.cnts["rps"]})
        
        self.cnts["pps"] = self.global_pps["pps"]
        
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
            _cnt.update(self.cnts_tlds)
            _cnt.update(self.cnts_latency)
        else:
            _cnt.update(s.cnts)
            _cnt.update(s.cnts_rcode)
            _cnt.update(s.cnts_rrtype)
            _cnt.update(s.cnts_tlds)
            _cnt.update(s.cnts_latency)
            
        # set counters
        c = {}
        for f in filters:
            c[f] = _cnt.get(f,0)
            
        return c

    def top_rrtypes(self, n, stream=None):
        """return top- hit/response|query"""
        top = {}
        s = self.streams.get(stream)
        cnt = s.cnts_rrtype if s is not None else self.cnts_rrtype
            
        for qr in [ "query", "response" ]:
            cnt_ = Counter(dict(filter(lambda x:x[0].startswith("%s" % qr), cnt.items())))
            top["hit/%s" % qr] = cnt_.most_common(n)
        return top
        
    def top_rcodes(self, n, stream=None):
        """return top- hit/response|query"""
        top = {}
        s = self.streams.get(stream)
        cnt = s.cnts_rcode if s is not None else self.cnts_rcode 
        for qr in [ "query", "response" ]:
            cnt_ = Counter(dict(filter(lambda x:x[0].startswith("%s" % qr), cnt.items())))
            top["hit/%s" % qr] = cnt_.most_common(n)
        return top
        
    def top_tlds(self, n, stream):
        """return top tld"""
        top = {}
        s = self.streams.get(stream)
        cnt = s.cnts_tlds if s is not None else self.cnts_tlds   
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
