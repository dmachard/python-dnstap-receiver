
from collections import Counter

class StatsStream:
    def __init__(self, name):
        """constructor"""
        self.name = name
        self.cnt = {
                "UDP": 0, "TCP": 0,
                "INET": 0, "INET6": 0,
                "queries": 0
            }
        self.buf = {
                "clients": {}, "clients-bw": {},
                "queries-types": {}, "dnstap-types": {},
                "responses-codes": {}, "responses-noerror": {},
                "responses-nx":{}, "responses-refused": {},
                "responses-other": {},
            }
        
    def record(self, dnstap):
        """record dnstap message"""
        # global counter for queries
        self.cnt["queries"] += 1
        
        # count query by the protocol udp or tcp
        self.cnt[dnstap["protocol"]] += 1
        
        # count query by family
        self.cnt[dnstap["family"]] += 1
        
        # count dnstap message per type
        if dnstap["message"] not in self.buf["dnstap-types"]:
            self.buf["dnstap-types"][dnstap["message"]] = 1
        else:
            self.buf["dnstap-types"][dnstap["message"]] += 1
        
        # count unique domains according to the return code
        if dnstap["code"] == "NOERROR":
            if dnstap["query-name"] not in self.buf["responses-noerror"]:
                self.buf["responses-noerror"][dnstap["query-name"]] = 1
            else:
                self.buf["responses-noerror"][dnstap["query-name"]] += 1
            
        elif dnstap["code"] == "NXDOMAIN": 
            if dnstap["query-name"] not in self.buf["responses-nx"]:
                self.buf["responses-nx"][dnstap["query-name"]] = 1
            else:
                self.buf["responses-nx"][dnstap["query-name"]] += 1
                
        elif dnstap["code"] == "REFUSED": 
            if dnstap["query-name"] not in self.buf["responses-refused"]:
                self.buf["responses-refused"][dnstap["query-name"]] = 1
            else:
                self.buf["responses-refused"][dnstap["query-name"]] += 1
                
        else:
            if dnstap["query-name"] not in self.buf["responses-other"]:
                self.buf["responses-other"][dnstap["query-name"]] = 1
            else:
                self.buf["responses-other"][dnstap["query-name"]] += 1

        # count per return code
        if dnstap["query-type"] not in self.buf["queries-types"]:
            self.buf["queries-types"][dnstap["query-type"]] = 1
        else:
            self.buf["queries-types"][dnstap["query-type"]] += 1
        
        # count per return code 
        if dnstap["code"] not in self.buf["responses-codes"]:
            self.buf["responses-codes"][dnstap["code"]] = 1
        else:
            self.buf["responses-codes"][dnstap["code"]] += 1
        
        # count the number of queries per client ip
        if dnstap["source-ip"] not in self.buf["clients"]:
            self.buf["clients"][dnstap["source-ip"]] = 1
        else:
            self.buf["clients"][dnstap["source-ip"]] += 1
            
        # count the total bandwidth per client ip
        if dnstap["source-ip"] not in self.buf["clients-bw"]:
            self.buf["clients-bw"][dnstap["source-ip"]] = dnstap["length"]
        else:
            self.buf["clients-bw"][dnstap["source-ip"]] += dnstap["length"]
            
    def reset(self):
        """reset the stream"""
        # reset all counters to zero
        for k,v in self.cnt.items():
            self.cnt[k] = 0
            
        # reset all buffers
        for k,v in self.buf.items():
            self.buf[k].clear()

class Statistics:
    def __init__(self):
        """constructor"""
        self.streams = {}
        
    def record(self, dnstap):
        """record dnstap message"""
        if dnstap["identity"] not in self.streams:
            s = StatsStream(name=dnstap["identity"])
            self.streams[dnstap["identity"]] = s
        self.streams[dnstap["identity"]].record(dnstap=dnstap)
          
    def reset(self):
        """reset all streams"""
        for _,s in self.streams.items():
            s.reset()

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
  
    def get_counters(self, stream=None):
        """return all counters"""
        counters = { "UDP": 0, "TCP": 0,
                     "INET": 0, "INET6": 0, "queries": 0,
                     "clients": 0, "domains": 0, 
                     "nxdomains": 0, "A": 0, "AAAA": 0 }
        for s in self.get_streams(stream=stream):    
            for k,v in s.cnt.items():
                if k not in counters:
                    counters[k] = 0
                counters[k] += v
                
            counters["clients"] += len(s.buf["clients"])
            
            domains = len(s.buf["responses-noerror"]) + len(s.buf["responses-nx"]) + \
                      len(s.buf["responses-refused"]) + len(s.buf["responses-other"])
            counters["domains"] += domains
            
            counters["nxdomains"] += len(s.buf["responses-nx"])

            if "A" in s.buf["queries-types"]:
                counters["A"] += s.buf["queries-types"]["A"]
            if "AAAA" in s.buf["queries-types"]:
                counters["AAAA"] += s.buf["queries-types"]["AAAA"]
                
        return counters
 
    def get_mostcommon(self, max, stream=None):
        """return top list"""
        # aggregation of all most common values
        mostcommon_ = {}
        for s in self.get_streams(stream=stream):
            for k,v in s.buf.items():
                if k not in mostcommon_:
                    mostcommon_[k] = {}
                for k2,v2 in Counter(v).most_common(int(max)):
                    if k2 in mostcommon_[k]:
                        mostcommon_[k][k2] += v2
                    else:
                        mostcommon_[k][k2] = v2
        
        # return final most commons list
        mostcommon = {}
        for k,v in mostcommon_.items():
            mostcommon[k] = Counter(v).most_common(int(max))
        return mostcommon