
class Stats:
    def prepare(self):
        """prepare stats"""
        self.qr_total = 0
        self.qr_nxdomains = {}
        self.qr_noerror = {}
        self.qr_refused = {}
        self.qr_other = {}
        self.proto = { "UDP": 0, "TCP": 0 }
        self.family = { "INET": 0, "INET6": 0 }
        self.qtype = {}
        self.dtype = {}
        self.rcode = {}
        self.clts_qr = {}
        self.clts_bw = {}
        
    def record_dnstap(self, dnstap):
        """record the dnstap message"""
        # global counter for queries
        self.qr_total += 1
        
        # count query by the protocol udp or tcp
        self.proto[dnstap["protocol"]] += 1
        
        # count query by family
        self.family[dnstap["family"]] += 1
        
        # count dnstap message per type
        if dnstap["message"] not in self.dtype:
            self.dtype[dnstap["message"]] = 1
        else:
            self.dtype[dnstap["message"]] += 1
        
        # count unique domains according to the return code
        if dnstap["code"] == "NOERROR":
            if dnstap["query-name"] not in self.qr_noerror:
                self.qr_noerror[dnstap["query-name"]] = 1
            else:
                self.qr_noerror[dnstap["query-name"]] += 1
            
        elif dnstap["code"] == "NXDOMAIN": 
            if dnstap["query-name"] not in self.qr_nxdomains:
                self.qr_nxdomains[dnstap["query-name"]] = 1
            else:
                self.qr_nxdomains[dnstap["query-name"]] += 1
                
        elif dnstap["code"] == "REFUSED": 
            if dnstap["query-name"] not in self.qr_refused:
                self.qr_refused[dnstap["query-name"]] = 1
            else:
                self.qr_refused[dnstap["query-name"]] += 1
                
        else:
            if dnstap["query-name"] not in self.qr_other:
                self.qr_other[dnstap["query-name"]] = 1
            else:
                self.qr_other[dnstap["query-name"]] += 1

        # count per return code
        if dnstap["query-type"] not in self.qtype:
            self.qtype[dnstap["query-type"]] = 1
        else:
            self.qtype[dnstap["query-type"]] += 1
        
        # count per return code 
        if dnstap["code"] not in self.rcode:
            self.rcode[dnstap["code"]] = 1
        else:
            self.rcode[dnstap["code"]] += 1
        
        # count the number of queries per client ip
        if dnstap["source-ip"] not in self.clts_qr:
            self.clts_qr[dnstap["source-ip"]] = 1
        else:
            self.clts_qr[dnstap["source-ip"]] += 1
            
        # count the total bandwidth per client ip
        if dnstap["source-ip"] not in self.clts_bw:
            self.clts_bw[dnstap["source-ip"]] = dnstap["length"]
        else:
            self.clts_bw[dnstap["source-ip"]] += dnstap["length"]
         