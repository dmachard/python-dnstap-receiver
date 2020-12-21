
import re
import logging
import socket
import hashlib

from datetime import datetime, timezone

# python3 -m pip dnspython
import dns.rcode
import dns.rdatatype
import dns.message

from dnstap_receiver import dnspython_patch
from dnstap_receiver.codecs import dnstap_pb2 

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

DNSTAP_TYPE = dnstap_pb2._MESSAGE_TYPE.values_by_number
DNSTAP_FAMILY = dnstap_pb2._SOCKETFAMILY.values_by_number
DNSTAP_PROTO = dnstap_pb2._SOCKETPROTOCOL.values_by_number  

class UnknownValue:
    name = "-"

async def cb_ondnstap(dnstap_decoder, payload, cfg, queues_list, stats, geoip_reader, cache):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.ParseFromString(payload)
    dm = dnstap_decoder.message
    
    if cfg["trace"]["dnstap"]:
        dns_pkt = dm.query_message if (dm.type % 2 ) == 1 else dm.response_message
        clogger.debug("%s\n%s\n\n" % (dm,dns.message.from_wire(dns_pkt)) )

    # filtering by dnstap identity ?
    tap_ident = dnstap_decoder.identity.decode()
    if not len(tap_ident):
        tap_ident = UnknownValue.name
    if cfg["filter"]["dnstap-identities"] is not None:
        if re.match(cfg["filter"]["dnstap-identities"], dnstap_decoder.identity.decode()) is None:
            return
            
    tap = { "identity": tap_ident, 
            "qname": UnknownValue.name, 
            "rrtype": UnknownValue.name, 
            "query-type": UnknownValue.name, 
            "source-ip": UnknownValue.name,
            "latency": UnknownValue.name}
    
    # decode type message
    tap["payload"] = payload
    tap["message"] = DNSTAP_TYPE.get(dm.type, UnknownValue).name
    tap["family"] = DNSTAP_FAMILY.get(dm.socket_family, UnknownValue).name
    tap["protocol"] = DNSTAP_PROTO.get(dm.socket_protocol, UnknownValue).name

    # decode query address
    qaddr = dm.query_address
    if len(qaddr) and dm.socket_family == 1:
        # condition for coredns, address is 16 bytes long so keept only 4 bytes
        qaddr = qaddr[12:] if len(qaddr) == 16 else qaddr
        # convert ip to string
        tap["source-ip"] = socket.inet_ntoa(qaddr)
    if len(qaddr) and dm.socket_family == 2:
        tap["source-ip"] = socket.inet_ntop(socket.AF_INET6, qaddr)
    tap["source-port"] = dm.query_port
    if tap["source-port"] == 0:
        tap["source-port"] = UnknownValue.name
        
    # handle query message
    # todo catching dns.message.ShortHeader exception
    # can occured with coredns if the full argument is missing
    if (dm.type % 2 ) == 1 :
        dnstap_parsed = dnspython_patch.from_wire(dm.query_message, question_only=True)                 
        tap["length"] = len(dm.query_message)
        d1 = dm.query_time_sec +  (round(dm.query_time_nsec ) / 1000000000)
        tap["timestamp"] = datetime.fromtimestamp(d1, tz=timezone.utc).isoformat()
        tap["type"] = "query"
        
        # hash query and put in cache the arrival time
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dnstap_parsed.id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            cache[qhash] = d1
            
    # handle response message
    if (dm.type % 2 ) == 0 :
        dnstap_parsed = dnspython_patch.from_wire(dm.response_message, question_only=True)
        tap["length"] = len(dm.response_message)
        d2 = dm.response_time_sec + (round(dm.response_time_nsec ) / 1000000000) 
        tap["timestamp"] = datetime.fromtimestamp(d2, tz=timezone.utc).isoformat()
        tap["type"] = "response"

        # compute hash of the query and latency
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dnstap_parsed.id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            if qhash in cache: tap["latency"] = round(d2-cache[qhash],3)

    # common params
    if len(dnstap_parsed.question):
        tap["qname"] = dnstap_parsed.question[0].name.to_text()
        tap["rrtype"] = dns.rdatatype.to_text(dnstap_parsed.question[0].rdtype)
    tap["rcode"] = dns.rcode.to_text(dnstap_parsed.rcode())
    tap["id"] = dnstap_parsed.id
    tap["flags"] = dns.flags.to_text(dnstap_parsed.flags)

    # filtering by qname ?
    if cfg["filter"]["qname-regex"] is not None:
        if re.match(cfg["filter"]["qname-regex"], tap["qname"]) is None:
            return

    # geoip support 
    if geoip_reader is not None:
        try:
            response = geoip_reader.city(tap["source-ip"])
            if cfg["geoip"]["country-iso"]:
                tap["country"] = response.country.iso_code
            else:
                tap["country"] = response.country.name
            if response.city.name is not None:
                tap["city"] = response.city.name
            else:
                tap["city"] = UnknownValue.name
        except Exception as e:
            tap["country"] = UnknownValue.name
            tap["city"] = UnknownValue.name
            
    # update metrics 
    stats.record(tap=tap)
        
    # append the dnstap message to the queue
    for q in queues_list:
        q.put_nowait(tap)