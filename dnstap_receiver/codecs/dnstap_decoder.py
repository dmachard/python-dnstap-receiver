
import re
import logging
import socket
import hashlib
import struct

from datetime import datetime, timezone

# python3 -m pip dnspython
import dns.rcode
import dns.rdatatype
import dns.message

from dnstap_receiver.codecs import dnstap_pb2 

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

DNSTAP_TYPE = dnstap_pb2._MESSAGE_TYPE.values_by_number
DNSTAP_FAMILY = dnstap_pb2._SOCKETFAMILY.values_by_number
DNSTAP_PROTO = dnstap_pb2._SOCKETPROTOCOL.values_by_number  

DNS_LEN = 12

class UnknownValue:
    name = "-"

unpack_dns = struct.Struct("!6H").unpack

def decode_question(data):
    buf = data
    qname = []

    while len(buf):
        length = buf[0]
        if length == 0x00:
            break
        label = buf[1:length+1]
        qname.append(buf[1:length+1])
        buf = buf[length+1:]

    q = struct.unpack('!HH', buf[1:5])    
    qtype = q[0]
    qclass = q[1]
    return (b".".join(qname)+ b".", qtype) 

def decode_dns(data):
    dns_hdr = unpack_dns(data[:DNS_LEN])
    dns_id = dns_hdr[0]
    dns_rcode = dns_hdr[1] & 15
    dns_qdcount = dns_hdr[2]
    
    return (dns_id, dns_rcode, dns_qdcount)
    
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
        
    # decode dns message
    dns_payload = dm.query_message if (dm.type % 2 ) == 1 else dm.response_message
    dns_id, dns_rcode, dns_qdcount = decode_dns(dns_payload)
    
    if (dm.type % 2 ) == 1 :               
        tap["length"] = len(dm.query_message)
        d1 = dm.query_time_sec +  (round(dm.query_time_nsec ) / 1000000000)
        tap["timestamp"] = datetime.fromtimestamp(d1, tz=timezone.utc).isoformat()
        tap["type"] = "query"
        
        # hash query and put in cache the arrival time
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dns_id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            cache[qhash] = d1
            
    # handle response message
    
    if (dm.type % 2 ) == 0 :
        tap["length"] = len(dm.response_message)
        d2 = dm.response_time_sec + (round(dm.response_time_nsec ) / 1000000000) 
        tap["timestamp"] = datetime.fromtimestamp(d2, tz=timezone.utc).isoformat()
        tap["type"] = "response"

        # compute hash of the query and latency
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dns_id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            if qhash in cache: tap["latency"] = round(d2-cache[qhash],3)

    # common params
    if dns_qdcount:
        qname, qtype = decode_question(dns_payload[DNS_LEN:])
        tap["qname"] = qname.decode()
        tap["rrtype"] = dns.rdatatype.to_text(qtype)
        
    tap["rcode"] = dns.rcode.to_text(dns_rcode)
    tap["id"] = dns_id

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