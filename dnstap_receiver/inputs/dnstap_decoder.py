
import re
import logging
import socket
import hashlib
import struct
import dnstap_pb

import dnstap_receiver.dns.rdatatype as dns_rdatatypes
import dnstap_receiver.dns.rcode as dns_rcodes
import dnstap_receiver.dns.parser as dns_parser

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

DNSTAP_TYPE = dnstap_pb.dnstap_pb2._MESSAGE_TYPE.values_by_number
DNSTAP_FAMILY = dnstap_pb.dnstap_pb2._SOCKETFAMILY.values_by_number
DNSTAP_PROTO = dnstap_pb.dnstap_pb2._SOCKETPROTOCOL.values_by_number  

class UnknownValue:
    name = "-"

async def cb_ondnstap(dnstap_decoder, payload, cfg, queues_list, stats, geoip_reader, cache):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.ParseFromString(payload)
    dm = dnstap_decoder.message
            
    # type: CLIENT_QUERY
    # socket_family: INET
    # socket_protocol: UDP
    # query_address: "\n\000\000\002"
    # response_address: "\n\000\000\322"
    # query_port: 33019
    # response_port: 53
    # query_time_sec: 1609271575
    # query_time_nsec: 779179701
    # query_message: "\2300\001 \000\001\000\000\000\000\000\001\003www\006google\003com\000\000\034\000
    # \001\000\000)\020\000\000\000\000\000\000\014\000\n\000\010U\222\\\270\340\330jg"

    # type: CLIENT_RESPONSE
    # socket_family: INET
    # socket_protocol: UDP
    # query_address: "\n\000\000\002"
    # response_address: "\n\000\000\322"
    # query_port: 33019
    # response_port: 53
    # query_time_sec: 1609271575
    # query_time_nsec: 779179701
    # response_time_sec: 1609271575
    # response_time_nsec: 831279572
    # response_message: "\2300\201\200\000\001\000\001\000\000\000\001\003www\006google\003com\000\000\034
    # \000\001\300\014\000\034\000\001\000\000\000\236\000\020*\000\024P@\007\010\006\000\000\000\000\000\000 \004\000\000)\004\320\000\000\000\000\000\000"
    
    tap = { "identity": UnknownValue.name, 
            "qname": UnknownValue.name, 
            "rrtype": UnknownValue.name, 
            "query-ip": UnknownValue.name, "query-port": UnknownValue.name,
            "response-ip": UnknownValue.name, "response-port": UnknownValue.name,
            "latency": UnknownValue.name}

    # filtering by dnstap identity ?
    if len(dnstap_decoder.identity): tap["identity"] = dnstap_decoder.identity.decode()
    if cfg["filter"]["dnstap-identities"] is not None:
        if re.match(cfg["filter"]["dnstap-identities"], tap["identity"]) is None:
            return

    # decode type message
    tap["message"] = DNSTAP_TYPE.get(dm.type, UnknownValue.name).name
    tap["family"] = DNSTAP_FAMILY.get(dm.socket_family, UnknownValue.name).name
    tap["protocol"] = DNSTAP_PROTO.get(dm.socket_protocol, UnknownValue.name).name

    # decode query address
    qaddr = dm.query_address
    if len(qaddr) and dm.socket_family == 1:
        qaddr = qaddr[12:] if len(qaddr) == 16 else qaddr # condition for coredns, address is 16 bytes long so kept only 4 bytes
        tap["query-ip"] = socket.inet_ntop(socket.AF_INET, qaddr) # socket.inet_ntoa(qaddr)
    if len(qaddr) and dm.socket_family == 2: tap["query-ip"] = socket.inet_ntop(socket.AF_INET6, qaddr)
    if dm.query_port > 0: tap["query-port"] = dm.query_port

    # decode response address
    raddr = dm.response_address
    if len(raddr) and dm.socket_family == 1:
        raddr = raddr[12:] if len(raddr) == 16 else raddr # condition for coredns, address is 16 bytes long so kept only 4 bytes
        tap["response-ip"] = socket.inet_ntop(socket.AF_INET, raddr) # socket.inet_ntoa(qaddr)
    if len(raddr) and dm.socket_family == 2: tap["response-ip"] = socket.inet_ntop(socket.AF_INET6, raddr)
    if dm.response_port > 0: tap["response-port"] = dm.response_port
    
    # decode dns message
    dns_payload = dm.query_message if (dm.type % 2 ) == 1 else dm.response_message
    tap["payload"] = dns_payload
    
    if len(dns_payload) >= dns_parser.DNS_LEN:
        dns_id, dns_rcode, dns_qdcount = dns_parser.decode_dns(dns_payload)
    else:
        clogger.error('Dnstap decoder - dns payload too short: %s' % dns_payload)
        return
        
    if (dm.type % 2 ) == 1 :               
        tap["length"] = len(dm.query_message)
        tap["timestamp"] = dm.query_time_sec + round(dm.query_time_nsec )*1e-9
        tap["time-sec"] = dm.query_time_sec
        tap["time-nsec"] = dm.query_time_nsec
        tap["type"] = "query"
        
        # hash query and put in cache the arrival time
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dns_id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            cache[qhash] = tap["timestamp"]
            
    # handle response message
    if (dm.type % 2 ) == 0 :
        tap["length"] = len(dm.response_message)
        tap["timestamp"] = dm.response_time_sec + round(dm.response_time_nsec )*1e-9
        tap["time-sec"] = dm.response_time_sec
        tap["time-nsec"] = dm.response_time_nsec        
        tap["type"] = "response"

        # compute hash of the query and latency
        if len(dm.query_address) and dm.query_port > 0:
            hash_payload = "%s+%s+%s" % (dm.query_address, str(dm.query_port), dns_id)
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            if qhash in cache: tap["latency"] = round(tap["timestamp"]-cache[qhash],3)

    # common params
    if dns_qdcount:
        qname, qtype = dns_parser.decode_question(dns_payload)
        tap["qname"] = qname.decode(errors="ignore")
        if qtype > len(dns_rdatatypes.RDATATYPES):
            clogger.error('Dnstap decoder - invalid qtype in question: %s' % qtype)
            return
        tap["rrtype"] = dns_rdatatypes.RDATATYPES[qtype]
        
    tap["rcode"] = dns_rcodes.RCODES[dns_rcode]
    tap["id"] = dns_id

    # filtering by qname ?
    if cfg["filter"]["qname-regex"] is not None:
        if re.match(cfg["filter"]["qname-regex"], tap["qname"]) is None:
            return

    # geoip support 
    if geoip_reader is not None:
        try:
            response = geoip_reader.city(tap["query-ip"])
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
        q.put_nowait(tap.copy())
