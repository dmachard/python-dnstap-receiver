
import socket
import struct
import logging
import asyncio
import time
import hashlib

import dnstap_receiver.dns.rdatatype as dns_rdatatypes
import dnstap_receiver.dns.rcode as dns_rcodes

clogger = logging.getLogger("dnstap_receiver.console")

SO_TIMESTAMPNS = 35

ETH_LEN     = 14
IPV4_LEN    = 20
IPV6_LEN    = 40 # 40 bytes
UDP_LEN     = 8
DNS_LEN     = 12
TCP_LEN     = 20 # header length in bytes

IPv4        = 0x0800
IPv6        = 0x86DD

TCP         = 6
UDP         = 17

def get_socket(interface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    
    s.bind( (interface, socket.SOCK_RAW) )
    s.setblocking(False)
    clogger.debug("Input handler: listening on interface %s" % interface)
    
    return s

def decode_question(dns_tap, data):
    buf = data
    qname = []
    
    while len(buf):
        length = buf[0]
        if length == 0x00:
            break
        label = buf[1:length+1]
        qname.append(buf[1:length+1])
        buf = buf[length+1:]

    dns_tap["rrtype"] = dns_rdatatypes.RDATATYPES[int.from_bytes(buf[1:3], "big")]
    dns_tap["qname"] = b".".join(qname) + b"."
    dns_tap["qname"] = dns_tap["qname"].decode()
    
async def watch_buffer(cfg, q, queues_list, stats, cache, start_shutdown):
    loop = asyncio.get_event_loop()
    
    while not start_shutdown.is_set():
        p = await q.get()
        data, ancdata, addr = p
        
        _, proto, _, _, _ = addr # interface name, protocol, packet type, arp, phy
        _, _, cmsg_data = ancdata # cmsg_level, cmsg_type, cmsg_data
        
        tap = {}
        tap["identity"] = cfg["dnstap-identity"]
        tap["latency"] = "-"
        tap["qname"] = "-"
        tap["rrtype"] = "-"
        tap["query-ip"] = "-"
        tap["query-port"] = "-"
        
        # extract arrival time
        tsec, _, nsec, _ = struct.unpack("iiii",cmsg_data)
        tap["time-sec"] = tsec
        tap["time-nsec"] = nsec
        tap["timestamp"] = tsec + nsec*1e-10
        
        # extract ethernet data 
        eth_data = data[ETH_LEN:]

        # decode ipv4 header ?
        if proto == IPv4:
            ip = eth_data[:IPV4_LEN]
            
            ip_proto = ip[9]
            ip_ihl = ( ip[0] & 15 )
            ip_data = eth_data[ (ip_ihl*32)//8: ]
            
            tap["family"] = "INET"
            tap["src-ip"] = socket.inet_ntoa(ip[12:16])
            tap["dst-ip"] = socket.inet_ntoa(ip[16:])
        
        # decode ipv6 header ?
        elif proto == IPv6:
            ip = eth_data[:IPV6_LEN]

            ip_proto = ip[6]
            ip_data = eth_data[IPV6_LEN:]
            
            tap["family"] = "INET6"
            tap["src-ip"] = socket.inet_ntop(socket.AF_INET6, ip[8:24])
            tap["dst-ip"] = socket.inet_ntop(socket.AF_INET6, ip[24:])

        else:
            continue # ignore other packet than ip

        # decode udp header ?
        if ip_proto == UDP:
            tap["protocol"] = "UDP"
            udp = ip_data[:UDP_LEN]

            tap["src-port"] = int.from_bytes(udp[0:2], "big")
            tap["dst-port"] = int.from_bytes(udp[2:4], "big")

            dns_payload = ip_data[UDP_LEN:]
        
        # decode tcp header ?
        # fragmented dns payload in several tcp push not yet implemented!
        elif ip_proto == TCP:
            tap["protocol"] = "TCP"
            
            tcp = ip_data[:TCP_LEN]

            psh = (int.from_bytes(tcp[12:14], "big") & 8) and 1 or 0
            if not psh: continue
            
            tap["src-port"] = int.from_bytes(tcp[0:2], "big")
            tap["dst-port"] = int.from_bytes(tcp[2:4], "big")
            
            data_offset = ( int.from_bytes(tcp[12:14], "big")  >> 12)*32//8
            dns_tcp_payload = ip_data[data_offset:]
        else:
            continue # ignore other protocol than udp and tcp

        # ignore packets according to the port
        if tap["src-port"] not in cfg["dns-port"] and tap["dst-port"] not in cfg["dns-port"]:
            continue

        if ip_proto == TCP:
            dns_length = int.from_bytes(dns_tcp_payload[0:2], "big")
            dns_payload = dns_tcp_payload[2:]
            
        # ignore the packet if the dns payload if too small
        if len(dns_payload) < DNS_LEN:  continue
 
        tap["payload"] = dns_payload
        # begin to decode the dns payload
        tap["id"] = int.from_bytes(dns_payload[0:2], "big")
        tap["type"] = "response" if int.from_bytes(dns_payload[2:4], "big") >> 15 else "query"
        
        tap["opcode"] = (int.from_bytes(dns_payload[2:4], "big") & 0x7800) >> 11
        tap["aa"] = (int.from_bytes(dns_payload[2:4], "big") & 0x0400) != 0 # authoritative answer
        tap["rd"] = (int.from_bytes(dns_payload[2:4], "big") & 0x100) != 0 # recursion desired
        tap["ra"] = (int.from_bytes(dns_payload[2:4], "big") & 0x80) != 0 # recursion available
        tap["tc"] = (int.from_bytes(dns_payload[2:4], "big") & 0x200) != 0 # truncated answer

        # find the type of dnstap message ?
        if cfg["client-query-support"] and tap["type"] == "query" and (tap["dst-ip"] in cfg["eth-ip"]):
            tap["message"] = "CLIENT_QUERY"
            tap["query-ip"] = tap["src-ip"]
            tap["query-port"] = tap["src-port"]
            tap["response-ip"] = tap["dst-ip"]
            tap["response-port"] = tap["dst-port"]
            
        elif cfg["client-response-support"] and tap["type"] == "response" and (tap["src-ip"] in cfg["eth-ip"]):
            tap["message"] = "CLIENT_RESPONSE"
            tap["query-ip"] = tap["dst-ip"]
            tap["query-port"] = tap["dst-port"]
            tap["response-ip"] = tap["src-ip"]
            tap["response-port"] = tap["src-port"]
            
        elif cfg["resolver-query-support"] and tap["type"] == "query" and not tap["rd"] and (tap["src-ip"] in cfg["eth-ip"]):
            tap["message"] = "RESOLVER_QUERY"
            tap["query-ip"] = tap["src-ip"]
            tap["query-port"] = tap["src-port"]
            tap["response-ip"] = tap["dst-ip"]
            tap["response-port"] = tap["dst-port"]
            
        elif cfg["resolver-response-support"] and tap["type"] == "response" and tap["aa"] and (tap["dst-ip"] in cfg["eth-ip"]):
            tap["message"] = "RESOLVER_RESPONSE"
            tap["query-ip"] = tap["dst-ip"]
            tap["query-port"] = tap["dst-port"]
            tap["response-ip"] = tap["src-ip"]
            tap["response-port"] = tap["src-port"]

        elif cfg["forwarder-query-support"] and tap["type"] == "query" and tap["rd"] and (tap["src-ip"] in cfg["eth-ip"]):
            tap["message"] = "FORWARDER_QUERY"
            tap["query-ip"] = tap["src-ip"]
            tap["query-port"] = tap["src-port"]
            tap["response-ip"] = tap["dst-ip"]
            tap["response-port"] = tap["dst-port"]
            
        elif cfg["forwarder-response-support"] and tap["type"] == "response" and tap["rd"] and (tap["dst-ip"] in cfg["eth-ip"]):
            tap["message"] = "FORWARDER_RESPONSE"
            tap["query-ip"] = tap["dst-ip"]
            tap["query-port"] = tap["dst-port"]
            tap["response-ip"] = tap["src-ip"]
            tap["response-port"] = tap["src-port"]
            
        else:
            continue

        # compute latency
        if tap["type"] == "query":
            hash_payload = "%s+%s+%s" % (tap["query-ip"], tap["src-port"], tap["id"])
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            cache[qhash] = tap["timestamp"]

        if tap["type"] == "response":
            hash_payload = "%s+%s+%s" % (tap["query-ip"], str(tap["dst-port"]), tap["id"])
            qhash = hashlib.sha1(hash_payload.encode()).hexdigest()
            if qhash in cache: tap["latency"] = round(tap["timestamp"]-cache[qhash],3)
          
        tap["length"] = len(dns_payload)
        
        tap["rcode"] = dns_rcodes.RCODES[int.from_bytes(dns_payload[2:4], "big") & 15]
        dns_qdcount = int.from_bytes(dns_payload[4:6], "big")
        
        # decode the question ?
        if dns_qdcount: decode_question(tap, dns_payload[DNS_LEN:])

        # update metrics 
        stats.record(tap=tap)
            
        # append the dnstap message to the queue
        for q_out in queues_list:
            q_out.put_nowait(tap)
            
def start_input(cfg, queue_sniffer, start_shutdown):
    clogger.debug("Input handler: sniffer")

    # prepare the socket
    s = get_socket(interface=cfg["eth-name"])

    # read data
    bufsize = 65535
    
    while not start_shutdown.is_set():
        try:
            raw_data, ancdata, _, address = s.recvmsg(bufsize, 1024)
        except BlockingIOError:
            time.sleep(0.01)
            continue
        queue_sniffer.put_nowait( (raw_data, ancdata[0], address) )
    
    clogger.debug("Input handler: closing sniffer")
    s.close()
