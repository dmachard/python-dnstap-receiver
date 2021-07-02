
import struct

DNS_LEN = 12

unpack_dns = struct.Struct("!6H").unpack

def decode_question(data):
    """minimalist decoder for dns question"""
    buf = data[DNS_LEN:]
    qname = []

    while len(buf):
        length = buf[0]
        if length == 0x00:
            break
        label = buf[1:length+1]
        qname.append(buf[1:length+1])
        buf = buf[length+1:]

    # requires a buffer of 4 bytes 
    # fix issue #35, invalid packet but some abuser sends it
    if len(buf) <= 4:
        qtype = 0 # set to None
    else:
        # decode qtype and qclass 
        qtype, qclass  = struct.unpack('!HH', buf[1:5])    
    return (b".".join(qname)+ b".", qtype) 

def decode_dns(data):
    dns_hdr = unpack_dns(data[:DNS_LEN])
    dns_id = dns_hdr[0]
    dns_rcode = dns_hdr[1] & 15
    dns_qdcount = dns_hdr[2]
    
    return (dns_id, dns_rcode, dns_qdcount)
    
def print_dns(data):
    dns_id, dns_rcode, dns_qdcount = decode_dns(data)
    if dns_qdcount:
        qname, qtype = decode_question(data)