import argparse
import logging
import asyncio
import socket
import json
import sys

from datetime import datetime

# python3 -m pip dnslib
import dnslib

# wget https://raw.githubusercontent.com/dnstap/dnstap.pb/master/dnstap.proto
# wget https://github.com/protocolbuffers/protobuf/releases/download/v3.13.0/protoc-3.13.0-linux-x86_64.zip
# python3 -m pip install protobuf
# bin/protoc --python_out=. dnstap.proto

from dnstap_receiver import dnstap as dnstap_pb2
from dnstap_receiver import fstrm

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

parser = argparse.ArgumentParser()
parser.add_argument("-u", required=True,
                          help="read dnstap payloads using framestreams from unix socket")
parser.add_argument("-j", required=False,
                          help="write JSON payload to tcp/ip address")

# http://dnstap.info/

DNSTAP_TYPE = { 1: 'AUTH_QUERY',
                2: 'AUTH_RESPONSE',
                3: 'RESOLVER_QUERY',
                4: 'RESOLVER_RESPONSE',
                5: 'CLIENT_QUERY',
                6: 'CLIENT_RESPONSE',
                7: 'FORWARDER_QUERY',
                8: 'FORWARDER_RESPONSE',
                9: 'STUB_QUERY',
                10: 'STUB_RESPONSE',
                11: 'TOOL_QUERY',
                12: 'TOOL_RESPONSE' }
DNSTAP_FAMILY = {1: 'IPv4', 2: 'IPv6'}
DNSTAP_PROTO = {1: 'UDP', 2: 'TCP'}    

DATETIME_FORMAT ='%Y-%m-%d %H:%M:%S.%f'

async def cb_ondnstap(dnstap_decoder, payload, tcp_writer):
    """on dnstap"""
    dnstap_decoder.parse_from_bytes(payload)
    dm = dnstap_decoder.message
        
    dnstap_d = {}
    
    dnstap_d["message"] = DNSTAP_TYPE.get(dm.type.value, "?")
    dnstap_d["s_family"] = DNSTAP_FAMILY.get(dm.socket_family.value, "?")
    dnstap_d["s_proto"] = DNSTAP_PROTO.get(dm.socket_protocol.value, "?")

    if len(dm.query_address) and dm.socket_family.value == 1:
        dnstap_d["q_addr"] = socket.inet_ntoa(dm.query_address)
    elif len(dm.query_address) and dm.socket_family.value == 2:
        dnstap_d["q_addr"] = socket.inet_ntop(socket.AF_INET6, dm.query_address)
    else:
        dnstap_d["q_addr"] = "?"
    dnstap_d["q_port"] = dm.query_port
        
    query_time_milli = (round(dm.query_time_nsec / 1000000) / 1000)
    d1 = dm.query_time_sec +  query_time_milli
    dnstap_d["dt_query"] = datetime.fromtimestamp(d1).strftime(DATETIME_FORMAT)[:-3]
    
    # handle query message
    if (dm.type.value % 2 ) == 1 :
        query = dnslib.DNSRecord.parse(dm.query_message)
        dnstap_d["q_name"] = str(query.questions[0].get_qname())
        dnstap_d["q_type"] = dnslib.QTYPE[query.questions[0].qtype]
        dnstap_d["q_bytes"] = len(dm.query_message)
        
    # handle response message
    if (dm.type.value % 2 ) == 0 :
        reply_time_milli = (round(dm.response_time_nsec / 1000000) / 1000) 
        d2 = dm.response_time_sec + reply_time_milli

        dnstap_d["dt_reply"] = datetime.fromtimestamp(d2).strftime(DATETIME_FORMAT)[:-3]
        dnstap_d["q_time"] = round(d2-d1, 3)

        response = dnslib.DNSRecord.parse(dm.response_message)
        if len(response.questions):
            dnstap_d["q_name"] = str(response.questions[0].get_qname())
            dnstap_d["q_type"] = dnslib.QTYPE[response.questions[0].qtype]
        dnstap_d["r_code"] = dnslib.RCODE[response.header.rcode]
        dnstap_d["r_bytes"] = len(dm.response_message)
    
    # send json message to remote tcp
    if tcp_writer is not None:
        tcp_writer.write(json.dumps(dnstap_d).encode() + b"\n")
    
    # print json payload to stdout
    else:
        print(json.dumps(dnstap_d))
        
async def cb_onconnect(reader, writer):
    """callback when a connection is established"""
    logging.info("connect accepted")

    # prepare frame streams decoder
    fstrm_handler = fstrm.FstrmHandler()
    loop = asyncio.get_event_loop()
    dnstap_decoder = dnstap_pb2.Dnstap()
    
    args = parser.parse_args()
    if args.j is None:
        tcp_writer = None
    else:
        if ":" not in args.j:
            raise Exception("bad remote ip provided")
        dest_ip, dest_port = args.j.split(":", 1)
        
        _, tcp_writer = await asyncio.open_connection(dest_ip, int(dest_port), loop=loop)
                                                   
    running = True
    while running:
        try:
            while not fstrm_handler.process():
                # read received data
                data = await reader.read(fstrm_handler.pending_nb_bytes())
                if not data:
                    break
                    
                # append data to the buffer
                fstrm_handler.append(data=data)
            
            # frame is complete so let's decode it
            fs, payload  = fstrm_handler.decode()
            
            # handle the DATA frame
            if fs == fstrm.FSTRM_DATA_FRAME:
                loop.create_task(cb_ondnstap(dnstap_decoder, payload, tcp_writer))
                continue
            
            # handle the control frame READY
            if fs == fstrm.FSTRM_CONTROL_READY:
                logging.info("<< control ready")
                ctrl_accept = fstrm_handler.encode(fs=fstrm.FSTRM_CONTROL_ACCEPT)
                
                # respond with accept only if the content type is dnstap
                writer.write(ctrl_accept)
                await writer.drain()
                logging.info(">> control accept")
            
            # handle the control frame READY
            if fs == fstrm.FSTRM_CONTROL_START:    
                logging.info("<< control start")
            
            # handle the control frame STOP
            if fs == fstrm.FSTRM_CONTROL_STOP:
                logging.info("<< control stop")
                running = False
            
        except Exception as e:
            running = False
            logging.error("something happened: %s" % e)
    
    # close the remote tcp conn
    if tcp_writer is not None:
        tcp_writer.close()
        
    logging.info("connection done")
    
def start_receiver():
    """start dnstap receiver"""
    try:
        args = parser.parse_args()
    except:
        sys.exit(1)
    
    logging.info("Start dnstap receiver...")

    # asynchronous unix socket
    socket_server = asyncio.start_unix_server(cb_onconnect, path=args.u)

    # run until complete
    loop = asyncio.get_event_loop()
    
    # run until complete
    loop.run_until_complete(socket_server)
    
    # run event loop
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass