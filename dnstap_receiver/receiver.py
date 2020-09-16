import argparse
import logging
import asyncio
import socket
import json
import yaml
import sys
import re
import ssl

from datetime import datetime, timezone

# python3 -m pip dnslib
import dnslib

# wget https://raw.githubusercontent.com/dnstap/dnstap.pb/master/dnstap.proto
# wget https://github.com/protocolbuffers/protobuf/releases/download/v3.13.0/protoc-3.13.0-linux-x86_64.zip
# python3 -m pip install protobuf
# bin/protoc --python_out=. dnstap.proto

# more informations on dnstap http://dnstap.info/
from dnstap_receiver import dnstap as dnstap_pb2

# framestreams decoder
from dnstap_receiver import fstrm

DNSTAP_TYPE = { 1: 'AUTH_QUERY', 2: 'AUTH_RESPONSE',
                3: 'RESOLVER_QUERY', 4: 'RESOLVER_RESPONSE',
                5: 'CLIENT_QUERY', 6: 'CLIENT_RESPONSE',
                7: 'FORWARDER_QUERY', 8: 'FORWARDER_RESPONSE',
                9: 'STUB_QUERY', 10: 'STUB_RESPONSE',
                11: 'TOOL_QUERY', 2: 'TOOL_RESPONSE' }
DNSTAP_FAMILY = {1: 'IP4', 2: 'IP6'}
DNSTAP_PROTO = {1: 'UDP', 2: 'TCP'}    

DATETIME_FORMAT ='%Y-%m-%d %H:%M:%S.%f'

# command line arguments definition
parser = argparse.ArgumentParser()
parser.add_argument("-l", 
                    help="IP of the dnsptap server to receive dnstap payloads (default: %(default)r)",
                    default="0.0.0.0")
parser.add_argument("-p", type=int,
                    help="Port the dnstap receiver is listening on (default: %(default)r)",
                    default=6000)               
parser.add_argument("-u", help="read dnstap payloads from unix socket")
parser.add_argument('-v', action='store_true', help="verbose mode")   
parser.add_argument("-c", help="external config file")   


async def cb_ondnstap(dnstap_decoder, payload, tcp_writer, cfg):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.parse_from_bytes(payload)
    dm = dnstap_decoder.message
    
    # filtering by dnstap identity ?
    if cfg["filter"]["dnstap-identities"] is not None:
        if re.match(cfg["filter"]["dnstap-identities"], dnstap_decoder.identity.decode()) is None:
            del dm
            return
            
    tap = { "identity": dnstap_decoder.identity.decode(),
            "query-name": "-", 
            "query-type": "-", 
            "source-ip": "-"}
    
    # decode type message
    tap["message"] = DNSTAP_TYPE.get(dm.type.value, "-")
    tap["protocol"] = DNSTAP_FAMILY.get(dm.socket_family.value, "-")
    tap["transport"] = DNSTAP_PROTO.get(dm.socket_protocol.value, "-")

    # decode query address
    if len(dm.query_address) and dm.socket_family.value == 1:
        tap["source-ip"] = socket.inet_ntoa(dm.query_address)
    if len(dm.query_address) and dm.socket_family.value == 2:
        tap["source-ip"] = socket.inet_ntop(socket.AF_INET6, dm.query_address)
    tap["source-port"] = dm.query_port
    if tap["source-port"] == 0:
        tap["source-port"] = "-"
        
    # handle query message
    if (dm.type.value % 2 ) == 1 :
        dnstap_parsed = dnslib.DNSRecord.parse(dm.query_message)
        tap["length"] = len(dm.query_message)
        d1 = dm.query_time_sec +  (round(dm.query_time_nsec ) / 1000000000)
        tap["timestamp"] = datetime.fromtimestamp(d1, tz=timezone.utc).isoformat()
        
    # handle response message
    if (dm.type.value % 2 ) == 0 :
        dnstap_parsed = dnslib.DNSRecord.parse(dm.response_message)
        tap["length"] = len(dm.response_message)
        d2 = dm.response_time_sec + (round(dm.response_time_nsec ) / 1000000000) 
        tap["timestamp"] = datetime.fromtimestamp(d2, tz=timezone.utc).isoformat()
        
    # common params
    if len(dnstap_parsed.questions):
        tap["query-name"] = str(dnstap_parsed.questions[0].get_qname())
        tap["query-type"] = dnslib.QTYPE[dnstap_parsed.questions[0].qtype]
    tap["code"] = dnslib.RCODE[dnstap_parsed.header.rcode]
    
    # filtering by qname ?
    if cfg["filter"]["qname-regex"] is not None:
        if re.match(cfg["filter"]["qname-regex"], tap["query-name"]) is None:
            del dm; del tap;
            return
    
    # reformat dnstap message
    if cfg["output-format"]["text"]:
        msg = "%s %s %s %s %s %s %s %s %sb %s %s" % (tap["timestamp"], tap["identity"], 
                                                   tap["message"], tap["code"],
                                                   tap["source-ip"], tap["source-port"],
                                                   tap["protocol"], tap["transport"],
                                                   tap["length"],
                                                   tap["query-name"], tap["query-type"])
        
    if cfg["output-format"]["json"]:
        msg = json.dumps(tap)
        
    if cfg["output-format"]["yaml"]:
        msg = yaml.dump(tap)

    # final step, stdout or remote destination ? 
    # send json message to remote tcp
    if tcp_writer is not None:
        tcp_writer.write(msg.encode() + b"\n")
    else:
        print(msg)

async def cb_onconnect(reader, writer, cfg):
    """callback when a connection is established"""
    sock = writer.get_extra_info('socket')
    if sock.family == socket.AF_UNIX:
        peername = "Unix socket"
    else:
        peername = "Remote %s:%s" % writer.get_extra_info('peername')
    logging.debug(f"{peername} - new connected")

    # prepare frame streams decoder
    fstrm_handler = fstrm.FstrmHandler()
    loop = asyncio.get_event_loop()
    dnstap_decoder = dnstap_pb2.Dnstap()
    
    # remote connection to enable ?
    tcp_writer = None
    if cfg["forward-to"]["enable"]:
        _, tcp_writer = await asyncio.open_connection(cfg["forward-to"]["remote-address"], 
                                                      cfg["forward-to"]["remote-port"],
                                                      loop=loop)

    try:
        while data := await reader.read(fstrm_handler.pending_nb_bytes()) :
            # append data to the buffer
            fstrm_handler.append(data=data)
            
            # process the buffer, check if we have received a complete frame ?
            if fstrm_handler.process():
                # Ok, the frame is complete so let's decode it
                fs, payload  = fstrm_handler.decode()

                # handle the DATA frame
                if fs == fstrm.FSTRM_DATA_FRAME:
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, tcp_writer, cfg))
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_READY:
                    logging.debug(f"{peername} - control ready received")
                    ctrl_accept = fstrm_handler.encode(fs=fstrm.FSTRM_CONTROL_ACCEPT)
                    # respond with accept only if the content type is dnstap
                    writer.write(ctrl_accept)
                    await writer.drain()
                    logging.debug(f"{peername} - sending control accept")
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_START:
                    logging.debug(f"{peername} - control start received")
   
                # handle the control frame STOP
                if fs == fstrm.FSTRM_CONTROL_STOP:
                    logging.debug(f"{peername} - control stop received")
                    fstrm_handler.reset()           
    except asyncio.CancelledError:
        logging.debug(f'{peername} - closing connection.')
        writer.close()
        await writer.wait_closed()
    except asyncio.IncompleteReadError:
        logging.debug(f'{peername} - disconnected')
    finally:
        logging.debug(f'{peername} - closed')

    # close the remote connection
    if tcp_writer is not None:
        tcp_writer.close()

def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # external config file provided ?
    if args.c:
        try:
            with open(args.c) as file:
                cfg = yaml.safe_load(file)
        except FileNotFoundError:
            print("error: config file not found")
            sys.exit(1)
    else:
        cfg = {"verbose": args.v, "input-mode": {}, 
               "output-format": {} , "forward-to": {}}
        cfg["input-mode"]["unix-socket"] = args.u
        cfg["input-mode"]["local-address"] =  args.l
        cfg["input-mode"]["local-port"] =  args.p
        cfg["input-mode"]["tls-support"] = False
        cfg["input-mode"]["tls-support"] = False
        cfg["filter"]["qname-regex"] = None
        cfg["filter"]["dnstap-identities"] = None
        cfg["output-format"]["yaml"] = False
        cfg["output-format"]["json"] = False
        cfg["output-format"]["text"] =True
        cfg["forward-to"]["enable"] =  False
        cfg["forward-to"]["remote-port"] = None
        cfg["forward-to"]["remote-port"] = None

    # init logging
    level = logging.INFO
    if cfg["verbose"]:
        level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', level=level)

    logging.debug("Start receiver...")
    loop = asyncio.get_event_loop()

    # asynchronous unix socket
    if cfg["input-mode"]["unix-socket"] is not None:
        logging.debug("Listening on %s" % args.u)
        socket_server = asyncio.start_unix_server(cb_onconnect,
                                                  path=cfg["input-mode"]["unix-socket"],
                                                  loop=loop)
    # asynchronous tcp socket
    else:
        ssl_context = None
        if cfg["input-mode"]["tls-support"]:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cfg["input-mode"]["tls-server-cert"], 
                                        keyfile=cfg["input-mode"]["tls-server-key"])
        
        logging.debug("Listening on %s:%s" % (cfg["input-mode"]["local-address"],
                                              cfg["input-mode"]["local-port"])), 
        socket_server = asyncio.start_server(lambda r, w: cb_onconnect(r, w, cfg),
                                             cfg["input-mode"]["local-address"],
                                             cfg["input-mode"]["local-port"],
                                             ssl=ssl_context,
                                             loop=loop)

    # run until complete
    loop.run_until_complete(socket_server)
    
    # run event loop
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass