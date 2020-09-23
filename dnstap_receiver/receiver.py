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


async def cb_ondnstap(dnstap_decoder, payload, tcp_writer, cfg, output_fmt):
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
    if output_fmt == "text":
        msg = "%s %s %s %s %s %s %s %s %sb %s %s" % (tap["timestamp"], tap["identity"], 
                                                   tap["message"], tap["code"],
                                                   tap["source-ip"], tap["source-port"],
                                                   tap["protocol"], tap["transport"],
                                                   tap["length"],
                                                   tap["query-name"], tap["query-type"])
        
    if output_fmt == "json":
        msg = json.dumps(tap)
        
    if output_fmt == "yaml":
        msg = yaml.dump(tap)

    # final step, stdout or remote destination ? 
    # send json message to remote tcp
    if tcp_writer is not None:
        tcp_writer.write(msg.encode() + b"\n")
    else:
        print(msg)

async def cb_onconnect(reader, writer, cfg):
    """callback when a connection is established"""
    # get peer name
    peername = writer.get_extra_info('peername')
    if not len(peername):
        peername = "(unix-socket)"
    logging.debug(f"{peername} - new connection")

    # prepare frame streams decoder
    fstrm_handler = fstrm.FstrmHandler()
    loop = asyncio.get_event_loop()
    dnstap_decoder = dnstap_pb2.Dnstap()
    
    # remote connection to enable ?
    tcp_writer = None
    output_fmt = cfg["output"]["stdout"]["format"]
    remote_tcp_addr = cfg["output"]["tcp-socket"]["remote-address"]
    remote_tcp_port = cfg["output"]["tcp-socket"]["remote-port"]
    
    # output to remote address enabled ?
    if remote_tcp_addr is not None and remote_tcp_port is not None :
        _, tcp_writer = await asyncio.open_connection(remote_tcp_addr, remote_tcp_port,
                                                      loop=loop)
        output_fmt = cfg["output"]["tcp-socket"]["format"]
        
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
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, 
                                                 tcp_writer, cfg, output_fmt))
                    
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

    # set default config
    cfg = {  
             "verbose": args.v, 
             "input": {
                         "tcp-socket": {
                                         "local-address": args.l,
                                         "local-port": args.p,
                                         "tls-support": False,
                                         "tls-server-cert": None,
                                         "tls-server-key": None,
                                       },
                         "unix-socket": {
                                          "path": args.u
                                        }
                      },
             "filter": {
                         "qname-regex": None,
                         "dnstap-identities": None
                       }, 
             "output": {
                         "stdout": {
                                     "format": "text"
                                   },
                         "tcp-socket": {
                                         "format": "text",
                                         "remote-address": None,
                                         "remote-port": None
                                       }
                       }
          }
    
    # overwrite config with external file ?    
    if args.c:
        try:
            with open(args.c) as file:
                cfg.update( yaml.safe_load(file) )
        except FileNotFoundError:
            print("error: config file not found")
            sys.exit(1)

    # init logging
    level = logging.INFO
    if cfg["verbose"]:
        level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', level=level)

    logging.debug("Start receiver...")
    loop = asyncio.get_event_loop()

    # asynchronous unix socket
    if cfg["input"]["unix-socket"]["path"] is not None:
        logging.debug("Listening on %s" % args.u)
        socket_server = asyncio.start_unix_server(lambda r, w: cb_onconnect(r, w, cfg),
                                                  path=cfg["input"]["unix-socket"]["path"],
                                                  loop=loop)
    # default mode: asynchronous tcp socket
    else:
        ssl_context = None
        if cfg["input"]["tcp-socket"]["tls-support"]:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cfg["input"]["tcp-socket"]["tls-server-cert"], 
                                        keyfile=cfg["input"]["tcp-socket"]["tls-server-key"])
        
        logging.debug("Listening on %s:%s" % (cfg["input"]["tcp-socket"]["local-address"],
                                              cfg["input"]["tcp-socket"]["local-port"])), 
        socket_server = asyncio.start_server(lambda r, w: cb_onconnect(r, w, cfg),
                                             cfg["input"]["tcp-socket"]["local-address"],
                                             cfg["input"]["tcp-socket"]["local-port"],
                                             ssl=ssl_context,
                                             loop=loop)

    # run until complete
    loop.run_until_complete(socket_server)
    
    # run event loop
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
