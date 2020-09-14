import argparse
import logging
import asyncio
import socket
import json
import yaml
import sys

from datetime import datetime

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

parser = argparse.ArgumentParser()
parser.add_argument("-l", help="receive dnstap payloads from remote tcp sender, listen on ip:port")
parser.add_argument("-u", help="read dnstap payloads using framestreams from unix socket")
parser.add_argument('-v', action='store_true', help="verbose mode")
parser.add_argument("-y", help="write YAML-formatted output", action='store_true')
parser.add_argument("-j", help="write JSON-formatted output", action='store_true')                       
parser.add_argument("-d", help="send dnstap message to remote tcp/ip address")   

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
DNSTAP_FAMILY = {1: 'IP4', 2: 'IP6'}
DNSTAP_PROTO = {1: 'UDP', 2: 'TCP'}    

DATETIME_FORMAT ='%Y-%m-%d %H:%M:%S.%f'

FMT_SHORT = "SHORT"
FMT_JSON = "JSON"
FMT_YAML = "YAML"

try:
    args = parser.parse_args()
except:
    sys.exit(1)

# init logging
level = logging.INFO
if args.v:
    level = logging.DEBUG
logging.basicConfig(format='%(asctime)s %(message)s', level=level)


async def cb_ondnstap(dnstap_decoder, payload, tcp_writer, output_fmt):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.parse_from_bytes(payload)
    dm = dnstap_decoder.message
    
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
        query_time_milli = (round(dm.query_time_nsec / 1000000) / 1000)
        d1 = dm.query_time_sec +  query_time_milli
        tap["timestamp"] = datetime.fromtimestamp(d1).strftime(DATETIME_FORMAT)[:-3]
        
    # handle response message
    if (dm.type.value % 2 ) == 0 :
        dnstap_parsed = dnslib.DNSRecord.parse(dm.response_message)
        tap["length"] = len(dm.response_message)

        reply_time_milli = (round(dm.response_time_nsec / 1000000) / 1000) 
        d2 = dm.response_time_sec + reply_time_milli
        tap["timestamp"] = datetime.fromtimestamp(d2).strftime(DATETIME_FORMAT)[:-3]

    # common params
    if len(dnstap_parsed.questions):
        tap["query-name"] = str(dnstap_parsed.questions[0].get_qname())
        tap["query-type"] = dnslib.QTYPE[dnstap_parsed.questions[0].qtype]
    tap["code"] = dnslib.RCODE[dnstap_parsed.header.rcode]
    
    
    # reformat dnstap message
    if output_fmt == FMT_SHORT:
        msg = "%s %s %s %s %s %s %s %s %sb %s %s" % (tap["timestamp"], tap["identity"], 
                                               tap["message"], tap["code"],
                                               tap["source-ip"], tap["source-port"],
                                               tap["protocol"], tap["transport"], tap["length"],
                                               tap["query-name"], tap["query-type"])
        
    if output_fmt == FMT_JSON:
        msg = json.dumps(tap)
        
    if output_fmt == FMT_YAML:
        msg = yaml.dump(tap)

    # final step, stdout or remote destination ? send json message to remote tcp
    if tcp_writer is not None:
        tcp_writer.write(msg.encode() + b"\n")
    else:
        print(msg)

async def cb_onconnect(reader, writer):
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
    
    args = parser.parse_args()
    if args.d is None:
        tcp_writer = None
    else:
        if ":" not in args.d:
            raise Exception("bad remote ip provided")
        dest_ip, dest_port = args.d.split(":", 1)
        
        _, tcp_writer = await asyncio.open_connection(dest_ip, 
                                                      int(dest_port),
                                                      loop=loop)
    
    fmt = FMT_SHORT
    if args.y:
        fmt = FMT_YAML
    if args.j:
        fmt = FMT_JSON

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
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, tcp_writer, fmt))
                    
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
        print(f'{peername} closing connection.')
        writer.close()
        await writer.wait_closed()
    except asyncio.IncompleteReadError:
        print(f'{peername} disconnected')
    finally:
        print(f'{peername} closed')

    # close the remote tcp conn
    if tcp_writer is not None:
        tcp_writer.close()

def start_receiver():
    """start dnstap receiver"""
    args = parser.parse_args()
    logging.debug("Start dnstap receiver...")

    loop = asyncio.get_event_loop()

    # asynchronous unix socket
    if args.u is not None:
        socket_server = asyncio.start_unix_server(cb_onconnect, path=args.u, loop=loop)
    elif args.l is not None:
        if ":" not in args.l:
            logging.error("malformed listen ip/port provided")
            sys.exit(1)
        listen_ip, listen_port = args.l.split(":", 1)
        socket_server = asyncio.start_server(cb_onconnect, listen_ip, listen_port, loop=loop)
    else:
        logging.error("no input provided")
        sys.exit(1)
        
    # run until complete
    loop.run_until_complete(socket_server)
    
    # run event loop
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass