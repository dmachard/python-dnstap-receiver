import argparse
import logging
import asyncio
import socket
import json
import yaml
import sys
import re
import ssl
import pkgutil

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

async def cb_ondnstap(dnstap_decoder, payload, cfg, queue):
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

    queue.put_nowait(tap)

async def cb_onconnect(reader, writer, cfg, queue):
    """callback when a connection is established"""
    # get peer name
    peername = writer.get_extra_info('peername')
    if not len(peername):
        peername = "(unix-socket)"
    logging.debug(f"Input handler: new connection from {peername}")

    # prepare frame streams decoder
    fstrm_handler = fstrm.FstrmHandler()
    loop = asyncio.get_event_loop()
    dnstap_decoder = dnstap_pb2.Dnstap()

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
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, cfg, queue))
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_READY:
                    logging.debug(f"Input handler: control ready received from {peername}")
                    ctrl_accept = fstrm_handler.encode(fs=fstrm.FSTRM_CONTROL_ACCEPT)
                    # respond with accept only if the content type is dnstap
                    writer.write(ctrl_accept)
                    await writer.drain()
                    logging.debug(f"Input handler: sending control accept to {peername}")
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_START:
                    logging.debug(f"Input handler: control start received from {peername}")
   
                # handle the control frame STOP
                if fs == fstrm.FSTRM_CONTROL_STOP:
                    logging.debug(f"Input handler: control stop received from {peername}")
                    fstrm_handler.reset()           
    except asyncio.CancelledError:
        logging.debug(f'Input handler: {peername} - closing connection.')
        writer.close()
        await writer.wait_closed()
    except asyncio.IncompleteReadError:
        logging.debug(f'Input handler: {peername} - disconnected')
    finally:
        logging.debug(f'Input handler: {peername} - closed')

async def plaintext_tcpclient(output_cfg, queue):
    host, port = output_cfg["remote-address"], output_cfg["remote-port"]
    logging.debug("Output handler: connection to %s:%s" % (host,port) )
    reader, tcp_writer = await asyncio.open_connection(host, port)
    logging.debug("Output handler: connected")
    
    # consume queue
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
            
        # add delimiter
        tcp_writer.write( b"%s%s" % (msg, output_cfg["delimiter"]) )
        
        # connection lost ? exit and try to reconnect 
        if tcp_writer.transport._conn_lost:
            break
        
        # done continue to next item
        queue.task_done()
        
    # something 
    logging.error("Output handler: connection lost")
    
async def syslog_tcpclient(output_cfg, queue):
    host, port = output_cfg["remote-address"], output_cfg["remote-port"]
    logging.debug("Output handler: connection to %s:%s" % (host,port) )
    reader, tcp_writer = await asyncio.open_connection(host, port)
    logging.debug("Output handler: connected")
    
    # consume queue
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
            
        # add count octets
        s_msg = "%s" % len(msg)
        tcp_writer.write( b"%s %s" % (s_msg.encode(), msg) )
        
        # connection lost ? exit and try to reconnect 
        if tcp_writer.transport._conn_lost:
            break
        
        # done continue to next item
        queue.task_done()
        
    # something 
    logging.error("Output handler: connection lost")

async def handle_output_tcp(output_cfg, queue):
    """tcp reconnect"""
    server_address = (output_cfg["remote-address"], output_cfg["remote-port"])
    loop = asyncio.get_event_loop()

    logging.debug("Output handler: TCP enabled")
    while True:
        try:
            await plaintext_tcpclient(output_cfg, queue)
        except ConnectionRefusedError:
            logging.error('Output handler: connection to tcp server failed!')
        except asyncio.TimeoutError:
            logging.error('Output handler: connection to tcp server timed out!')
        else:
            logging.error('Output handler: connection to tcp is closed.')
            
        logging.debug("'Output handler: retry to connect every 5s")
        await asyncio.sleep(output_cfg["retry"])
     
async def handle_output_syslog(output_cfg, queue):
    """tcp reconnect"""
    server_address = (output_cfg["remote-address"], output_cfg["remote-port"])
    loop = asyncio.get_event_loop()
    
    # syslog tcp
    if output_cfg["transport"] == "tcp":
        logging.debug("Output handler: syslog TCP enabled")
        while True:
            try:
                await syslog_tcpclient(output_cfg, queue)
            except ConnectionRefusedError:
                logging.error('Output handler: connection to syslog server failed!')
            except asyncio.TimeoutError:
                logging.error('Output handler: connection to syslog server timed out!')
            else:
                logging.error('Output handler: connection to server is closed.')
                
            logging.debug("'Output handler: retry to connect every 5s")
            await asyncio.sleep(output_cfg["retry"])
    
    # syslog udp
    else:
        logging.debug("Output handler: syslog UDP enabled with %s" % str(server_address) )
        transport, _  = await loop.create_datagram_endpoint(asyncio.DatagramProtocol,
                                                            remote_addr=server_address)

        # consume the queue
        while True:
            # read item from queue
            tapmsg = await queue.get()
            
            # convert dnstap message
            msg = convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
            # send msg
            transport.sendto( msg )
            
            # all done
            queue.task_done()

async def handle_output_stdout(output_cfg, queue):
    """stdout output handler"""
    
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        print(msg.decode())
        
        # all done
        queue.task_done()

def convert_dnstap(fmt, tapmsg):
    """convert dnstap message"""
    if fmt == "text":
        msg = "%s %s %s %s %s %s %s %s %sb %s %s" % (tapmsg["timestamp"], tapmsg["identity"],  
                                                     tapmsg["message"], tapmsg["code"],
                                                     tapmsg["source-ip"], tapmsg["source-port"],
                                                     tapmsg["protocol"], tapmsg["transport"],
                                                     tapmsg["length"],
                                                     tapmsg["query-name"], tapmsg["query-type"])  
    elif fmt == "json":
        msg = json.dumps(tapmsg)
        
    elif fmt == "yaml":
        msg = yaml.dump(tapmsg)
    else:
        raise Exception("invalid output format")
    return msg.encode()
    
def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # set default config
    try:
        cfg =  yaml.safe_load(pkgutil.get_data(__package__, 'dnstap.conf')) 
    except FileNotFoundError:
        print("error: default config file not found")
        sys.exit(1)
    except yaml.parser.ParserError:
        print("error: invalid default yaml config file")
        sys.exit(1)
    
    # update default config with command line arguments
    cfg["verbose"] = args.v
    cfg["input"]["unix-socket"]["path"] = args.u
    cfg["input"]["tcp-socket"]["local-address"] = args.l
    cfg["input"]["tcp-socket"]["local-port"] = args.p
    
    # overwrite config with external file ?    
    if args.c:
        try:
            with open(args.c) as file:
                cfg.update( yaml.safe_load(file) )
        except FileNotFoundError:
            print("error: config file not found")
            sys.exit(1)
        except yaml.parser.ParserError:
            print("error: invalid yaml config file")
            sys.exit(1)
            
    # init logging
    level = logging.INFO
    if cfg["verbose"]:
        level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', level=level)

    # start receiver and get event loop
    logging.debug("Start receiver...")
    loop = asyncio.get_event_loop()

    # prepare output
    queue = asyncio.Queue()
    
    if cfg["output"]["syslog"]["enable"]:
        logging.debug("Output handler: syslog")
        loop.create_task(handle_output_syslog(cfg["output"]["syslog"], queue))
        
    elif cfg["output"]["tcp-socket"]["enable"]:
        logging.debug("Output handler: tcp")
        loop.create_task(handle_output_tcp(cfg["output"]["tcp-socket"], queue))

    else:
        logging.debug("Output handler: stdout")
        loop.create_task(handle_output_stdout(cfg["output"]["stdout"], queue))

    
    # prepare inputs
    
    # asynchronous unix socket
    if cfg["input"]["unix-socket"]["path"] is not None:
        logging.debug("Input handler: unix socket")
        logging.debug("Input handler: listening on %s" % args.u)
        socket_server = asyncio.start_unix_server(lambda r, w: cb_onconnect(r, w, cfg, queue),
                                                  path=cfg["input"]["unix-socket"]["path"],
                                                  loop=loop)
    # default mode: asynchronous tcp socket
    else:
        logging.debug("Input handler: tcp socket")
        
        ssl_context = None
        if cfg["input"]["tcp-socket"]["tls-support"]:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cfg["input"]["tcp-socket"]["tls-server-cert"], 
                                        keyfile=cfg["input"]["tcp-socket"]["tls-server-key"])
            logging.debug("Input handler - tls support enabled")
        logging.debug("Input handler: listening on %s:%s" % (cfg["input"]["tcp-socket"]["local-address"],
                                              cfg["input"]["tcp-socket"]["local-port"])), 
        socket_server = asyncio.start_server(lambda r, w: cb_onconnect(r, w, cfg, queue),
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
