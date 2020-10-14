import argparse
import logging
import asyncio
import socket
import yaml
import sys
import re
import ssl
import pkgutil
import ipaddress

from datetime import datetime, timezone

# python3 -m pip dnslib
import dnslib

# wget https://raw.githubusercontent.com/dnstap/dnstap.pb/master/dnstap.proto
# wget https://github.com/protocolbuffers/protobuf/releases/download/v3.13.0/protoc-3.13.0-linux-x86_64.zip
# python3 -m pip install protobuf
# bin/protoc --python_out=. dnstap.proto

from dnstap_receiver import dnstap_pb2 # more informations on dnstap http://dnstap.info/
from dnstap_receiver import fstrm  # framestreams decoder
from dnstap_receiver import output_stdout
from dnstap_receiver import output_syslog
from dnstap_receiver import output_tcp
from dnstap_receiver import output_metrics

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

async def cb_ondnstap(dnstap_decoder, payload, cfg, queue, metrics):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.ParseFromString(payload)
    dm = dnstap_decoder.message
    
    # filtering by dnstap identity ?
    tap_ident = dnstap_decoder.identity.decode()
    if not len(tap_ident):
        tap_ident = "-"
    if cfg["filter"]["dnstap-identities"] is not None:
        if re.match(cfg["filter"]["dnstap-identities"], dnstap_decoder.identity.decode()) is None:
            del dm
            return
            
    tap = { "identity": tap_ident,
            "query-name": "-", 
            "query-type": "-", 
            "source-ip": "-"}
    
    # decode type message
    tap["message"] = DNSTAP_TYPE.get(dm.type, "-")
    tap["protocol"] = DNSTAP_FAMILY.get(dm.socket_family, "-")
    tap["transport"] = DNSTAP_PROTO.get(dm.socket_protocol, "-")

    # decode query address
    if len(dm.query_address) and dm.socket_family == 1:
        tap["source-ip"] = socket.inet_ntoa(dm.query_address)
    if len(dm.query_address) and dm.socket_family == 2:
        tap["source-ip"] = socket.inet_ntop(socket.AF_INET6, dm.query_address)
    tap["source-port"] = dm.query_port
    if tap["source-port"] == 0:
        tap["source-port"] = "-"
        
    # handle query message
    if (dm.type % 2 ) == 1 :
        dnstap_parsed = dnslib.DNSRecord.parse(dm.query_message)
        tap["length"] = len(dm.query_message)
        d1 = dm.query_time_sec +  (round(dm.query_time_nsec ) / 1000000000)
        tap["timestamp"] = datetime.fromtimestamp(d1, tz=timezone.utc).isoformat()
        
    # handle response message
    if (dm.type % 2 ) == 0 :
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

    # update metrics 
    metrics.record_dnstap(dnstap=tap)
        
    # finally add decoded tap message in queue for outputs
    # except for metrics
    if cfg["output"]["metrics"]["enable"]:
        return
        
    queue.put_nowait(tap)

async def cb_onconnect(reader, writer, cfg, queue, metrics):
    """callback when a connection is established"""
    # get peer name
    peername = writer.get_extra_info('peername')
    if not len(peername):
        peername = "(unix-socket)"
    logging.debug(f"Input handler: new connection from {peername}")

    # access control list check
    if len(writer.get_extra_info('peername')):
        acls_network = []
        for a in cfg["input"]["tcp-socket"]["access-control-list"]:
            acls_network.append(ipaddress.ip_network(a))
            
        acl_allow = False
        for acl in acls_network:
            if ipaddress.ip_address(peername[0]) in acl:
                acl_allow = True
        
        if not acl_allow:
            writer.close()
            logging.debug("Input handler: checking acl refused")
            return
        
        logging.debug("Input handler: checking acl allowed")
        
    # prepare frame streams decoder
    fstrm_handler = fstrm.FstrmHandler()
    loop = asyncio.get_event_loop()
    dnstap_decoder = dnstap_pb2.Dnstap()

    try: 
        # syntax only works with python 3.8
        # while data := await reader.read(fstrm_handler.pending_nb_bytes()) 
        running = True
        while running:
            # read bytes
            data = await reader.read(fstrm_handler.pending_nb_bytes()) 
            if not len(data):
                running = False
                break
                
            # append data to the buffer
            fstrm_handler.append(data=data)
            
            # process the buffer, check if we have received a complete frame ?
            if fstrm_handler.process():
                # Ok, the frame is complete so let's decode it
                fs, payload  = fstrm_handler.decode()

                # handle the DATA frame
                if fs == fstrm.FSTRM_DATA_FRAME:
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, cfg, queue, metrics))
                    
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

class Metrics:
    def prepare(self):
        """prepare stats"""
        self.stats = {"total-queries": 0}
        self.queries = {}
        self.rtype = {}
        self.rcode = {}
        self.clients = {}
        self.nxdomains = {}
        self.proto = {}
        self.family = {}
    
    def reset(self):
        """reset statistics"""
        del self.stats
        del self.queries
        del self.rtype
        del self.rcode
        del self.clients
        del self.nxdomains 
        del self.proto
        del self.family
        
        self.prepare()
        
    def record_dnstap(self, dnstap):
        """add dnstap message"""
        self.stats["total-queries"] += 1

        if dnstap["transport"] not in self.proto:
            self.proto[dnstap["transport"]] = 1
        else:
            self.proto[dnstap["transport"]] += 1
            
        if dnstap["protocol"] not in self.family:
            self.family[dnstap["protocol"]] = 1
        else:
            self.family[dnstap["protocol"]] += 1
            
        if dnstap["query-name"] not in self.queries:
            self.queries[dnstap["query-name"]] = 1
        else:
            self.queries[dnstap["query-name"]] += 1
        
        if dnstap["source-ip"] not in self.clients:
            self.clients[dnstap["source-ip"]] = 1
        else:
            self.clients[dnstap["source-ip"]] += 1
         
        if dnstap["query-type"] not in self.rtype:
            self.rtype[dnstap["query-type"]] = 1
        else:
            self.rtype[dnstap["query-type"]] += 1
        
        if dnstap["code"] not in self.rcode:
            self.rcode[dnstap["code"]] = 1
        else:
            self.rcode[dnstap["code"]] += 1
            
def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # set default config
    try:
        cfg =  yaml.safe_load(pkgutil.get_data(__package__, 'dnstap.conf')) 
    except FileNotFoundError:
        logging.error("default config file not found")
        sys.exit(1)
    except yaml.parser.ParserError:
        logging.error("invalid default yaml config file")
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
            logging.error("external config file not found")
            sys.exit(1)
        except yaml.parser.ParserError:
            logging.error("external invalid yaml config file")
            sys.exit(1)
            
    # init logging
    level = logging.INFO
    if cfg["verbose"]:
        level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', stream=sys.stdout, level=level)

    # start receiver and get event loop
    logging.debug("Start receiver...")
    loop = asyncio.get_event_loop()

    # prepare output
    queue = asyncio.Queue()
    metrics = Metrics()
    metrics.prepare()
    
    if cfg["output"]["syslog"]["enable"]:
        logging.debug("Output handler: syslog")
        loop.create_task(output_syslog.handle(cfg["output"]["syslog"], 
                                              queue))
        
    if cfg["output"]["tcp-socket"]["enable"]:
        logging.debug("Output handler: tcp")
        loop.create_task(output_tcp.handle(cfg["output"]["tcp-socket"],
                                           queue))

    if cfg["output"]["stdout"]["enable"]:
        logging.debug("Output handler: stdout")
        loop.create_task(output_stdout.handle(cfg["output"]["stdout"],
                                              queue))

    
    if cfg["output"]["metrics"]["enable"]:
        logging.debug("Output handler: metrics")
        loop.create_task(output_metrics.handle(cfg["output"]["metrics"],
                                              metrics))
                                              

    # asynchronous unix socket
    if cfg["input"]["unix-socket"]["path"] is not None:
        logging.debug("Input handler: unix socket")
        logging.debug("Input handler: listening on %s" % args.u)
        socket_server = asyncio.start_unix_server(lambda r, w: cb_onconnect(r, w, cfg, queue, metrics),
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
        socket_server = asyncio.start_server(lambda r, w: cb_onconnect(r, w, cfg, queue, metrics),
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
