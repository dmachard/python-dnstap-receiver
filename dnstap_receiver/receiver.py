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

# python3 -m pip dnspython
import dns.rcode
import dns.rdatatype
import dns.message

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

# import framestreams and dnstap protobuf decoder
from dnstap_receiver.codec import dnstap_pb2 
from dnstap_receiver.codec import fstrm 

# import all outputs
from dnstap_receiver.outputs import output_stdout
from dnstap_receiver.outputs import output_file
from dnstap_receiver.outputs import output_syslog
from dnstap_receiver.outputs import output_tcp
from dnstap_receiver.outputs import output_metrics

from dnstap_receiver import api_server
from dnstap_receiver import statistics

class UnknownValue:
    name = "-"

DNSTAP_TYPE = dnstap_pb2._MESSAGE_TYPE.values_by_number
DNSTAP_FAMILY = dnstap_pb2._SOCKETFAMILY.values_by_number
DNSTAP_PROTO = dnstap_pb2._SOCKETPROTOCOL.values_by_number  

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

import dns.exception
import dns.opcode
import dns.flags

# waiting fix with dnspython 2.1
# will be removed in the future
class _WireReader(dns.message._WireReader):
    def read(self):
        """issue fixed - waiting fix with dnspython 2.1"""
        if self.parser.remaining() < 12:
            raise dns.message.ShortHeader
        (id, flags, qcount, ancount, aucount, adcount) = \
            self.parser.get_struct('!HHHHHH')
        factory = dns.message._message_factory_from_opcode(dns.opcode.from_flags(flags))
        self.message = factory(id=id)
        self.message.flags = flags
        self.initialize_message(self.message)
        self.one_rr_per_rrset = \
            self.message._get_one_rr_per_rrset(self.one_rr_per_rrset)
        self._get_question(dns.message.MessageSection.QUESTION, qcount)
        
        return self.message

# waiting fix with dnspython 2.1
# will be removed in the future
def from_wire(wire, question_only=True):
    """decode wire message - waiting fix with dnspython 2.1"""
    raise_on_truncation=False
    def initialize_message(message):
        message.request_mac = b''
        message.xfr = False
        message.origin = None
        message.tsig_ctx = None

    reader = _WireReader(wire, initialize_message, question_only=question_only,
                 one_rr_per_rrset=False, ignore_trailing=False,
                 keyring=None, multi=False)
    try:
        m = reader.read()
    except dns.exception.FormError:
        if reader.message and (reader.message.flags & dns.flags.TC) and \
           raise_on_truncation:
            raise dns.message.Truncated(message=reader.message)
        else:
            raise
    # Reading a truncated message might not have any errors, so we
    # have to do this check here too.
    if m.flags & dns.flags.TC and raise_on_truncation:
        raise dns.message.Truncated(message=m)

    return m
    
async def cb_ondnstap(dnstap_decoder, payload, cfg, queue, stats):
    """on dnstap"""
    # decode binary payload
    dnstap_decoder.ParseFromString(payload)
    dm = dnstap_decoder.message
    
    # filtering by dnstap identity ?
    tap_ident = dnstap_decoder.identity.decode()
    if not len(tap_ident):
        tap_ident = UnknownValue.name
    if cfg["filter"]["dnstap-identities"] is not None:
        if re.match(cfg["filter"]["dnstap-identities"], dnstap_decoder.identity.decode()) is None:
            del dm
            return
            
    tap = { "identity": tap_ident, "query-name": UnknownValue.name, 
            "query-type": UnknownValue.name, "source-ip": UnknownValue.name}
    
    # decode type message
    tap["message"] = DNSTAP_TYPE.get(dm.type, UnknownValue).name
    tap["family"] = DNSTAP_FAMILY.get(dm.socket_family, UnknownValue).name
    tap["protocol"] = DNSTAP_PROTO.get(dm.socket_protocol, UnknownValue).name

    # decode query address
    if len(dm.query_address) and dm.socket_family == 1:
        tap["source-ip"] = socket.inet_ntoa(dm.query_address)
    if len(dm.query_address) and dm.socket_family == 2:
        tap["source-ip"] = socket.inet_ntop(socket.AF_INET6, dm.query_address)
    tap["source-port"] = dm.query_port
    if tap["source-port"] == 0:
        tap["source-port"] = UnknownValue.name
        
    # handle query message
    if (dm.type % 2 ) == 1 :
        dnstap_parsed = from_wire(dm.query_message,
                                  question_only=True)
        tap["length"] = len(dm.query_message)
        d1 = dm.query_time_sec +  (round(dm.query_time_nsec ) / 1000000000)
        tap["timestamp"] = datetime.fromtimestamp(d1, tz=timezone.utc).isoformat()
        tap["type"] = "query"
        
    # handle response message
    if (dm.type % 2 ) == 0 :
        dnstap_parsed = from_wire(dm.response_message,
                                  question_only=True)
        tap["length"] = len(dm.response_message)
        d2 = dm.response_time_sec + (round(dm.response_time_nsec ) / 1000000000) 
        tap["timestamp"] = datetime.fromtimestamp(d2, tz=timezone.utc).isoformat()
        tap["type"] = "response"
        
    # common params
    if len(dnstap_parsed.question):
        tap["qname"] = dnstap_parsed.question[0].name.to_text()
        tap["rrtype"] = dns.rdatatype.to_text(dnstap_parsed.question[0].rdtype)
    tap["rcode"] = dns.rcode.to_text(dnstap_parsed.rcode())
    
    # filtering by qname ?
    if cfg["filter"]["qname-regex"] is not None:
        if re.match(cfg["filter"]["qname-regex"], tap["query-name"]) is None:
            del dm; del tap;
            return

    # update metrics 
    stats.record(tap=tap)
        
    # append the dnstap message to the queue
    queue.put_nowait(tap)

async def cb_onconnect(reader, writer, cfg, queue, stats):
    """callback when a connection is established"""
    # get peer name
    peername = writer.get_extra_info('peername')
    if not len(peername):
        peername = "(unix-socket)"
    clogger.debug(f"Input handler: new connection from {peername}")

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
            clogger.debug("Input handler: checking acl refused")
            return
        
        clogger.debug("Input handler: checking acl allowed")
        
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
                    loop.create_task(cb_ondnstap(dnstap_decoder, payload, cfg, queue, stats))
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_READY:
                    clogger.debug(f"Input handler: control ready received from {peername}")
                    ctrl_accept = fstrm_handler.encode(fs=fstrm.FSTRM_CONTROL_ACCEPT)
                    # respond with accept only if the content type is dnstap
                    writer.write(ctrl_accept)
                    await writer.drain()
                    clogger.debug(f"Input handler: sending control accept to {peername}")
                    
                # handle the control frame READY
                if fs == fstrm.FSTRM_CONTROL_START:
                    clogger.debug(f"Input handler: control start received from {peername}")
   
                # handle the control frame STOP
                if fs == fstrm.FSTRM_CONTROL_STOP:
                    clogger.debug(f"Input handler: control stop received from {peername}")
                    fstrm_handler.reset()           
    except asyncio.CancelledError:
        clogger.debug(f'Input handler: {peername} - closing connection.')
        writer.close()
        await writer.wait_closed()
    except asyncio.IncompleteReadError:
        clogger.debug(f'Input handler: {peername} - disconnected')
    finally:
        clogger.debug(f'Input handler: {peername} - closed')

def merge_cfg(u, o):
    """merge config"""
    for k,v in u.items():
        if k in o:
            if isinstance(v, dict):
                merge_cfg(u=v,o=o[k])
            else:
                o[k] = v
   
def setup_config(args):
    """load default config and update it with arguments if provided"""
    # set default config
    try:
        cfg =  yaml.safe_load(pkgutil.get_data(__package__, 'dnstap.conf')) 
    except FileNotFoundError:
        print("default config file not found")
        sys.exit(1)
    except yaml.parser.ParserError:
        print("invalid default yaml config file")
        sys.exit(1)
    
    # update default config with command line arguments
    cfg["trace"]["verbose"] = args.v
    cfg["input"]["unix-socket"]["path"] = args.u
    cfg["input"]["tcp-socket"]["local-address"] = args.l
    cfg["input"]["tcp-socket"]["local-port"] = args.p

    # overwrite config with external file ?    
    if args.c:
        try:
            with open(args.c) as file:
                merge_cfg(u=yaml.safe_load(file),o=cfg)
        except FileNotFoundError:
            print("external config file not found")
            sys.exit(1)
        except yaml.parser.ParserError:
            print("external invalid yaml config file")
            sys.exit(1)
    return cfg
    
def setup_logger(cfg):
    """setup main logger"""

    loglevel = logging.DEBUG if cfg["verbose"] else logging.INFO
    logfmt = '%(asctime)s %(levelname)s %(message)s'
    
    clogger.setLevel(loglevel)
    clogger.propagate = False
    
    if cfg["file"] is None:
        lh = logging.StreamHandler(stream=sys.stdout )
    else:
        lh = logging.FileHandler(cfg["file"])
    lh.setLevel(loglevel)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    clogger.addHandler(lh)
    
def setup_outputs(cfg, queue, stats, loop):
    """setup outputs"""
    conf = cfg["output"]

    if conf["syslog"]["enable"]:
        if not output_syslog.checking_conf(cfg=conf["syslog"]): return
        loop.create_task(output_syslog.handle(conf["syslog"], queue, stats))    

    if conf["tcp-socket"]["enable"]:
        if not output_tcp.checking_conf(cfg=conf["tcp-socket"]): return
        loop.create_task(output_tcp.handle(conf["tcp-socket"], queue, stats))
                                               
    if conf["file"]["enable"]:
        if not output_file.checking_conf(cfg=conf["file"]): return
        loop.create_task(output_file.handle(conf["file"], queue, stats))
                                              
    if conf["stdout"]["enable"]:
        if not output_stdout.checking_conf(cfg=conf["stdout"]): return
        loop.create_task(output_stdout.handle(conf["stdout"], queue, stats))

    if conf["metrics"]["enable"]:
        if not output_metrics.checking_conf(cfg=conf["metrics"]): return
        loop.create_task(output_metrics.handle(conf["metrics"], queue, stats))

def setup_inputs(args, cfg, queue, stats, loop):
    """setup inputs"""
    # asynchronous unix socket
    if cfg["input"]["unix-socket"]["path"] is not None:
        clogger.debug("Input handler: unix socket")
        clogger.debug("Input handler: listening on %s" % args.u)
        socket_server = asyncio.start_unix_server(lambda r, w: cb_onconnect(r, w, cfg, queue, stats),
                                                  path=cfg["input"]["unix-socket"]["path"],
                                                  loop=loop)
    # default mode: asynchronous tcp socket
    else:
        clogger.debug("Input handler: tcp socket")
        
        ssl_context = None
        if cfg["input"]["tcp-socket"]["tls-support"]:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cfg["input"]["tcp-socket"]["tls-server-cert"], 
                                        keyfile=cfg["input"]["tcp-socket"]["tls-server-key"])
            clogger.debug("Input handler - tls support enabled")
        clogger.debug("Input handler: listening on %s:%s" % (cfg["input"]["tcp-socket"]["local-address"],
                                              cfg["input"]["tcp-socket"]["local-port"])), 
        socket_server = asyncio.start_server(lambda r, w: cb_onconnect(r, w, cfg, queue, stats),
                                             cfg["input"]["tcp-socket"]["local-address"],
                                             cfg["input"]["tcp-socket"]["local-port"],
                                             ssl=ssl_context,
                                             loop=loop)
                                             
    # run until complete
    loop.run_until_complete(socket_server)
    
def setup_api(cfg, queue, stats, loop):
    """setup web api"""
    if cfg["web-api"]["enable"]:
        api_svr = api_server.create_server(loop, cfg=cfg["web-api"], 
                                           stats=stats, cfg_stats=cfg["statistics"])
        loop.run_until_complete(api_svr)
    
def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # init config
    cfg = setup_config(args=args)
            
    # init logging
    setup_logger(cfg=cfg["trace"])

    # add debug message if external config is used
    if args.c: clogger.debug("External config file loaded")
    
    # start receiver and get event loop
    clogger.debug("Start receiver...")
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()
    stats = statistics.Statistics()
    loop.create_task(statistics.watcher(stats))
    
    # prepare outputs
    setup_outputs(cfg, queue, stats, loop)
    
    # prepare inputs
    setup_inputs(args, cfg, queue, stats, loop)

    # start the rest api
    setup_api(cfg, queue, stats, loop)

    # run event loop 
    try:
       loop.run_forever()
    except KeyboardInterrupt:
        pass
