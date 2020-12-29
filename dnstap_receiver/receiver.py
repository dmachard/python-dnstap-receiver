import argparse
import logging
import asyncio
import yaml
import sys

import ssl
import pkgutil
import pathlib
import cachetools

import geoip2.database

# create default logger for the dnstap receiver
clogger = logging.getLogger("dnstap_receiver.console")

# import all inputs
from dnstap_receiver.inputs import input_socket
from dnstap_receiver.inputs import input_sniffer

# import all outputs
from dnstap_receiver.outputs import output_stdout
from dnstap_receiver.outputs import output_file
from dnstap_receiver.outputs import output_syslog
from dnstap_receiver.outputs import output_tcp
from dnstap_receiver.outputs import output_metrics

from dnstap_receiver import api_server
from dnstap_receiver import statistics

DFLT_LISTEN_IP = "0.0.0.0"
DFLT_LISTEN_PORT = 6000

# command line arguments definition
parser = argparse.ArgumentParser()
parser.add_argument("-l", 
                    help="IP of the dnsptap server to receive dnstap payloads (default: %(default)r)",
                    default=DFLT_LISTEN_IP)
parser.add_argument("-p", type=int,
                    help="Port the dnstap receiver is listening on (default: %(default)r)",
                    default=DFLT_LISTEN_PORT)               
parser.add_argument("-u", help="read dnstap payloads from unix socket")
parser.add_argument('-v', action='store_true', help="verbose mode")   
parser.add_argument("-c", help="external config file")   

# get event loop
loop = asyncio.get_event_loop()

def merge_cfg(u, o):
    """merge config"""
    for k,v in u.items():
        if k in o:
            if isinstance(v, dict):
                merge_cfg(u=v,o=o[k])
            else:
                o[k] = v

def load_yaml(f):
    """load yaml file"""
    try:
        cfg =  yaml.safe_load(f) 
    except FileNotFoundError:
        print("default config file not found")
        sys.exit(1)
    except yaml.parser.ParserError:
        print("invalid default yaml config file")
        sys.exit(1)
    return cfg 
    
def setup_config(args):
    """load default config and update it with arguments if provided"""
    # Set the default configuration file
    f = pkgutil.get_data(__package__, 'dnstap.conf')
    cfg = load_yaml(f)

    # Overwrites then with the external file ?    
    if args.c:
        cfg_ext = load_yaml(open(args.c, 'r'))
        merge_cfg(u=cfg_ext,o=cfg)

    # Or searches for a file named dnstap.conf in /etc/dnstap_receiver/       
    else:
        etc_conf = "/etc/dnstap_receiver/dnstap.conf"
        f = pathlib.Path(etc_conf)
        if f.exists():
            cfg_etc = load_yaml(open(etc_conf, 'r'))
            merge_cfg(u=cfg_etc,o=cfg)
            
    # update default config with command line arguments
    if args.v:
        cfg["trace"]["verbose"] = args.v    
    if args.u is not None:
        cfg["input"]["unix-socket"]["path"] = args.u
    if args.l != DFLT_LISTEN_IP:
        cfg["input"]["tcp-socket"]["local-address"] = args.l
    if args.l != DFLT_LISTEN_PORT:
        cfg["input"]["tcp-socket"]["local-port"] = args.p

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
    
def setup_outputs(cfg, stats):
    """setup outputs"""
    conf = cfg["output"]

    queues_list = []
    if conf["syslog"]["enable"]:
        if not output_syslog.checking_conf(cfg=conf["syslog"]): return
        queue_syslog = asyncio.Queue()
        queues_list.append(queue_syslog)
        loop.create_task(output_syslog.handle(conf["syslog"], queue_syslog, stats))    

    if conf["tcp-socket"]["enable"]:
        if not output_tcp.checking_conf(cfg=conf["tcp-socket"]): return
        queue_tcpsocket = asyncio.Queue()
        queues_list.append(queue_tcpsocket)
        loop.create_task(output_tcp.handle(conf["tcp-socket"], queue_tcpsocket, stats))
                                               
    if conf["file"]["enable"]:
        if not output_file.checking_conf(cfg=conf["file"]): return
        queue_file = asyncio.Queue()
        queues_list.append(queue_file)
        loop.create_task(output_file.handle(conf["file"], queue_file, stats))
                                              
    if conf["stdout"]["enable"]:
        if not output_stdout.checking_conf(cfg=conf["stdout"]): return
        queue_stdout = asyncio.Queue()
        queues_list.append(queue_stdout)
        loop.create_task(output_stdout.handle(conf["stdout"], queue_stdout, stats))

    if conf["metrics"]["enable"]:
        if not output_metrics.checking_conf(cfg=conf["metrics"]): return
        queue_metrics = asyncio.Queue()
        queues_list.append(queue_metrics)
        loop.create_task(output_metrics.handle(conf["metrics"], queue_metrics, stats))

    return queues_list
    
def setup_inputs(cfg, queues_outputs, stats, geoip_reader, running):
    """setup inputs"""
    cache = cachetools.TTLCache(maxsize=1000000, ttl=60)
    
    # asynchronous unix 
    if conf["unix-socket"]["enable"]:
        loop.create_task(input_socket.start_unixsocket(cfg["input"], queues_outputs, stats, geoip_reader, cache)) 
        
    # sniffer
    elif conf["sniffer"]["enable"]:
        queue_sniffer = asyncio.Queue()
        loop.create_task(input_sniffer.watch_buffer(cfg["input"]["sniffer"], queue_sniffer, queues_outputs, stats, cache))
        loop.run_in_executor(None, input_sniffer.start_input, conf["sniffer"], queue_sniffer, running)
    
    # default one tcp socket
    else:
        loop.create_task(input_socket.start_tcpsocket(cfg["input"], queues_outputs, stats, geoip_reader, cache))

def setup_webserver(cfg, stats):
    """setup web api"""
    if not cfg["web-api"]["enable"]: return

    loop.create_task(api_server.create_server(loop, cfg=cfg["web-api"], stats=stats, cfg_stats=cfg["statistics"]) )

def setup_geoip(cfg):
    if not cfg["enable"]: return None
    if cfg["city-database"] is None: return None
    
    reader = None
    try:
        reader = geoip2.database.Reader(cfg["city-database"])
    except Exception as e:
        clogger.error("geoip setup: %s" % e)
        
    return reader
    
def start_receiver():
    """start dnstap receiver"""
    # Handle command-line arguments.
    args = parser.parse_args()

    # setup config
    cfg = setup_config(args=args)
  
    # setup logging
    setup_logger(cfg=cfg["trace"])

    # setup geoip if enabled 
    geoip_reader = setup_geoip(cfg=cfg["geoip"])
    
    # add debug message if external config is used
    if args.c: clogger.debug("External config file loaded")
    
    # start receiver
    clogger.debug("Start receiver...")
    stats = statistics.Statistics(cfg=cfg["statistics"])
    loop.create_task(statistics.watcher(stats))
    
    # prepare outputs
    queues_outputs = setup_outputs(cfg, stats)
    
    # prepare inputs
    running = ["running"]
    setup_inputs(cfg, queues_outputs, stats, geoip_reader, running)

    # start the http api
    setup_webserver(cfg, stats)

    # run event loop 
    try:
       loop.run_forever()
    except KeyboardInterrupt:
        clogger.debug("exiting, please wait..")
        running.clear()

    # close geoip
    if geoip_reader is not None: geoip_reader.close()