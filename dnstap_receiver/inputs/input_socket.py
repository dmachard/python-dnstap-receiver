import asyncio
import logging
import ssl
import ipaddress

# import framestreams and dnstap protobuf decoder
from dnstap_receiver.codecs import fstrm 
from dnstap_receiver.codecs import dnstap_pb2 
from dnstap_receiver.codecs import dnstap_decoder 

clogger = logging.getLogger("dnstap_receiver.console")
    
async def cb_onconnect(reader, writer, cfg, queues_list, stats, geoip_reader):
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
    dnstap_protobuf = dnstap_pb2.Dnstap()

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
                    loop.create_task(dnstap_decoder.cb_ondnstap(dnstap_protobuf, payload, cfg, queues_list, stats, geoip_reader))
                    
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

def start_tcpsocket(cfg, cb_onconnect):
    clogger.debug("Input handler: tcp socket")
    loop = asyncio.get_event_loop()
    
    ssl_context = None
    if cfg["tls-support"]:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cfg["tls-server-cert"], keyfile=["tls-server-key"])
        clogger.debug("Input handler - tls support enabled")
        
    clogger.debug("Input handler: listening on %s:%s" % (cfg["local-address"],cfg["local-port"])), 
    server = asyncio.start_server(cb_onconnect, cfg["local-address"],cfg["local-port"],
                                  ssl=ssl_context, loop=loop)
    return server
    
def start_unixsocket(cfg, cb_onconnect):
    clogger.debug("Input handler: unix socket")
    clogger.debug("Input handler: listening on %s" % cfg["path"])
    loop = asyncio.get_event_loop()
    
    # asynchronous unix socket
    server = asyncio.start_unix_server(cb_onconnect, path=cfg["path"], loop=loop)
                                                  
    return server
    
def start_input(cfg, queues_list, stats, geoip_reader):
    # define callback on new connection
    cb_lambda = lambda r, w: cb_onconnect(r, w, cfg, queues_list, stats, geoip_reader)
    
    if cfg["input"]["unix-socket"]["path"] is not None:
        return start_unixsocket(cfg=cfg["input"]["unix-socket"], cb_onconnect=cb_lambda)
    else:
        return start_tcpsocket(cfg=cfg["input"]["tcp-socket"], cb_onconnect=cb_lambda) 
