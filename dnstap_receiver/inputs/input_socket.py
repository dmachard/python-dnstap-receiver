import asyncio
import logging
import ssl
import ipaddress
import fstrm
import dnstap_pb

from dnstap_receiver.inputs import dnstap_decoder 

clogger = logging.getLogger("dnstap_receiver.console")


async def cb_onconnect(reader, writer, cfg, cfg_input, queues_list, stats, geoip_reader, cache, start_shutdown):
    """callback when a connection is established"""
    # get peer name
    peername = writer.get_extra_info('peername')
    if not len(peername):
        peername = "(unix-socket)"
    clogger.debug(f"Input handler: new connection from {peername}")

    # access control list check
    if "access-control-list" in cfg_input:
        if len(writer.get_extra_info('peername')):
            acls_network = []
            for a in cfg_input["access-control-list"]:
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
    content_type = b"protobuf:dnstap.Dnstap"
    fstrm_handler = fstrm.FstrmCodec()
    loop = asyncio.get_event_loop()
    dnstap_protobuf = dnstap_pb.Dnstap()

    try: 
        # syntax only works with python 3.8
        # while data := await reader.read(fstrm_handler.pending_nb_bytes()) 
        running = True
        while running:
            # read bytes
            shutdown_wait_task = asyncio.create_task(start_shutdown.wait())
            read_task = asyncio.create_task(reader.read(fstrm_handler.pending_nb_bytes()))
            done, pending = await asyncio.wait(
                [shutdown_wait_task, read_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            if shutdown_wait_task in done:
                read_task.cancel()
                return
            else:
                shutdown_wait_task.cancel()
                data = await read_task

            if not len(data):
                running = False
                break
                
            # append data to the buffer
            fstrm_handler.append(data=data)
            
            # process the buffer, check if we have received a complete frame ?
            if fstrm_handler.process():
                # Ok, the frame is complete so let's decode it
                ctrl, ct, payload  = fstrm_handler.decode()

                # handle the DATA frame
                if ctrl == fstrm.FSTRM_DATA_FRAME:
                    await dnstap_decoder.cb_ondnstap(dnstap_protobuf, payload, cfg, queues_list, stats, geoip_reader, cache)
                    
                # handle the control frame READY
                if ctrl == fstrm.FSTRM_CONTROL_READY:
                    clogger.debug(f"Input handler: control ready received from {peername}")
                    if content_type not in ct:
                        raise Exception("content type error: %s" % ct)
                        
                    # todo, checking content type
                    ctrl_accept = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_ACCEPT, ct=[content_type])
                    # respond with accept only if the content type is dnstap
                    writer.write(ctrl_accept)
                    await writer.drain()
                    clogger.debug(f"Input handler: sending control accept to {peername}")
                    
                # handle the control frame READY
                if ctrl == fstrm.FSTRM_CONTROL_START:
                    clogger.debug(f"Input handler: control start received from {peername}")
   
                # handle the control frame STOP
                if ctrl == fstrm.FSTRM_CONTROL_STOP:
                    clogger.debug(f"Input handler: control stop received from {peername}")
                    fstrm_handler.reset()
                    
                    # send finish control
                    ctrl_finish = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_FINISH)
                    writer.write(ctrl_finish)
                    await writer.drain()
                    
                    clogger.debug(f"Input handler: sending control finish to {peername}")
                    
    except ConnectionError as e:
        clogger.error(f'Input handler: {peername} - %s' % e)
    except asyncio.CancelledError:
        clogger.debug(f'Input handler: {peername} - closing connection.')
        writer.close()
        await writer.wait_closed()
    except asyncio.IncompleteReadError:
        clogger.debug(f'Input handler: {peername} - disconnected')
    finally:
        clogger.debug(f'Input handler: {peername} - closed')

def start_tcpsocket(cfg, queues_list, stats, geoip_reader, cache, start_shutdown):
    clogger.debug("Input handler: tcp socket")
    loop = asyncio.get_event_loop()
    cfg_input = cfg["input"]["tcp-socket"]
    
    # define callback on new connection
    cb_lambda = lambda r, w: cb_onconnect(r, w, cfg, cfg_input, queues_list, stats, geoip_reader, cache, start_shutdown)
    
    ssl_context = None
    if cfg_input["tls-support"]:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cfg_input["tls-server-cert"], keyfile=cfg_input["tls-server-key"])
        clogger.debug("Input handler - tls support enabled")
        
    clogger.debug("Input handler: listening on %s:%s" % (cfg_input["local-address"],cfg_input["local-port"])), 
    server = asyncio.start_server(cb_lambda, cfg_input["local-address"],cfg_input["local-port"],
                                  ssl=ssl_context, loop=loop)
    return server
    
def start_unixsocket(cfg, queues_list, stats, geoip_reader, cache, start_shutdown):
    clogger.debug("Input handler: unix socket")
    cfg_input = cfg["input"]["unix-socket"]
    
    loop = asyncio.get_event_loop()
    
    # define callback on new connection
    cb_lambda = lambda r, w: cb_onconnect(r, w, cfg, cfg_input, queues_list, stats, geoip_reader, cache, start_shutdown)
    
    # asynchronous unix socket
    clogger.debug("Input handler: listening on %s" % cfg_input["path"])
    server = asyncio.start_unix_server(cb_lambda, path=cfg_input["path"], loop=loop)
                                                  
    return server
