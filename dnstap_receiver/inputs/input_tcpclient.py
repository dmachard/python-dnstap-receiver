import asyncio
import logging
import fstrm
import dnstap_pb

from dnstap_receiver.inputs import dnstap_decoder 

clogger = logging.getLogger("dnstap_receiver.console")

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Input handler: tcp client")
    
    valid_conf = True
    
    if cfg["remote-address"] is None:
        valid_conf = False
        clogger.error("Input handler: no remote address provided")
        
    if cfg["remote-port"] is None:
        valid_conf = False
        clogger.error("Input handler: no port provided")
            
    return valid_conf
    
async def tcp_client(cfg, cfg_input, queues_list, stats, geoip_reader, cache, start_shutdown):
    host, port = cfg_input["remote-address"], cfg_input["remote-port"]
    clogger.debug("Input handler: connection to %s:%s" % (host,port) )
    reader, tcp_writer = await asyncio.open_connection(host, port)
    clogger.debug("Input handler: connected")
    
    content_type = b"protobuf:dnstap.Dnstap"
    fstrm_handler = fstrm.FstrmCodec()
    dnstap = dnstap_pb.Dnstap()
 
                    
    try: 
        # framestream - do handshake 
        ctrl_ready = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_READY, ct=[content_type])
        tcp_writer.write(ctrl_ready)
        
        shutdown_wait_task = asyncio.create_task(start_shutdown.wait())

        while True:
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
                break
            fstrm_handler.append(data=data)
            
            # process the buffer, check if we have received a complete frame ?
            if fstrm_handler.process():
                # Ok, the frame is complete so let's decode it
                ctrl, ct, payload  = fstrm_handler.decode()
                    
                if ctrl == fstrm.FSTRM_CONTROL_ACCEPT:
                    ctrl_start = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_START)
                    tcp_writer.write(ctrl_start)
                    break

        # waiting for incoming data
        running = True
        while running:
            # read bytes
            read_task = asyncio.create_task(reader.read(fstrm_handler.pending_nb_bytes()))
            done, pending = await asyncio.wait(
                [shutdown_wait_task, read_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            if shutdown_wait_task in done:
                read_task.cancel()
                return
            else:
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
                    loop.create_task(dnstap_decoder.cb_ondnstap(dnstap_protobuf, payload, cfg, queues_list, stats, geoip_reader, cache))
     
    except ConnectionError as e:
        clogger.error(f'Input handler: {peername} - %s' % e)
    except asyncio.CancelledError:
        clogger.debug(f'Input handler: {peername} - closing connection.')
        writer.close()
    except asyncio.IncompleteReadError:
        clogger.debug(f'Input handler: {peername} - disconnected')
    finally:
        writer.close()
        clogger.debug(f'Input handler: {peername} - closed')
        
async def start_tcpclient(cfg, queues_list, stats, geoip_reader, cache, start_shutdown):
    """start input tcp client"""
    server_address = (cfg_input["remote-address"], cfg_input["remote-port"])
    loop = asyncio.get_event_loop()
    
    clogger.debug("Input handler: TCP client enabled")
    while not start_shutdown.is_set():
        try:
            await tcp_client(cfg, cfg_input, queues_list, stats, geoip_reader, cache, start_shutdown)
        except ConnectionRefusedError:
            clogger.error('Input handler: connection to remote dns server failed!')
        except TimeoutError:
            clogger.error('Input handler: connection to remote dns server timed out!')
        else:
            clogger.error('Input handler: connection to remote dns server is closed.')
            
        clogger.debug("Input handler: retry to connect every %ss" % cfg_input["retry"])
        await asyncio.sleep(cfg_input["retry"])
