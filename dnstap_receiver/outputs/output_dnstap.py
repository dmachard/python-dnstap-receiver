import asyncio
import logging
import socket
import fstrm
import dnstap_pb

from dnstap_receiver.outputs import transform

clogger = logging.getLogger("dnstap_receiver.console")

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: dnstap")
    
    valid_conf = True
    
    if cfg["remote-address"] is None:
        valid_conf = False
        clogger.error("Output handler: no remote address provided")
        
    if cfg["remote-port"] is None:
        valid_conf = False
        clogger.error("Output handler: no port provided")
            
    return valid_conf
    
async def dnstap_client(output_cfg, queue, start_shutdown):
    host, port = output_cfg["remote-address"], output_cfg["remote-port"]
    clogger.debug("Output handler: connection to %s:%s" % (host,port) )
    reader, tcp_writer = await asyncio.open_connection(host, port)
    clogger.debug("Output handler: connected")
    
    content_type = b"protobuf:dnstap.Dnstap"
    fstrm_handler = fstrm.FstrmCodec()
    dnstap = dnstap_pb.Dnstap()
    
    # framestream - do handshake 
    ctrl_ready = fstrm_handler.encode(ctrl=fstrm.FSTRM_CONTROL_READY, ct=[content_type])
    tcp_writer.write(ctrl_ready)
    
    while not start_shutdown.is_set():
        data = await reader.read(fstrm_handler.pending_nb_bytes())
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

    if start_shutdown.is_set():
        return

    # consume queue and send data frames
    while not start_shutdown.is_set():
        # read item from queue
        tap = await queue.get()
        
        dnstap.Clear()
        
        dnstap.type = 1
        dnstap.version = b"-"
        dnstap.identity = output_cfg["dnstap-identity"].encode()
        
        dnstap.message.type = dnstap_pb.dnstap_pb2._MESSAGE_TYPE.values_by_name[tap["message"]].number
        dnstap.message.socket_protocol = dnstap_pb.dnstap_pb2._SOCKETPROTOCOL.values_by_name[tap["protocol"]].number
        dnstap.message.socket_family = dnstap_pb.dnstap_pb2._SOCKETFAMILY.values_by_name[tap["family"]].number

        if tap["type"] == "query":
            dnstap.message.query_message = tap["payload"]
            dnstap.message.query_time_nsec = tap["time-nsec"]
            dnstap.message.query_time_sec = tap["time-sec"]
        else:
            dnstap.message.response_message = tap["payload"]
            dnstap.message.response_time_nsec = tap["time-nsec"]
            dnstap.message.response_time_sec = tap["time-sec"]

        if tap["family"] == "INET":
            dnstap.message.query_address = socket.inet_pton(socket.AF_INET, tap["query-ip"])
            dnstap.message.response_address = socket.inet_pton(socket.AF_INET, tap["response-ip"])
            
        if tap["family"] == "INET6":
            dnstap.message.query_address = socket.inet_pton(socket.AF_INET6, tap["query-ip"])
            dnstap.message.response_address = socket.inet_pton(socket.AF_INET6, tap["response-ip"])
            
        dnstap.message.query_port = tap["query-port"]
        dnstap.message.response_port = tap["response-port"]

        # convert to dnstap message
        data = fstrm_handler.encode(ctrl=fstrm.FSTRM_DATA_FRAME, payload=dnstap.SerializeToString())
        tcp_writer.write(data)
        
        # connection lost ? exit and try to reconnect 
        if tcp_writer.transport._conn_lost:
            break
        
        # done continue to next item
        queue.task_done()

    if start_shutdown.is_set():
        return
        
    # something 
    clogger.error("Output handler: connection lost")
 
async def handle(output_cfg, queue, metrics, start_shutdown):
    """handle output"""
    server_address = (output_cfg["remote-address"], output_cfg["remote-port"])
    loop = asyncio.get_event_loop()
    
    clogger.debug("Output handler: DNS tap enabled")
    while not start_shutdown.is_set():
        try:
            await dnstap_client(output_cfg, queue, start_shutdown)
        except ConnectionRefusedError:
            clogger.error('Output handler: connection to remote dnstap receiver failed!')
        except TimeoutError:
            clogger.error('Output handler: connection to remote dnstap receiver timed out!')
        else:
            clogger.error('Output handler: connection to remote dnstap receiver is closed.')
            
        clogger.debug("Output handler: retry to connect every %ss" % output_cfg["retry"])
        if not start_shutdown.is_set():
            await asyncio.sleep(output_cfg["retry"])
