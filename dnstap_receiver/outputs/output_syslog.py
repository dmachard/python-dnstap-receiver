import asyncio
import logging

clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver import transform

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: syslog")
    
    valid_conf = True
    
    if cfg["remote-address"] is None:
        valid_conf = False
        clogger.error("Output handler: no remote address provided")
        
    if cfg["remote-port"] is None:
        valid_conf = False
        clogger.error("Output handler: no port provided")
            
    return valid_conf
    
async def syslog_tcpclient(output_cfg, queue):
    host, port = output_cfg["remote-address"], output_cfg["remote-port"]
    clogger.debug("Output handler: connection to %s:%s" % (host,port) )
    reader, tcp_writer = await asyncio.open_connection(host, port)
    clogger.debug("Output handler: connected")
    
    # consume queue
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
            
        # add count octets
        s_msg = "%s" % len(msg)
        tcp_writer.write( b"%s %s" % (s_msg.encode(), msg) )
        
        # connection lost ? exit and try to reconnect 
        if tcp_writer.transport._conn_lost:
            break
        
        # done continue to next item
        queue.task_done()
        
    # something 
    clogger.error("Output handler: connection lost")
 
async def handle(output_cfg, queue, metrics):
    """handle output"""
    server_address = (output_cfg["remote-address"], output_cfg["remote-port"])
    loop = asyncio.get_event_loop()
    
    # syslog tcp
    if output_cfg["transport"] == "tcp":
        clogger.debug("Output handler: syslog TCP enabled")
        while True:
            try:
                await syslog_tcpclient(output_cfg, queue)
            except ConnectionRefusedError:
                clogger.error('Output handler: connection to syslog server failed!')
            except asyncio.TimeoutError:
                clogger.error('Output handler: connection to syslog server timed out!')
            else:
                clogger.error('Output handler: connection to server is closed.')
                
            clogger.debug("'Output handler: retry to connect every 5s")
            await asyncio.sleep(output_cfg["retry"])
    
    # syslog udp
    else:
        clogger.debug("Output handler: syslog UDP enabled with %s" % str(server_address) )
        transport, _  = await loop.create_datagram_endpoint(asyncio.DatagramProtocol,
                                                            remote_addr=server_address)

        # consume the queue
        while True:
            # read item from queue
            tapmsg = await queue.get()
            
            # convert dnstap message
            msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
            # send msg
            transport.sendto( msg )
            
            # all done
            queue.task_done()