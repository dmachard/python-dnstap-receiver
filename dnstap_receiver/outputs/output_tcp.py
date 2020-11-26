import asyncio
import logging

clogger = logging.getLogger("dnstap_receiver.console")
clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver import transform

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: tcp")
    
    valid_conf = True
    
    if cfg["remote-address"] is None:
        valid_conf = False
        clogger.error("Output handler: no remote address provided")
        
    if cfg["remote-port"] is None:
        valid_conf = False
        clogger.error("Output handler: no port provided")
            
    return valid_conf
    
async def plaintext_tcpclient(output_cfg, queue):
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
            
        # add delimiter
        tcp_writer.write( b"%s%s" % (msg, output_cfg["delimiter"]) )
        
        # connection lost ? exit and try to reconnect 
        if tcp_writer.transport._conn_lost:
            break
        
        # done continue to next item
        queue.task_done()
        
    # something 
    clogger.error("Output handler: connection lost")

async def handle(output_cfg, queue, metrics):
    """tcp reconnect"""
    server_address = (output_cfg["remote-address"], output_cfg["remote-port"])
    loop = asyncio.get_event_loop()

    clogger.debug("Output handler: TCP enabled")
    while True:
        try:
            await plaintext_tcpclient(output_cfg, queue)
        except ConnectionRefusedError:
            clogger.error('Output handler: connection to tcp server failed!')
        except asyncio.TimeoutError:
            clogger.error('Output handler: connection to tcp server timed out!')
        else:
            clogger.error('Output handler: connection to tcp is closed.')
            
        clogger.debug("'Output handler: retry to connect every 5s")
        await asyncio.sleep(output_cfg["retry"])

