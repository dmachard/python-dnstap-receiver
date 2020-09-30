import asyncio
import logging

from dnstap_receiver import transform

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
    logging.error("Output handler: connection lost")
 
async def handle(output_cfg, queue):
    """handle output"""
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
            msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
            # send msg
            transport.sendto( msg )
            
            # all done
            queue.task_done()