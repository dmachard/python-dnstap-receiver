import logging

from dnstap_receiver import transform

async def handle(output_cfg, queue):
    """stdout output handler"""
    
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        logging.info(msg.decode())
        
        # all done
        queue.task_done()