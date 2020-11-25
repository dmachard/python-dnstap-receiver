import logging
import sys

file_logger = logging.getLogger("dnstap_receiver.output.file")

from dnstap_receiver import transform

def setup_logger(cfg):
    """setup loggers"""
    logfmt = '%(asctime)s %(message)s'
    
    file_logger.setLevel(logging.INFO)
    file_logger.propagate = False
    
    lh = logging.FileHandler(cfg["file"])
    lh.setLevel(logging.INFO)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    file_logger.addHandler(lh)
    
async def handle(output_cfg, queue, metrics):
    """stdout output handler"""
    
    # init output logger
    setup_logger(cfg)
    
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        file_logger.info(msg.decode())
        
        # all done
        queue.task_done()