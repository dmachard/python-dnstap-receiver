import logging
import sys

tap_logger = logging.getLogger("dnstap_receiver.output.stdout")

from dnstap_receiver import transform

def setup_taplogger():
    """setup loggers"""
    logfmt = '%(message)s'
    
    tap_logger.setLevel(logging.INFO)
    tap_logger.propagate = False
    
    lh = logging.StreamHandler(stream=sys.stdout)
    lh.setLevel(logging.INFO)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    tap_logger.addHandler(lh)
    
async def handle(output_cfg, queue, metrics):
    """stdout output handler"""
    
    # init tap logger
    setup_taplogger()
    
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        tap_logger.info(msg.decode())
        
        # all done
        queue.task_done()