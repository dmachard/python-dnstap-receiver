import logging
import sys

clogger = logging.getLogger("dnstap_receiver.console")
tap_logger = logging.getLogger("dnstap_receiver.output.stdout")

from dnstap_receiver import transform

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: stdout")
    return True
    
def setup_logger():
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
    
    # init logger
    setup_logger()
    
    while True:
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        tap_logger.info(msg.decode())
        
        # all done
        queue.task_done()