import logging
import logging.handlers
import sys

clogger = logging.getLogger("dnstap_receiver.console")
file_logger = logging.getLogger("dnstap_receiver.output.file")

from dnstap_receiver.outputs import transform

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: file")
    
    return True
    
def setup_logger(cfg):
    """setup loggers"""
    logfmt = '%(message)s'
    max_bytes = int(cfg["file-max-size"].split('M')[0]) * 1024 * 1024
    
    file_logger.setLevel(logging.INFO)
    file_logger.propagate = False
    
    lh = logging.handlers.RotatingFileHandler(
        cfg["file"],
        maxBytes=max_bytes,
        backupCount=cfg["file-count"]
    )
    lh.setLevel(logging.INFO)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    file_logger.addHandler(lh)
    
async def handle(output_cfg, queue, metrics, start_shutdown):
    """stdout output handler"""

    # init output logger
    setup_logger(output_cfg)
    
    while not start_shutdown.is_set():
        # read item from queue
        tapmsg = await queue.get()
        
        # convert dnstap message
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        
        # print to stdout
        file_logger.info(msg.decode())
        
        # all done
        queue.task_done()
