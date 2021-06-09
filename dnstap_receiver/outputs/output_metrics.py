import logging
import asyncio
import sys

clogger = logging.getLogger("dnstap_receiver.console")
metrics_logger = logging.getLogger("dnstap_receiver.output.metrics")

def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: metrics")
    return True
    
def setup_logger(cfg):
    """setup loggers"""
    logfmt = '%(asctime)s %(message)s'
    max_bytes = int(cfg["file-max-size"].split('M')[0]) * 1024 * 1024
    
    metrics_logger.setLevel(logging.INFO)
    metrics_logger.propagate = False
    
    if cfg["file"] is not None:
        lh = logging.handlers.RotatingFileHandler(
            cfg["file"],
            maxBytes=max_bytes,
            backupCount=cfg["file-count"]
        )
    else:
        lh = logging.StreamHandler(stream=sys.stdout)
    lh.setLevel(logging.INFO)
    lh.setFormatter(logging.Formatter(logfmt))    
    
    metrics_logger.addHandler(lh)
    
    
async def handle(cfg, queue, metrics, start_shutdown):
    """stdout output handler"""
    # init logger
    setup_logger(cfg)

    shutdown_wait_task = asyncio.create_task(start_shutdown.wait())
    sleep_task = asyncio.create_task(asyncio.sleep(cfg["interval"]))
    while True:
        done, pending = await asyncio.wait(
            [shutdown_wait_task, sleep_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if shutdown_wait_task in done:
            sleep_task.cancel()
            return
        else:
            sleep_task = asyncio.sleep(cfg["interval"])

        # clear queue
        for _ in range(queue.qsize()):
            queue.get_nowait()
            queue.task_done()
            
        # get counters
        filters = [ "query", "qps", "clients", "domains",
                    "query/inet", "query/inet6", 
                    "query/udp", "query/tcp",
                    "response/noerror", "response/nxdomain",
                    "query/a", "query/aaaa"] 
        counters = metrics.get_counters(filters=filters)

        msg = [ "%s QUERIES" % counters["query"] ]
        msg.append( "%s QPS" % counters["qps"] )
        
        msg.append( "%s DOMAINS" % counters["domains"] )
        msg.append( "%s CLIENTS" % counters["clients"] )
        
        msg.append( "%s INET" % counters["query/inet"] )   
        msg.append( "%s INET6" % counters["query/inet6"] )

        msg.append( "%s UDP" % counters["query/udp"] )
        msg.append( "%s TCP" % counters["query/tcp"] )
        
        msg.append( "%s NOERROR" % counters["response/noerror"] )
        msg.append( "%s NXDOMAINS" % counters["response/nxdomain"] )
        
        msg.append( "%s A" % counters["query/a"] )
        msg.append( "%s AAAA" % counters["query/aaaa"] )
        
        # print to stdout
        metrics_logger.info(", ".join(msg))
        
        # reset stats?
        if not cfg["cumulative"]:
            metrics.reset()
