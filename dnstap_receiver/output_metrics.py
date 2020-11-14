import logging
import asyncio

async def handle(cfg, queue, metrics):
    """stdout output handler"""
    
    queries_prev = metrics.get_counters()["queries"]
    while True:
        await asyncio.sleep(cfg["interval"])
        
        # clear queue
        for _ in range(queue.qsize()):
            queue.get_nowait()
            queue.task_done()
            
        # get counters
        counters = metrics.get_counters()
    
        if not cfg["cumulative"]:
            queries_prev = 0
        queries_cur = counters["queries"]
        qps = (queries_cur - queries_prev ) / cfg["interval"] 
        queries_prev = queries_cur
        
        msg = [ "%s QUERIES" % queries_cur ]
        msg.append( "%s QPS" % round(qps, 2))
        msg.append( "%s CLIENTS" % counters["clients"] )
        
        msg.append( "%s INET" % counters["INET"] )   
        msg.append( "%s INET6" % counters["INET6"] )

        msg.append( "%s UDP" % counters["UDP"] )
        msg.append( "%s TCP" % counters["TCP"] )
 
        msg.append( "%s DOMAINS" % counters["domains"] )
        msg.append( "%s NXDOMAINS" % counters["nxdomains"] )
        
        msg.append( "%s A" % counters["A"] )
        msg.append( "%s AAAA" % counters["AAAA"] )
        
        # print to stdout
        logging.info(", ".join(msg))
        
        # reset stats?
        if not cfg["cumulative"]:
            metrics.reset()