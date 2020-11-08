import logging
import asyncio

async def handle(cfg, queue, metrics):
    """stdout output handler"""
    
    queries_prev = metrics.qr_total
    while True:
        await asyncio.sleep(cfg["interval"])
        
        # clear queue
        for _ in range(queue.qsize()):
            queue.get_nowait()
            queue.task_done()
 
        if not cfg["cumulative"]:
            queries_prev = 0
        queries_cur = metrics.qr_total
        qps = (queries_cur - queries_prev ) / cfg["interval"] 
        queries_prev = queries_cur
        
        msg = [ "%s QUERIES" % queries_cur ]
        msg.append( "%s QPS" % round(qps, 2))
        msg.append( "%s CLIENTS" % len(metrics.clients) )
        
        msg.append( "%s INET" % metrics.family.get("INET", 0) )   
        msg.append( "%s INET6" % metrics.family.get("INET6", 0) )

        msg.append( "%s UDP" % metrics.proto.get("UDP", 0) )
        msg.append( "%s TCP" % metrics.proto.get("TCP", 0) )
 
        msg.append( "%s NOERROR" % metrics.rcode.get("NOERROR", 0) )
        msg.append( "%s NXDOMAIN" % metrics.rcode.get("NXDOMAIN", 0) )

        msg.append( "%s A" % metrics.qtype.get("A", 0) )
        msg.append( "%s AAAA" % metrics.qtype.get("AAAA", 0) )

        # print to stdout
        logging.info(", ".join(msg))
        
        # reset stats?
        if not cfg["cumulative"]:
            metrics.reset()