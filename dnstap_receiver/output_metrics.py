import logging
import asyncio

async def handle(cfg, metrics):
    """stdout output handler"""
    
    queries_prev = metrics.stats["total-queries"]
    while True:
        await asyncio.sleep(cfg["interval"])
        
        if not cfg["cumulative"]:
            queries_prev = 0
        queries_cur = metrics.stats["total-queries"]
        qps = (queries_cur - queries_prev ) / cfg["interval"] 
        queries_prev = queries_cur
        
        msg = [ "%s QUERIES" % queries_cur ]
        msg.append( "%s QPS" % round(qps, 2))
        msg.append( "%s CLIENTS" % len(metrics.clients) )
        
        msg.append( "%s IP4" % metrics.family.get("IP4", 0) )   
        msg.append( "%s IP6" % metrics.family.get("IP6", 0) )

        msg.append( "%s UDP" % metrics.proto.get("UDP", 0) )
        msg.append( "%s TCP" % metrics.proto.get("TCP", 0) )
 
        msg.append( "%s NOERROR" % metrics.rcode.get("NOERROR", 0) )
        msg.append( "%s NXDOMAIN" % metrics.rcode.get("NXDOMAIN", 0) )

        msg.append( "%s A" % metrics.rtype.get("A", 0) )
        msg.append( "%s AAAA" % metrics.rtype.get("AAAA", 0) )

        # print to stdout
        logging.info(", ".join(msg))
        
        # reset stats?
        if not cfg["cumulative"]:
            metrics.reset()