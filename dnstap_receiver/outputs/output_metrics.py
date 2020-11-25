import logging
import asyncio

async def handle(cfg, queue, metrics):
    """stdout output handler"""
    while True:
        await asyncio.sleep(cfg["interval"])
        
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
        logging.info(", ".join(msg))
        
        # reset stats?
        if not cfg["cumulative"]:
            metrics.reset()