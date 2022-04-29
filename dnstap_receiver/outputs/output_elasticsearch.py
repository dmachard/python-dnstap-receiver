import asyncio
import logging

import requests

clogger = logging.getLogger("dnstap_receiver.console")


def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: elasticsearch")
    
    valid_conf = True
    
    if cfg["url"] is None:
        valid_conf = False
        clogger.error("Output handler: no url provided")
    
    return valid_conf
    

def setup_elasticsearch(cfg):
    """setup elasticsearch"""
    mapping = {
        "mappings": {
            "properties": {
                "message": {
                    "type": "text" 
                },
                "type": {
                    "type": "text"
                },
                "timestamp": {
                    "type": "double"
                },
                "query_ip": {
                    "type": "ip"
                },
                "response_ip": {
                    "type": "ip"
                },
                "qname": {
                    "type": "text"
                },
                "rrtype": {
                    "type": "text"
                },
                "rcode": {
                    "type": "text"
                }
            }
        }
    }

    try:
        requests.put("{}/dnstap_receiver".format(cfg["url"]), json=mapping)
    except Exception as e:
        clogger.error("Output handler: {}".format(str(e)))
    

async def handle(output_cfg, queue, metrics, start_shutdown):
    """elasticsearch output handler"""
    
    # init elasticsearch
    setup_elasticsearch(output_cfg)
    
    while not start_shutdown.is_set():
        try:
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        
        data = {
            "message": tapmsg['message'],
            "type": tapmsg['type'],
            "timestamp": tapmsg['timestamp'],
            "query_ip": tapmsg['query-ip'],
            "response_ip": tapmsg['response-ip'],
            "qname": tapmsg['qname'],
            "rrtype": tapmsg['rrtype'],
            "rcode": tapmsg['rcode']
        }

        try:
            requests.post("{}/dnstap_receiver/_doc".format(output_cfg["url"]), json=data)
        except Exception as e:
            clogger.error("Output handler: {}".format(str(e)))

        queue.task_done()
