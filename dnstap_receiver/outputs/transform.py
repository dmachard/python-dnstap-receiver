import json
import yaml

from datetime import datetime, timezone

def convert_dnstap(fmt, tapmsg):
    """convert dnstap message"""
    tapmsg["datetime"] = datetime.fromtimestamp(tapmsg["timestamp"], tz=timezone.utc).isoformat()

    if fmt == "text":
        msg_list = []
        msg_list.append("%s" % tapmsg["datetime"])
        msg_list.append("%s" % tapmsg["identity"])
        msg_list.append("%s" % tapmsg["message"])
        msg_list.append("%s" % tapmsg["rcode"]) 
        msg_list.append("%s" % tapmsg["query-ip"])
        msg_list.append("%s" % tapmsg["query-port"])
        msg_list.append("%s" % tapmsg["family"])
        msg_list.append("%s" % tapmsg["protocol"])
        msg_list.append("%sb" % tapmsg["length"])
        msg_list.append("%s" % tapmsg["qname"])
        msg_list.append("%s" % tapmsg["rrtype"])
        msg_list.append("%s" % tapmsg["latency"])
        
        # geoip activated ?
        if "country" in tapmsg:
            msg_list.append("%s" % tapmsg["country"])
            msg_list.append("%s" % tapmsg["city"])
            
        msg = " ".join(msg_list)
        del msg_list
        return msg.encode()
        
    elif fmt == "json":
        # delete some unneeded keys
        del tapmsg["payload"]; del tapmsg["time-sec"]; del tapmsg["time-nsec"];
        
        msg = json.dumps(tapmsg)
        return msg.encode()
        
    elif fmt == "yaml":
        # delete some unneeded keys
        del tapmsg["payload"]; del tapmsg["time-sec"]; del tapmsg["time-nsec"];
        
        msg = yaml.dump(tapmsg)
        return msg.encode()
        
    else:
        return tapmsg
    