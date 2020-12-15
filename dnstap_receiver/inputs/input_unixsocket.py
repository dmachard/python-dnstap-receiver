import asyncio
import logging

clogger = logging.getLogger("dnstap_receiver.console")

def start_input(cfg, cb_onconnect, loop):
    clogger.debug("Input handler: unix socket")
    clogger.debug("Input handler: listening on %s" % cfg["path"])
  
    # asynchronous unix socket
    server = asyncio.start_unix_server(cb_onconnect, path=cfg["path"], loop=loop)
                                                  
    return server