import asyncio
import logging
import ssl

clogger = logging.getLogger("dnstap_receiver.console")

def start_input(cfg, cb_onconnect, loop):
    clogger.debug("Input handler: tcp socket")
    
    ssl_context = None
    if cfg["tls-support"]:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=cfg["tls-server-cert"], keyfile=["tls-server-key"])
        clogger.debug("Input handler - tls support enabled")
        
    clogger.debug("Input handler: listening on %s:%s" % (cfg["local-address"],cfg["local-port"])), 
    server = asyncio.start_server(cb_onconnect, cfg["local-address"],cfg["local-port"],
                                  ssl=ssl_context, loop=loop)
    return server