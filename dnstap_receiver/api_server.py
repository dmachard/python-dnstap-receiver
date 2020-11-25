
import logging
import json

from aiohttp import web

clogger = logging.getLogger("dnstap_receiver.console")

class Handlers:
    def __init__(self, apikey, stats, cfg_stats):
        self.api_key = apikey
        self.cfg_stats = cfg_stats
        self.stats = stats
        self.top = 10
        
    def check_auth(self, request):
        """check api key value"""
        req_auth = request.headers.get('X-API-Key')
        if req_auth is None or req_auth != self.api_key:
            return False
        return True
   
    async def handle_reset(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)
      
        self.stats.reset()
        return web.Response(status=204)
        
    async def handle_count(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)

        n = request.query.get("n", self.top)
        s = request.query.get("stream", None)
        more_filters = request.query.get("more", [])
        if not isinstance(more_filters, list):
            more_filters = more_filters.split(",")
            
        filters = self.cfg_stats["default-counters"]
        filters.extend(more_filters)
        
        data = {"stream": s, "counters": self.stats.get_counters(s, filters=filters)}
        return web.json_response(data)
        
    async def handle_top(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)

        n = request.query.get("n", self.top)
        s = request.query.get("stream", None)
        more_filters = request.query.get("more", [])
        if not isinstance(more_filters, list):
            more_filters = more_filters.split(",")
            
        filters = self.cfg_stats["default-top"]
        filters.extend(more_filters)

        data = { "stream": s,
                 "top-domain": self.stats.top_domains(int(n),s, filters=filters),
                 "top-client": self.stats.top_clients(int(n), s),
                 "top-rcode": self.stats.top_dnscode(int(n), s, rcode=True),
                 "top-rrtype": self.stats.top_dnscode(int(n),s, rcode=False) }
        return web.json_response(data)
        
    async def handle_streams(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)

        data = { "streams": self.stats.get_nameslist() }
        return web.json_response(data)
        
async def create_server(loop, cfg, stats, cfg_stats):
    # api ressources
    hdlrs = Handlers(cfg["api-key"], stats, cfg_stats)
    
    # rest api server
    app = web.Application(loop=loop)
 
    # endpoints
    app.router.add_get('/top', hdlrs.handle_top)
    app.router.add_get('/count', hdlrs.handle_count)
    app.router.add_get('/streams', hdlrs.handle_streams)
    app.router.add_delete('/reset', hdlrs.handle_reset)

    # create the server
    listen_address = (cfg["local-address"], cfg["local-port"])
    srv = await loop.create_server(app.make_handler(access_log=None), *listen_address)
    clogger.debug("Api rest: listening on %s:%s" % listen_address )
    
    return srv
