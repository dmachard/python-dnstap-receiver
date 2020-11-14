
import logging
import json

from aiohttp import web

class Handlers:
    def __init__(self, apikey, stats):
        self.api_key = apikey
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
        return web.json_response({"message": "success"})
        
    async def handle_top(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)

        top = request.query.get("max", self.top)
        stream = request.query.get("stream", None)

        data = { "streams": self.stats.get_nameslist(),
                 "current": stream,
                 "top": self.stats.get_mostcommon(top,stream),
                 "total": self.stats.get_counters(stream) }
        return web.json_response(data)

async def create_server(loop, cfg, stats):
    # api ressources
    hdlrs = Handlers(cfg["api-key"], stats)
    
    # rest api server
    app = web.Application(loop=loop)
 
    # endpoints
    app.router.add_get('/top', hdlrs.handle_top)
    app.router.add_get('/reset', hdlrs.handle_reset)

    # create the server
    listen_address = (cfg["local-address"], cfg["local-port"])
    srv = await loop.create_server(app.make_handler(access_log=None), *listen_address)
    logging.debug("Api rest: listening on %s:%s" % listen_address )
    
    return srv
