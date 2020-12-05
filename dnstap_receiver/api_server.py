
import logging
import json

from aiohttp import web
from aiohttp import BasicAuth

clogger = logging.getLogger("dnstap_receiver.console")

class Handlers:
    def __init__(self, apikey, basicauth, stats, cfg_stats):
        self.api_key = apikey
        self.basic_auth = basicauth
        self.cfg_stats = cfg_stats
        self.stats = stats
        self.top = 10
        
    def check_auth(self, request):
        """check api key value"""
        # support basic auth or x-api-key authentication
        req_auth = request.headers.get('X-API-Key')
        basic_auth = request.headers.get('Authorization')

        if req_auth is None and basic_auth is None:
            return False
        
        if req_auth is not None:
            if req_auth != self.api_key:
                return False
                
        if basic_auth is not None:
            auth = BasicAuth(login="").decode(auth_header=basic_auth)

            if self.basic_auth != auth:
                return False
                
        return True
   
    async def handle_reset(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)
      
        self.stats.reset()
        return web.Response(status=204)
    
    async def handle_metrics(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)
  
        filters = ["qps", "domains", "clients",
                   "query", "query/udp", "query/tcp", "query/inet", "query/inet6", 
                   "query/a", "query/aaaa", "query/svr",
                   "response", "response/udp", "response/tcp", "response/inet", "response/inet6", 
                   "response/nxdomain", "response/noerror", "response/serverfail" ]
                   
        # global counters
        counters = self.stats.get_counters(stream=None, filters=filters)

        p = []
        
        p.append( "# HELP dnstap_qps Number of queries per second received" )
        p.append( "# TYPE dnstap_qps counter" )
        p.append( "dnstap_qps %s" % counters["qps"] )
        
        p.append( "# HELP dnstap_domains Number of domains asked" )
        p.append( "# TYPE dnstap_domains counter" )
        p.append( "dnstap_domains %s" % counters["domains"] )
        
        p.append( "# HELP dnstap_clients Number of clients asked" )
        p.append( "# TYPE dnstap_clients counter" )
        p.append( "dnstap_clients %s" % counters["clients"] )
        
        p.append( "# HELP dnstap_queries Number of queries received" )
        p.append( "# TYPE dnstap_queries counter" )
        p.append( "dnstap_queries %s" % counters["query"] )
        
        p.append( "# HELP dnstap_queries_udp Number of UDP queries received" )
        p.append( "# TYPE dnstap_queries_udp counter" )
        p.append( "dnstap_queries_udp %s" % counters["query/udp"] )
        
        p.append( "# HELP dnstap_queries_tcp Number of TCP queries received" )
        p.append( "# TYPE dnstap_queries_tcp counter" )
        p.append( "dnstap_queries_tcp %s" % counters["query/tcp"] )
        
        p.append( "# HELP dnstap_queries_inet Number of IPv4 queries received" )
        p.append( "# TYPE dnstap_queries_inet counter" )
        p.append( "dnstap_queries_inet %s" % counters["query/inet"] )
        
        p.append( "# HELP dnstap_queries_inet6 Number of IPv6 queries received" )
        p.append( "# TYPE dnstap_queries_inet6 counter" )
        p.append( "dnstap_queries_inet6 %s" % counters["query/inet6"] )
        
        p.append( "# HELP dnstap_queries_a Number of A queries received" )
        p.append( "# TYPE dnstap_queries_a counter" )
        p.append( "dnstap_queries_a %s" % counters["query/a"] )
        
        p.append( "# HELP dnstap_queries_aaaa Number of AAAA queries received" )
        p.append( "# TYPE dnstap_queries_aaaa counter" )
        p.append( "dnstap_queries_aaaa %s" % counters["query/aaaa"] )
        
        p.append( "# HELP dnstap_queries_svr Number of SVR queries received" )
        p.append( "# TYPE dnstap_queries_svr counter" )
        p.append( "dnstap_queries_svr %s" % counters["query/svr"] )
        
        p.append( "# HELP dnstap_responses Number of responses received" )
        p.append( "# TYPE dnstap_responses counter" )
        p.append( "dnstap_responses %s" % counters["response"] )
        
        p.append( "# HELP dnstap_response_udp Number of UDP responses received" )
        p.append( "# TYPE dnstap_response_udp counter" )
        p.append( "dnstap_response_udp %s" % counters["response/udp"] )
        
        p.append( "# HELP dnstap_responses_tcp Number of TCP responses received" )
        p.append( "# TYPE dnstap_response_tcp counter" )
        p.append( "dnstap_response_tcp %s" % counters["response/tcp"] )
        
        p.append( "# HELP dnstap_response_inet Number of IPv4 responses received" )
        p.append( "# TYPE dnstap_response_inet counter" )
        p.append( "dnstap_response_inet %s" % counters["response/inet"] )
        
        p.append( "# HELP dnstap_response_inet6 Number of IPv6 responses received" )
        p.append( "# TYPE dnstap_response_inet6 counter" )
        p.append( "dnstap_response_inet6 %s" % counters["response/inet6"] )
        
        p.append( "# HELP dnstap_responses_noerror Number of NOERROR answers" )
        p.append( "# TYPE dnstap_responses_noerror counter" )
        p.append( "dnstap_responses_noerror %s" % counters["response/noerror"] )
        
        p.append( "# HELP dnstap_responses_nxdomain Number of NXDomain answers" )
        p.append( "# TYPE dnstap_responses_nxdomain counter" )
        p.append( "dnstap_responses_nxdomain %s" % counters["response/nxdomain"] )
        
        p.append( "# HELP dnstap_responses_serverfail Number of SERVFAIL answers" )
        p.append( "# TYPE dnstap_responses_serverfail counter" )
        p.append( "dnstap_responses_serverfail %s" % counters["response/serverfail"] )
        
        
        for s in self.stats.get_nameslist():
            sub_cntrs = self.stats.get_counters(stream=s, filters=filters)
            
            p.append( "# HELP dnstap_qps Number of queries per second for this dnstap identity" )
            p.append( "# TYPE dnstap_qps counter" )
            
            p.append( "# HELP dnstap_domains Number of domains asked for this dnstap identity" )
            p.append( "# TYPE dnstap_domains counter" )
        
            p.append( "# HELP dnstap_clients Number of clients asked for this dnstap identity" )
            p.append( "# TYPE dnstap_clients counter" )

            p.append( "# HELP dnstap_queries Number of queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries counter" )
            
            p.append( "# HELP dnstap_queries_udp Number of UDP queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_udp counter" )
            
            p.append( "# HELP dnstap_queries_tcp Number of TCP queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_tcp counter" )
            
            p.append( "# HELP dnstap_queries_inet Number of IPv4 queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_inet counter" )
            
            p.append( "# HELP dnstap_queries_inet6 Number of IPv6 queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_inet6 counter" )

            p.append( "# HELP dnstap_queries_a Number of A queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_a counter" )
            
            p.append( "# HELP dnstap_queries_aaaa Number of AAAA queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_aaaa counter" )
            
            p.append( "# HELP dnstap_queries_svr Number of SVR queries received for this dnstap identity" )
            p.append( "# TYPE dnstap_queries_svr counter" )

            p.append( "# HELP dnstap_responses Number of responses received for this dnstap identity" )
            p.append( "# TYPE dnstap_responses counter" )
            
            p.append( "# HELP dnstap_response_udp Number of UDP responses received for this dnstap identity" )
            p.append( "# TYPE dnstap_response_udp counter" )
            
            p.append( "# HELP dnstap_responses_tcp Number of TCP responses received for this dnstap identity" )
            p.append( "# TYPE dnstap_response_tcp counter" )
            
            p.append( "# HELP dnstap_response_inet Number of IPv4 responses received for this dnstap identity" )
            p.append( "# TYPE dnstap_response_inet counter" )
            
            p.append( "# HELP dnstap_response_inet6 Number of IPv6 responses received for this dnstap identity" )
            p.append( "# TYPE dnstap_response_inet6 counter" )
            
            p.append( "# HELP dnstap_responses_noerror Number of NOERROR answers for this dnstap identity" )
            p.append( "# TYPE dnstap_responses_noerror counter" )
            
            p.append( "# HELP dnstap_responses_nxdomain Number of NXDomain answers for this dnstap identity" )
            p.append( "# TYPE dnstap_responses_nxdomain counter" )
            
            p.append( "# HELP dnstap_responses_serverfail Number of SERVFAIL answers for this dnstap identity" )
            p.append( "# TYPE dnstap_responses_serverfail counter" )
            
        
            p.append( "dnstap_qps{identity=\"%s\"} %s" % (s,sub_cntrs["qps"]) )
            p.append( "dnstap_domains{identity=\"%s\"} %s" % (s,sub_cntrs["domains"]) )
            p.append( "dnstap_clients{identity=\"%s\"} %s" % (s,sub_cntrs["clients"]) )
            
            p.append( "dnstap_queries{identity=\"%s\"} %s" % (s,sub_cntrs["query"]) )
            p.append( "dnstap_queries_udp{identity=\"%s\"} %s" % (s,sub_cntrs["query/udp"]) )
            p.append( "dnstap_queries_tcp{identity=\"%s\"} %s" % (s,sub_cntrs["query/tcp"]) )
            p.append( "dnstap_queries_inet{identity=\"%s\"} %s" % (s,sub_cntrs["query/inet"]) )
            p.append( "dnstap_queries_inet6{identity=\"%s\"} %s" % (s,sub_cntrs["query/inet6"]) )
            p.append( "dnstap_queries_a{identity=\"%s\"} %s" % (s,sub_cntrs["query/a"]) )
            p.append( "dnstap_queries_aaaa{identity=\"%s\"} %s" % (s,sub_cntrs["query/aaaa"]) )
            p.append( "dnstap_queries_svr{identity=\"%s\"} %s" % (s,sub_cntrs["query/svr"]) )

            p.append( "dnstap_responses{identity=\"%s\"} %s" % (s,sub_cntrs["response"]) )
            p.append( "dnstap_response_udp{identity=\"%s\"} %s" % (s,sub_cntrs["response/udp"]) )
            p.append( "dnstap_response_tcp{identity=\"%s\"} %s" % (s,sub_cntrs["response/tcp"]) )
            p.append( "dnstap_response_inet{identity=\"%s\"} %s" % (s,sub_cntrs["response/inet"]) )
            p.append( "dnstap_response_inet6{identity=\"%s\"} %s" % (s,sub_cntrs["response/inet6"]) )
            p.append( "dnstap_responses_noerror{identity=\"%s\"} %s" % (s,sub_cntrs["response/noerror"]) )
            p.append( "dnstap_responses_nxdomain{identity=\"%s\"} %s" % (s,sub_cntrs["response/nxdomain"]) )
            p.append( "dnstap_responses_serverfail{identity=\"%s\"} %s" % (s,sub_cntrs["response/serverfail"]) )
            
        return web.Response(text="\n".join(p), content_type='text/plan')
        
    async def handle_counters(self, request):
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
        
    async def handle_tables(self, request):
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
                 "top-domains": self.stats.top_domains(int(n),s, filters=filters),
                 "top-clients": self.stats.top_clients(int(n), s),
                 "top-rcodes": self.stats.top_dnscode(int(n), s, rcode=True),
                 "top-rrtypes": self.stats.top_dnscode(int(n),s, rcode=False) }
        return web.json_response(data)
        
    async def handle_streams(self, request):
        auth = self.check_auth(request=request)
        if not auth:
            return web.Response(status=401)

        data = { "streams": self.stats.get_nameslist() }
        return web.json_response(data)
        
async def create_server(loop, cfg, stats, cfg_stats):
    # api ressources
    basic_auth = BasicAuth(login=cfg["login"], password=cfg["password"])
    hdlrs = Handlers(cfg["api-key"], basic_auth, stats, cfg_stats)
    
    # rest api server
    app = web.Application(loop=loop)
 
    # endpoints
    app.router.add_get('/metrics', hdlrs.handle_metrics)
    app.router.add_get('/tables', hdlrs.handle_tables)
    app.router.add_get('/counters', hdlrs.handle_counters)
    app.router.add_get('/streams', hdlrs.handle_streams)
    app.router.add_delete('/reset', hdlrs.handle_reset)

    # create the server
    listen_address = (cfg["local-address"], cfg["local-port"])
    srv = await loop.create_server(app.make_handler(access_log=None), *listen_address)
    clogger.debug("Api rest: listening on %s:%s" % listen_address )
    
    return srv
