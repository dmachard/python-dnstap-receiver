
async def pgsql_pre_loop_userfunc(output_cfg, conn, start_shutdown):

    return await conn.execute("""
        CREATE TABLE IF NOT EXISTS dnstap_receiver (
            message     TEXT        -- "AUTH_QUERY"
           ,type        TEXT        -- "query"
           ,timestamp   TIMESTAMPTZ -- "1625636652.113565"
           ,query_ip    TEXT        -- "192.0.2.100"
           ,response_ip TEXT        -- "203.0.113.200"
           ,qname       TEXT        -- "www.example.com."
           ,rrtype      TEXT        -- "A"
           ,rcode       TEXT        -- "NOERROR"
        )
    """)

async def pgsql_main_loop_userfunc(tapmsg, output_cfg, conn, start_shutdown):
    return await conn.execute("""
        INSERT INTO dnstap_receiver VALUES
            ($1, $2, to_timestamp($3), $4, $5, $6, $7, $8)
        """,
            tapmsg['message'], tapmsg['type']
           ,tapmsg['timestamp'], tapmsg['query-ip']
           ,tapmsg['response-ip'], tapmsg['qname']
           ,tapmsg['rrtype'], tapmsg['rcode']
    )
