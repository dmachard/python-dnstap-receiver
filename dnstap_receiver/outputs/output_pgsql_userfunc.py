'''
This file contains the default functions of pgsql_init and pgsql_main.
If you feel like replace them, 
  1) copy this file and edit it as you like (but keep function names),
  2) then designate it in the `userfuncefile` in the configuration.
     (See outputs: pgsql: section in ../dnstap.conf)
'''

import logging
clogger = logging.getLogger("dnstap_receiver.console")

async def pgsql_init(conn):
    '''
    pgsql_init is a function which is executed once just after
    creation of asyncpg connection pool (nearly equals to every time 
    when the dnstap_receiver being started).
    It is expected to do something like "CREATE TABLE IF NOT EXISTS..." here.

    `conn` is a connection to PostgreSQL server acquired from pool.
    '''
    clogger.info("pgsql_init: createing table if not exists.")
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

async def pgsql_main(tapmsg, conn):
    '''
    pgsql_main is a function which is executed on each dnstap data delivered.
    It is expected to do something like "INSERT INTO..." here.

    `conn` is a connection to PostgreSQL server acquired from pool.
    `tapmsg` is a dict that contains dnstap data delivered.
    '''
    clogger.info("pgsql_main: inserting data.")
    return await conn.execute("""
        INSERT INTO dnstap_receiver VALUES
            ($1, $2, to_timestamp($3), $4, $5, $6, $7, $8)
        """,
            tapmsg['message'], tapmsg['type']
           ,tapmsg['timestamp'], tapmsg['query-ip']
           ,tapmsg['response-ip'], tapmsg['qname']
           ,tapmsg['rrtype'], tapmsg['rcode']
    )
