import asyncio
import logging

from os.path import abspath,realpath,expanduser,expandvars
from importlib.util import spec_from_file_location, module_from_spec

try:
    import asyncpg
    has_pgsql = True
except:
    has_pgsql = False

clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver.outputs import transform


def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: pgsql")

    valid_conf = True

    if not has_pgsql:
        valid_conf = False
        clogger.error("Output handler: pgsql: asyncpg dependency is missing")

    if cfg["dsn"] is None:
        valid_conf = False
        clogger.error("Output handler: no dsn provided")

    return valid_conf

async def plaintext_pgclient(output_cfg, queue, start_shutdown):
    dsn = output_cfg["dsn"]
    clogger.debug("Output handler: connection to %s" % (dsn,))

    passfile = output_cfg["passfile"]
    min_size = output_cfg["min_size"]
    max_size = output_cfg["max_size"]
    busy_wait = float(output_cfg["busy_wait"])
    userfuncfile = output_cfg["userfuncfile"]

    # importing functions to handle PostgreSQL.
    # pgsql_init shall be executed once just after connection pool
    # to PostgreSQL. Ususally it should contain "CREATE TABLE IF NOT
    # EXISTS..."
    # pgsql_main shall be executed on receiving every DNS queries.
    # Usually it should be "INSERT INTO..."
    # dnstap_receiver has default functions to fall back to, or 
    # user can define his/her own function in the 'userfuncfile'.
    # For example,
    # $ cp output_pgsql_userfunc.py output_pgsql_myfunc.py
    # $ vi output_pgsql_myfunc.py
    # and make 'userfuncfile: /path/to/output_pgsql_myfunc.py' in dnstap.conf
    if userfuncfile is None:
        clogger.debug(f"Output handler: pgsql: loading default userfuncfile.")
        from .output_pgsql_userfunc import pgsql_init, pgsql_main
    else:
        try:
            userfuncfile = abspath(realpath(expandvars(expanduser(userfuncfile))))
            # Should check process euid == file owner ?

            spec = spec_from_file_location('userfunc', userfuncfile)
            userfunc = module_from_spec(spec)
            spec.loader.exec_module(userfunc)
            pgsql_init = userfunc.pgsql_init
            pgsql_main = userfunc.pgsql_main
            clogger.debug(f"Output handler: pgsql: loaded userfunc in {userfuncfile}.")
        except:
            clogger.info("Output handler: pgsql faild to load userfunc. fallback to default.")
            from .output_pgsql_userfunc import pgsql_init, pgsql_main

    # create connection pool to PostgreSQL server.
    async with asyncpg.create_pool(dsn=dsn, passfile=passfile, min_size=min_size, max_size=max_size, timeout=15) as pool:
        clogger.debug("Output handler: pgsql connected")

        # acquire a connection and execute pgsql_init()
        # such as "CREATE TABLE IF NOT EXISTS..."
        async with pool.acquire() as conn:
            async with conn.transaction():
                await pgsql_init(conn)

        # consume queue
        while not start_shutdown.is_set():
            #clogger.debug(f'Output handler: pgsql receiving tapmsg from queue.')
            # 'tapmsg = await queue.get()' will block start_shutdown_task
            # to gracefully shutdown dnstap_receiver itself.
            # 'queue.get_nowait()' won't block but introduces
            # busy-wait-loop instead. which do yo like?
            try:
                tapmsg = queue.get_nowait()
            except asyncio.QueueEmpty as e:
                if start_shutdown.is_set():
                    clogger.debug('Output handler: pgsql shutting down. ')
                    break
                else:
                    await asyncio.sleep(busy_wait)
                    continue
            else:
                clogger.debug(f'Output handler: pgsql received tapmsg: {tapmsg}.')

            # acquire a connection and send 'INSERT...' to PostgreSQL server.
            async with pool.acquire() as conn:
                async with conn.transaction():
                    await pgsql_main(tapmsg, conn)
                    clogger.debug('Output handler: pgsql INSERT dispached.')
    
            # done continue to next item
            queue.task_done()

        clogger.debug(f'Output handler: pgsql closing pool.')

    # something 
    if not start_shutdown.is_set():
        clogger.error("Output handler: pgclient connection lost")

async def handle(output_cfg, queue, metrics, start_shutdown):
    """pgsql reconnect"""
    loop = asyncio.get_event_loop() # do we need this?

    clogger.debug("Output handler: PostgreSQL enabled")

    while not start_shutdown.is_set():
        try:
            await plaintext_pgclient(output_cfg, queue, start_shutdown)
        except ConnectionRefusedError:
            clogger.error('Output handler: connection to pgsql server failed!')
        except asyncio.TimeoutError:
            clogger.error('Output handler: connection to pgsql server timed out!')
        else:
            clogger.error('Output handler: connection to pgsql is closed.')

        if not start_shutdown.is_set():
            clogger.debug("'Output handler: retry to connect every %ss" % output_cfg["retry"])
            await asyncio.sleep(output_cfg["retry"])
