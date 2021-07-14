import asyncio
import logging

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
    userfuncfile = output_cfg["userfuncfile"]

    if userfuncfile is None:
        from .output_pgsql_userfunc import pgsql_pre_loop_userfunc, pgsql_main_loop_userfunc
    else:
        try:
            from os.path import abspath,expanduser,expandvars
            userfuncfile = abspath(expandvars(expanduser(userfuncfile)))
            clogger.debug(f"Output handler: pgsql: loading userfuncfile={userfuncfile}")
            from importlib.util import spec_from_file_location, module_from_spec
            clogger.debug(f"Output handler: pgsql: funcs in importlib.util imported.")
            spec = spec_from_file_location('userfunc', userfuncfile)
            clogger.debug(f"Output handler: pgsql: spec={spec}")
            userfunc = module_from_spec(spec)
            clogger.debug(f"Output handler: pgsql: userfunc={userfunc}")
            spec.loader.exec_module(userfunc)
            clogger.debug(f"Output handler: pgsql: userfunc={userfunc}")
            pgsql_pre_loop_userfunc  = userfunc.pgsql_pre_loop_userfunc
            pgsql_main_loop_userfunc = userfunc.pgsql_main_loop_userfunc
        except:
            clogger.info("Output handler: pgsql faild to load userfunc. fallback to default.")
            from .output_pgsql_userfunc import pgsql_pre_loop_userfunc, pgsql_main_loop_userfunc

    async with asyncpg.create_pool(dsn=dsn, passfile=passfile, min_size=min_size, max_size=max_size) as pool:
        clogger.debug("Output handler: pgsql connected")

        ### CREATE TABLE IF NOT EXISTS
        async with pool.acquire() as conn:
            async with conn.transaction():
                await pgsql_pre_loop_userfunc(output_cfg, conn, start_shutdown)

        # consume queue
        while not start_shutdown.is_set():
            clogger.debug(f'Output handler: pgsql receiving tapmsg from queue.')
            # read item from queue
            tapmsg = await queue.get()
            clogger.debug(f'Output handler: pgsql received tapmsg: {tapmsg}.')

            if start_shutdown.is_set():
                clogger.debug('Output handler: pgsql shutting down. ')
                pool.close()
                break

            async with pool.acquire() as conn:
                clogger.debug('Output handler: pgsql conn acquired.')
                async with conn.transaction():
                    clogger.debug('Output handler: pgsql transaction began.')
                    await pgsql_main_loop_userfunc(tapmsg, output_cfg, conn, start_shutdown)
                    clogger.debug('Output handler: pgsql INSERT dispached.')
    
            clogger.debug(f'Output handler: pgsql conn released.')
            # done continue to next item
            queue.task_done()

    # something 
    if not start_shutdown.is_set():
        clogger.error("Output handler: pgclient connection lost")

async def handle(output_cfg, queue, metrics, start_shutdown):
    """pgsql reconnect"""
    loop = asyncio.get_event_loop()

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
