import asyncio
import logging

try:
    import pika
    has_pika = True
except:
    has_pika = False

clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver.outputs import transform


def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: rabbitmq")

    valid_conf = True

    if not has_pika:
        valid_conf = False
        clogger.error("Output handler: rabbitmq: confluent_kafka dependency is missing")

    if cfg["connection"]["username"] is None \
        or cfg["connection"]["password"] is None \
        or cfg["connection"]["host"] is None \
        or cfg["connection"]["port"] is None:
        valid_conf = False
        clogger.error("Output handler: rabbitmq: missing connection details")

    if cfg["queue"] is None:
        valid_conf = False
        clogger.error("Output handler: rabbitmq: no queue provided")

    return valid_conf


async def handle(output_cfg, queue, metrics, start_shutdown):
    credentials = pika.PlainCredentials(
                            output_cfg["connection"]['username'],
                            output_cfg["connection"]['password']
    )
    connection_params = pika.ConnectionParameters(
                            host=output_cfg["connection"]['host'],
                            port=output_cfg["connection"]['port'],
                            credentials=credentials
    )
    try:
        connection = pika.BlockingConnection(connection_params)
    except Exception as pika_e:
        print(pika_e)
        clogger.error("Output handler: rabbitmq: connection failed!!!")
        return

    channel = connection.channel()
    channel.queue_declare(queue=output_cfg["queue"], passive=False, durable=True, exclusive=False, auto_delete=False)

    routing_key = output_cfg.get('routing_key', output_cfg['queue'])

    clogger.info("Output handler: rabbitmq: Enabled")
    while not start_shutdown.is_set():
        try:
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
            clogger.info("Get")
        except asyncio.TimeoutError:
            continue
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        clogger.info("Pushing")
        channel.basic_publish(exchange=output_cfg['exchange'],
                        routing_key=routing_key,
                        body=msg)

        queue.task_done()

    # tell producer to shut down
    clogger.info("Output handler: rabbitmq: Triggering producer shutdown")
