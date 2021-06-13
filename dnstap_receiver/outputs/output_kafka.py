import asyncio
import logging
import threading

try:
    import confluent_kafka
    has_kafka = True
except:
    has_kafka = False

clogger = logging.getLogger("dnstap_receiver.console")

from dnstap_receiver.outputs import transform


class Producer:
    def __init__(self, config, topic, start_shutdown):
        self.loop = asyncio.get_event_loop()
        self.producer = confluent_kafka.Producer(config)
        self.topic = topic
        self.start_shutdown = start_shutdown

        self.polling_task = asyncio.create_task(self.polling_task())


    async def polling_task(self):
        while not self.start_shutdown.is_set():
            await asyncio.to_thread(self.producer.poll, 1)

        clogger.debug("Output handler: kafka: performing last flush")
        self.producer.flush()
        clogger.info("Output handler: kafka: polling task stopped")


    def produce(self, value):
        self.producer.produce(self.topic, value)
        self.producer.poll(0)


def checking_conf(cfg):
    """validate the config"""
    clogger.debug("Output handler: kafka")

    valid_conf = True

    if not has_kafka:
        valid_conf = False
        clogger.error("Output handler: kafka: confluent_kafka dependency is missing")

    if cfg["rdkafka-config"]["bootstrap.servers"] is None:
        valid_conf = False
        clogger.error("Output handler: kafka: no bootstrap.servers provided")

    if cfg["topic"] is None:
        valid_conf = False
        clogger.error("Output handler: kafka: no topic provided")

    return valid_conf


async def handle(output_cfg, queue, metrics, start_shutdown):
    start_shutdown_producer = asyncio.Event()
    producer = Producer(output_cfg['rdkafka-config'], output_cfg['topic'], start_shutdown_producer)

    clogger.info("Output handler: kafka: Enabled")
    while not start_shutdown.is_set():
        try:
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)

        producer.produce(msg)
        queue.task_done()

    # tell producer to shut down
    clogger.info("Output handler: kafka: Triggering producer shutdown")
    start_shutdown_producer.set()
