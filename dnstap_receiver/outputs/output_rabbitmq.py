import asyncio
import logging
import time

from dnstap_receiver.outputs import transform
from dnstap_receiver import statistics

try:
    import pika
    has_pika = True
except:
    has_pika = False

clogger = logging.getLogger("dnstap_receiver.console")


def checking_conf(cfg: dict) -> bool:
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

    if cfg["queue"]["queue"] is None:
        valid_conf = False
        clogger.error("Output handler: rabbitmq: no queue provided")

    return valid_conf


class RabbitMQ:
    """Class to handle RabbitMQ connections and channel push"""

    def __init__(self, output_cfg: dict) -> None:
        self.cfg = output_cfg
        self.cfg["routing_key"] = output_cfg.get("routing_key", output_cfg["queue"]["queue"])

        self.connection: pika.BlockingConnection = None
        self.channel: pika.adapters.blocking_connection.BlockingChannel = None

        self.credentials = pika.PlainCredentials(
                                self.cfg["connection"]["username"],
                                self.cfg["connection"]["password"]
        )
        self.connection_params = pika.ConnectionParameters(
                                host=self.cfg["connection"]["host"],
                                port=self.cfg["connection"]["port"],
                                credentials=self.credentials
        )
        self.init_connection()

    def init_connection(self) -> None:
        """init connection and channel"""
        if self.connection and self.connection.is_open:
            return

        self.connection = pika.BlockingConnection(self.connection_params)

        self.channel = self.connection.channel()
        self.channel.queue_declare(
                    queue       =   self.cfg["queue"]["queue"],
                    passive     =   self.cfg["queue"]["passive"],
                    durable     =   self.cfg["queue"]["durable"],
                    exclusive   =   self.cfg["queue"]["exclusive"],
                    auto_delete =   self.cfg["queue"]["auto_delete"]
        )


    def publish(self, msg) -> None:
        """publish msg to the channel"""
        for attempt in range(self.cfg['retry-count']):
            try:
                self.init_connection()
                clogger.debug("RabbitMQ publish")
                self.channel.basic_publish(
                                exchange=self.cfg["exchange"],
                                routing_key=self.cfg["routing_key"],
                                body=msg
                )
            except (pika.exceptions.ConnectionClosed,
                    pika.exceptions.StreamLostError,
                    pika.exceptions.ChannelWrongStateError,
                    ConnectionResetError
                    ) as connection_error:
                clogger.debug(connection_error)
                clogger.debug(f"Publish failed, trying to reconnect, attepmt {attempt +1}")
                time.sleep(self.cfg['retry-delay'])
            else:
                break
        else:
            clogger.error(f"Publish failed. Connection error after {self.cfg['retry-count']}")


    def close_connection(self):
        """properly close the connection"""
        if self.connection and self.connection.is_open:
            self.connection.close()



async def handle(output_cfg: dict, queue: asyncio.Queue, _metrics: statistics.Statistics, start_shutdown: asyncio.Event):
    """Connect to rabbit and push the messages from the queue"""

    rabbitmq = RabbitMQ(output_cfg=output_cfg)
    clogger.info("Output handler: rabbitmq: Enabled")
    while not start_shutdown.is_set():
        try:
            tapmsg = await asyncio.wait_for(queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        msg = transform.convert_dnstap(fmt=output_cfg["format"], tapmsg=tapmsg)
        rabbitmq.publish(msg)
        queue.task_done()

    # tell producer to shut down
    clogger.info("Output handler: rabbitmq: Triggering producer shutdown")
    rabbitmq.close_connection()
