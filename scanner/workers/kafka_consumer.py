import json
import logging
from typing import Any
import confluent_kafka
from scanner.core.config import settings
from scanner.workers.scan_worker import ScanWorker

logger = logging.getLogger(__name__)


class ScanKafkaConsumer:
    def __init__(
        self,
        bootstrap_servers: str | None = None,
        group_id: str | None = None,
        worker: ScanWorker | None = None,
        max_retries: int = 3,
    ):
        self.bootstrap_servers = bootstrap_servers or settings.kafka_bootstrap_servers
        self.group_id = group_id or settings.kafka_consumer_group
        self.worker = worker or ScanWorker()
        self.max_retries = max_retries
        self._consumer: confluent_kafka.Consumer | None = None
        self._retry_counts: dict[str, int] = {}
        self.deadletter_events: list[dict[str, Any]] = []

    def get_consumer(self) -> confluent_kafka.Consumer | None:
        if self._consumer is None:
            try:
                conf = {
                    "bootstrap.servers": self.bootstrap_servers,
                    "group.id": self.group_id,
                    "auto.offset.reset": "earliest",
                    "enable.auto.commit": True,
                }
                c = confluent_kafka.Consumer(conf)
                c.subscribe([settings.kafka_scan_requests_topic])
                self._consumer = c
            except Exception as err:
                logger.warning(f"Could not connect Kafka consumer: {err}")
                self._consumer = None
        return self._consumer

    def process_message(self, message_data: dict[str, Any]) -> bool:
        """Process a single deserialized scan request event with retry & DLQ handling."""
        scan_id = message_data.get("scan_id")
        repo_url = message_data.get("repository_url")

        if not scan_id or not repo_url:
            logger.error("Malformed scan event received without scan_id or repository_url")
            return False

        try:
            success = self.worker.process_scan_job(scan_id, repo_url)
            if success:
                self._retry_counts.pop(scan_id, None)
                return True

            # If worker returned False, handle retry
            retries = self._retry_counts.get(scan_id, 0) + 1
            self._retry_counts[scan_id] = retries
            if retries >= self.max_retries:
                logger.error(f"Scan job {scan_id} exceeded max retries. Routing to deadletter.")
                self.deadletter_events.append(message_data)
                return False
            return False

        except Exception as err:
            logger.error(f"Exception processing scan {scan_id}: {err}")
            retries = self._retry_counts.get(scan_id, 0) + 1
            self._retry_counts[scan_id] = retries
            if retries >= self.max_retries:
                self.deadletter_events.append(message_data)
            return False

    def poll_and_process_once(self, timeout: float = 1.0) -> bool:
        """Poll one message from Kafka (if connected) and process it."""
        consumer = self.get_consumer()
        if not consumer:
            return False

        msg = consumer.poll(timeout)
        if msg is None:
            return False
        if msg.error():
            logger.warning(f"Kafka consumer error: {msg.error()}")
            return False

        try:
            payload = json.loads(msg.value().decode("utf-8"))
            return self.process_message(payload)
        except Exception as err:
            logger.error(f"Failed to decode Kafka message payload: {err}")
            return False

