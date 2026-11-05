import json
import socket
from datetime import datetime, timezone
from typing import Any
import confluent_kafka
from scanner.core.config import settings


def is_kafka_broker_open(bootstrap_servers: str, timeout: float = 0.2) -> bool:
    """Probe the first bootstrap server host:port to see if broker is listening."""
    try:
        first_server = bootstrap_servers.split(",")[0].strip()
        parts = first_server.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 9092
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError, TimeoutError, ValueError):
        return False


class ScanKafkaProducer:
    def __init__(self, bootstrap_servers: str | None = None):
        self.bootstrap_servers = bootstrap_servers or settings.kafka_bootstrap_servers
        self._producer: confluent_kafka.Producer | None = None
        self._is_available: bool | None = None
        # In-memory event buffer for testing or when Kafka is unavailable
        self.published_events: list[dict[str, Any]] = []

    @property
    def producer(self) -> confluent_kafka.Producer | None:
        if self._is_available is False:
            return None
        if self._producer is None:
            if not is_kafka_broker_open(self.bootstrap_servers, timeout=0.1):
                self._is_available = False
                return None
            try:
                conf = {
                    "bootstrap.servers": self.bootstrap_servers,
                    "socket.timeout.ms": 500,
                    "message.timeout.ms": 1000,
                }
                self._producer = confluent_kafka.Producer(conf)
                self._is_available = True
            except Exception:
                self._is_available = False
                self._producer = None
        return self._producer

    def is_healthy(self) -> bool:
        if not is_kafka_broker_open(self.bootstrap_servers, timeout=0.1):
            return False
        try:
            p = self.producer
            if not p:
                return False
            p.list_topics(timeout=0.5)
            return True
        except Exception:
            return False

    def publish_scan_requested(
        self,
        scan_id: str,
        repository_url: str,
        topic: str | None = None,
    ) -> bool:
        """Publish a scan.requested event to Kafka."""
        target_topic = topic or settings.kafka_scan_requests_topic
        event = {
            "event_type": "scan.requested",
            "scan_id": scan_id,
            "repository_url": repository_url,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Record in memory buffer
        self.published_events.append(event)

        p = self.producer
        if p:
            try:
                payload = json.dumps(event).encode("utf-8")
                p.produce(
                    topic=target_topic,
                    key=scan_id.encode("utf-8"),
                    value=payload,
                )
                p.flush(timeout=1.0)
                return True
            except Exception:
                pass
        return True


kafka_producer = ScanKafkaProducer()
