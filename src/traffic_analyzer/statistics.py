
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from heapq import heappop, heappush
import math
from typing import Literal

from .models import PacketRecord


PortDirection = Literal["source", "destination"]


@dataclass(frozen=True, slots=True)
class TrafficRate:
    """Statistics for one fixed-duration time bucket."""

    interval_start: datetime
    packets: int
    observed_bytes: int
    packets_per_second: float
    bytes_per_second: float


@dataclass(slots=True)
class _BucketTotals:
    """Mutable counters for one internal time bucket."""

    packets: int = 0
    observed_bytes: int = 0


class TrafficStatistics:
    """Collect incremental statistics from parsed packet records."""

    def __init__(
        self,
        interval_seconds: float = 1.0,
        max_time_buckets: int = 3600,
    ) -> None:
        if (
            isinstance(interval_seconds, bool)
            or not isinstance(interval_seconds, (int, float))
            or not math.isfinite(interval_seconds)
            or interval_seconds <= 0
        ):
            raise ValueError(
                "Interval must be a finite positive number."
            )

        if (
            isinstance(max_time_buckets, bool)
            or not isinstance(max_time_buckets, int)
            or max_time_buckets <= 0
        ):
            raise ValueError(
                "Maximum time buckets must be a positive integer."
            )

        self.interval_seconds = float(interval_seconds)
        self.max_time_buckets = max_time_buckets

        # Overall counters
        self.total_packets = 0
        self.total_observed_bytes = 0
        self.packets_without_usable_timestamp = 0

        # Protocol statistics
        self._protocol_packets: Counter[str] = Counter()
        self._protocol_bytes: Counter[str] = Counter()

        # IP address statistics
        self._source_ips: Counter[str] = Counter()
        self._destination_ips: Counter[str] = Counter()

        # Transport port statistics
        self._source_ports: dict[str, Counter[int]] = {
            "TCP": Counter(),
            "UDP": Counter(),
        }

        self._destination_ports: dict[str, Counter[int]] = {
            "TCP": Counter(),
            "UDP": Counter(),
        }

        # Directional source-IP -> destination-IP statistics
        self._endpoint_pair_packets: Counter[
            tuple[str, str]
        ] = Counter()

        self._endpoint_pair_bytes: Counter[
            tuple[str, str]
        ] = Counter()

        # Time-series storage
        self._time_buckets: dict[int, _BucketTotals] = {}
        self._bucket_heap: list[int] = []

    @staticmethod
    def _valid_port(port: int | None) -> bool:
        """Check that a port is an integer in the TCP/UDP range."""
        return (
            isinstance(port, int)
            and not isinstance(port, bool)
            and 0 <= port <= 65535
        )

    @staticmethod
    def _valid_address(address: str | None) -> bool:
        """Check whether an endpoint address is available."""
        return (
            isinstance(address, str)
            and bool(address.strip())
        )

    def add(self, record: PacketRecord) -> None:
        """Add one parsed packet record to all applicable counters."""
        if not isinstance(record, PacketRecord):
            raise TypeError("Expected a PacketRecord instance.")

        if (
            isinstance(record.observed_bytes, bool)
            or not isinstance(record.observed_bytes, int)
            or record.observed_bytes < 0
        ):
            raise ValueError(
                "Observed bytes must be a non-negative integer."
            )

        if (
            not isinstance(record.protocol, str)
            or not record.protocol.strip()
        ):
            raise ValueError("Protocol must be a non-empty string.")

        protocol = record.protocol.strip().upper()
        observed_bytes = record.observed_bytes

        # 1. Overall statistics
        self.total_packets += 1
        self.total_observed_bytes += observed_bytes

        # 2. Protocol statistics
        self._protocol_packets[protocol] += 1
        self._protocol_bytes[protocol] += observed_bytes

        # 3. IP statistics
        source_ip = (
            record.source_ip
            if self._valid_address(record.source_ip)
            else None
        )

        destination_ip = (
            record.destination_ip
            if self._valid_address(record.destination_ip)
            else None
        )

        if source_ip is not None:
            self._source_ips[source_ip] += 1

        if destination_ip is not None:
            self._destination_ips[destination_ip] += 1

        # 4. Endpoint-pair statistics
        if source_ip is not None and destination_ip is not None:
            pair = (source_ip, destination_ip)

            self._endpoint_pair_packets[pair] += 1
            self._endpoint_pair_bytes[pair] += observed_bytes

        # 5. TCP/UDP port statistics
        if protocol in ("TCP", "UDP"):
            source_port = record.source_port
            destination_port = record.destination_port

            if self._valid_port(source_port):
                self._source_ports[protocol][source_port] += 1

            if self._valid_port(destination_port):
                self._destination_ports[protocol][
                    destination_port
                ] += 1

        # 6. Time-series statistics
        self._add_time_bucket(record.timestamp, observed_bytes)

    def _add_time_bucket(
        self,
        timestamp: datetime | None,
        observed_bytes: int,
    ) -> None:
        """Add a packet to its corresponding UTC time bucket."""
        if timestamp is None:
            self.packets_without_usable_timestamp += 1
            return

        try:
            # Naive timestamps have no reliable timezone information.
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                self.packets_without_usable_timestamp += 1
                return

            epoch_seconds = timestamp.timestamp()

            if not math.isfinite(epoch_seconds):
                self.packets_without_usable_timestamp += 1
                return

            bucket_index = math.floor(
                epoch_seconds / self.interval_seconds
            )

        except (AttributeError, OSError, OverflowError, TypeError, ValueError):
            self.packets_without_usable_timestamp += 1
            return

        bucket = self._time_buckets.get(bucket_index)

        if bucket is None:
            bucket = _BucketTotals()
            self._time_buckets[bucket_index] = bucket

            heappush(self._bucket_heap, bucket_index)

            # Discard the oldest time buckets when the limit is reached.
            while len(self._time_buckets) > self.max_time_buckets:
                oldest_index = heappop(self._bucket_heap)
                self._time_buckets.pop(oldest_index, None)

        # A late-arriving packet can belong to a bucket that was
        # immediately discarded because it is older than our retention.
        if self._time_buckets.get(bucket_index) is None:
            return

        bucket.packets += 1
        bucket.observed_bytes += observed_bytes

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """Validate the number of top results requested."""
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("Limit must be a positive integer.")

    def protocol_summary(self) -> dict[str, dict[str, int]]:
        """Return packet and observed-byte totals by protocol."""
        return {
            protocol: {
                "packets": self._protocol_packets[protocol],
                "observed_bytes": self._protocol_bytes[protocol],
            }
            for protocol in sorted(self._protocol_packets)
        }

    def top_source_ips(
        self,
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """Return source IP addresses ordered by packet count."""
        self._validate_limit(limit)
        return self._source_ips.most_common(limit)

    def top_destination_ips(
        self,
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """Return destination IP addresses ordered by packet count."""
        self._validate_limit(limit)
        return self._destination_ips.most_common(limit)

    def top_ports(
        self,
        protocol: str,
        direction: PortDirection = "destination",
        limit: int = 5,
    ) -> list[tuple[int, int]]:
        """Return the most frequently observed TCP/UDP ports."""
        self._validate_limit(limit)

        protocol = protocol.strip().upper()
        direction = direction.lower()

        if protocol not in ("TCP", "UDP"):
            raise ValueError("Protocol must be TCP or UDP.")

        if direction not in ("source", "destination"):
            raise ValueError(
                "Direction must be source or destination."
            )

        if direction == "source":
            counter = self._source_ports[protocol]
        else:
            counter = self._destination_ports[protocol]

        return counter.most_common(limit)

    def top_endpoint_pairs(
        self,
        limit: int = 5,
    ) -> list[tuple[str, str, int, int]]:
        """Return directional IP pairs ordered by packet count.

        Each result contains:
        source IP, destination IP, packet count, observed bytes.
        """
        self._validate_limit(limit)

        results = []

        for (source, destination), packet_count in (
            self._endpoint_pair_packets.most_common(limit)
        ):
            observed_bytes = self._endpoint_pair_bytes[
                (source, destination)
            ]

            results.append(
                (source, destination, packet_count, observed_bytes)
            )

        return results

    def time_series(self) -> list[TrafficRate]:
        """Return retained time buckets in chronological order."""
        results = []

        for bucket_index in sorted(self._time_buckets):
            bucket = self._time_buckets[bucket_index]

            interval_start = datetime.fromtimestamp(
                bucket_index * self.interval_seconds,
                tz=timezone.utc,
            )

            results.append(
                TrafficRate(
                    interval_start=interval_start,
                    packets=bucket.packets,
                    observed_bytes=bucket.observed_bytes,
                    packets_per_second=(
                        bucket.packets / self.interval_seconds
                    ),
                    bytes_per_second=(
                        bucket.observed_bytes / self.interval_seconds
                    ),
                )
            )

        return results
