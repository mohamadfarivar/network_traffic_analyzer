
import unittest
from datetime import datetime, timedelta, timezone

from traffic_analyzer.models import PacketRecord # type: ignore
from traffic_analyzer.statistics import TrafficStatistics # type: ignore


BASE_TIME = datetime(
    2026, 10, 30, 10, 0, 0,
    tzinfo=timezone.utc,
)


def make_record(
    protocol="TCP",
    source_ip="192.0.2.10",
    destination_ip="198.51.100.20",
    source_port=50000,
    destination_port=443,
    observed_bytes=100,
    timestamp=BASE_TIME,
):
    """Create a synthetic PacketRecord for testing."""
    return PacketRecord(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_mac=None,
        destination_mac=None,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        observed_bytes=observed_bytes,
    )


class TestTrafficStatistics(unittest.TestCase):

    def setUp(self):
        self.statistics = TrafficStatistics()

    def test_total_packets_and_bytes(self):
        self.statistics.add(make_record(observed_bytes=100))
        self.statistics.add(make_record(observed_bytes=200))
        self.statistics.add(
            make_record(protocol="UDP", observed_bytes=80)
        )

        self.assertEqual(self.statistics.total_packets, 3)
        self.assertEqual(self.statistics.total_observed_bytes, 380)

    def test_protocol_statistics(self):
        self.statistics.add(make_record(observed_bytes=100))
        self.statistics.add(make_record(observed_bytes=200))
        self.statistics.add(
            make_record(protocol="UDP", observed_bytes=80)
        )

        expected = {
            "TCP": {
                "packets": 2,
                "observed_bytes": 300,
            },
            "UDP": {
                "packets": 1,
                "observed_bytes": 80,
            },
        }

        self.assertEqual(
            self.statistics.protocol_summary(),
            expected,
        )

    def test_top_source_and_destination_ips(self):
        self.statistics.add(
            make_record(
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
            )
        )

        self.statistics.add(
            make_record(
                source_ip="192.0.2.10",
                destination_ip="198.51.100.30",
            )
        )

        self.statistics.add(
            make_record(
                source_ip="192.0.2.20",
                destination_ip="198.51.100.20",
            )
        )

        self.assertEqual(
            self.statistics.top_source_ips(),
            [("192.0.2.10", 2), ("192.0.2.20", 1)],
        )

        self.assertEqual(
            self.statistics.top_destination_ips(),
            [("198.51.100.20", 2), ("198.51.100.30", 1)],
        )

    def test_top_tcp_and_udp_ports(self):
        self.statistics.add(
            make_record(
                protocol="TCP",
                source_port=50000,
                destination_port=443,
            )
        )

        self.statistics.add(
            make_record(
                protocol="TCP",
                source_port=50000,
                destination_port=443,
            )
        )

        self.statistics.add(
            make_record(
                protocol="TCP",
                source_port=50001,
                destination_port=80,
            )
        )

        self.statistics.add(
            make_record(
                protocol="UDP",
                source_port=53000,
                destination_port=53,
            )
        )

        self.assertEqual(
            self.statistics.top_ports("TCP", "destination"),
            [(443, 2), (80, 1)],
        )

        self.assertEqual(
            self.statistics.top_ports("TCP", "source"),
            [(50000, 2), (50001, 1)],
        )

        self.assertEqual(
            self.statistics.top_ports("UDP", "destination"),
            [(53, 1)],
        )

    def test_endpoint_pair_statistics(self):
        self.statistics.add(
            make_record(
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
                observed_bytes=100,
            )
        )

        self.statistics.add(
            make_record(
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
                observed_bytes=120,
            )
        )

        self.statistics.add(
            make_record(
                source_ip="192.0.2.10",
                destination_ip="198.51.100.30",
                observed_bytes=200,
            )
        )

        self.assertEqual(
            self.statistics.top_endpoint_pairs(),
            [
                ("192.0.2.10", "198.51.100.20", 2, 220),
                ("192.0.2.10", "198.51.100.30", 1, 200),
            ],
        )

    def test_time_buckets_and_rates(self):
        self.statistics.add(
            make_record(
                observed_bytes=100,
                timestamp=BASE_TIME + timedelta(seconds=0.1),
            )
        )

        self.statistics.add(
            make_record(
                observed_bytes=200,
                timestamp=BASE_TIME + timedelta(seconds=0.7),
            )
        )

        self.statistics.add(
            make_record(
                observed_bytes=80,
                timestamp=BASE_TIME + timedelta(seconds=1.1),
            )
        )

        series = self.statistics.time_series()

        self.assertEqual(len(series), 2)

        self.assertEqual(series[0].packets, 2)
        self.assertEqual(series[0].observed_bytes, 300)
        self.assertEqual(series[0].packets_per_second, 2.0)
        self.assertEqual(series[0].bytes_per_second, 300.0)

        self.assertEqual(series[1].packets, 1)
        self.assertEqual(series[1].observed_bytes, 80)

    def test_missing_and_naive_timestamps(self):
        self.statistics.add(
            make_record(timestamp=None)
        )

        self.statistics.add(
            make_record(
                timestamp=BASE_TIME.replace(tzinfo=None)
            )
        )

        self.assertEqual(self.statistics.total_packets, 2)
        self.assertEqual(
            self.statistics.packets_without_usable_timestamp,
            2,
        )
        self.assertEqual(self.statistics.time_series(), [])

    def test_time_bucket_retention(self):
        statistics = TrafficStatistics(max_time_buckets=2)

        for seconds in range(3):
            statistics.add(
                make_record(
                    timestamp=BASE_TIME + timedelta(seconds=seconds),
                )
            )

        self.assertEqual(statistics.total_packets, 3)

        series = statistics.time_series()

        self.assertEqual(len(series), 2)
        self.assertEqual(
            series[0].interval_start,
            BASE_TIME + timedelta(seconds=1),
        )
        self.assertEqual(
            series[1].interval_start,
            BASE_TIME + timedelta(seconds=2),
        )

    def test_invalid_observed_bytes(self):
        record = make_record(observed_bytes=-10)

        with self.assertRaises(ValueError):
            self.statistics.add(record)

        self.assertEqual(self.statistics.total_packets, 0)

    def test_invalid_port_query(self):
        with self.assertRaises(ValueError):
            self.statistics.top_ports("ICMP")

        with self.assertRaises(ValueError):
            self.statistics.top_ports("TCP", "invalid")

        with self.assertRaises(ValueError):
            self.statistics.top_source_ips(0)

    def test_empty_statistics(self):
        self.assertEqual(self.statistics.total_packets, 0)
        self.assertEqual(self.statistics.total_observed_bytes, 0)
        self.assertEqual(self.statistics.protocol_summary(), {})
        self.assertEqual(self.statistics.top_source_ips(), [])
        self.assertEqual(self.statistics.top_destination_ips(), [])
        self.assertEqual(self.statistics.time_series(), [])


if __name__ == "__main__":
    unittest.main()
