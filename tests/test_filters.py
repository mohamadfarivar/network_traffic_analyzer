
import unittest
from datetime import datetime, timezone

from traffic_analyzer.models import PacketRecord # type: ignore
from traffic_analyzer.filters import PacketFilter # type: ignore


TEST_TIME = datetime(
    2026, 10, 30, 10, 0, 0,
    tzinfo=timezone.utc,
)


def make_record(
    source_ip="192.0.2.10",
    destination_ip="198.51.100.20",
    protocol="TCP",
    source_port=52000,
    destination_port=443,
):
    return PacketRecord(
        timestamp=TEST_TIME,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_mac=None,
        destination_mac=None,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        observed_bytes=100,
    )


class TestPacketFilter(unittest.TestCase):

    def test_empty_filter_matches_every_packet(self):
        packet_filter = PacketFilter()

        self.assertTrue(packet_filter.matches(make_record()))
        self.assertFalse(packet_filter.is_active)

    def test_source_ip_filter(self):
        packet_filter = PacketFilter(
            source_ips=frozenset({"192.0.2.10"})
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(source_ip="192.0.2.20")
            )
        )

    def test_destination_ip_filter(self):
        packet_filter = PacketFilter(
            destination_ips=frozenset({"198.51.100.20"})
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(destination_ip="198.51.100.30")
            )
        )

    def test_multiple_source_ips_use_or(self):
        packet_filter = PacketFilter(
            source_ips=frozenset({
                "192.0.2.10",
                "192.0.2.20",
            })
        )

        self.assertTrue(
            packet_filter.matches(
                make_record(source_ip="192.0.2.20")
            )
        )

    def test_protocol_filter_is_case_insensitive(self):
        packet_filter = PacketFilter(
            protocols=frozenset({"tcp"})
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(protocol="UDP")
            )
        )

    def test_multiple_protocols_use_or(self):
        packet_filter = PacketFilter(
            protocols=frozenset({"TCP", "UDP"})
        )

        self.assertTrue(
            packet_filter.matches(make_record(protocol="UDP"))
        )

        self.assertTrue(
            packet_filter.matches(make_record(protocol="TCP"))
        )

    def test_different_filter_categories_use_and(self):
        packet_filter = PacketFilter(
            source_ips=frozenset({"192.0.2.10"}),
            protocols=frozenset({"TCP"}),
            ports=frozenset({443}),
            port_direction="destination",
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(protocol="UDP")
            )
        )

        self.assertFalse(
            packet_filter.matches(
                make_record(source_ip="192.0.2.99")
            )
        )

        self.assertFalse(
            packet_filter.matches(
                make_record(destination_port=80)
            )
        )

    def test_either_port_direction(self):
        packet_filter = PacketFilter(
            ports=frozenset({52000})
        )

        self.assertTrue(packet_filter.matches(make_record()))

    def test_source_port_direction(self):
        packet_filter = PacketFilter(
            ports=frozenset({52000}),
            port_direction="source",
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(source_port=12345, destination_port=52000)
            )
        )

    def test_destination_port_direction(self):
        packet_filter = PacketFilter(
            ports=frozenset({443}),
            port_direction="destination",
        )

        self.assertTrue(packet_filter.matches(make_record()))

        self.assertFalse(
            packet_filter.matches(
                make_record(source_port=443, destination_port=80)
            )
        )

    def test_port_filter_does_not_match_icmp(self):
        packet_filter = PacketFilter(
            ports=frozenset({443})
        )

        self.assertFalse(
            packet_filter.matches(
                make_record(
                    protocol="ICMP",
                    source_port=None,
                    destination_port=None,
                )
            )
        )

    def test_ipv6_address_filter(self):
        packet_filter = PacketFilter(
            source_ips=frozenset({"2001:0db8:0:0:0:0:0:1"})
        )

        record = make_record(
            source_ip="2001:db8::1",
            destination_ip="2001:db8::2",
        )

        self.assertTrue(packet_filter.matches(record))

    def test_invalid_ip_filter(self):
        with self.assertRaises(ValueError):
            PacketFilter(
                source_ips=frozenset({"not-an-ip"})
            )

    def test_invalid_protocol_filter(self):
        with self.assertRaises(ValueError):
            PacketFilter(
                protocols=frozenset({"INVALID"})
            )

    def test_invalid_port_filter(self):
        with self.assertRaises(ValueError):
            PacketFilter(ports=frozenset({70000}))

        with self.assertRaises(ValueError):
            PacketFilter(ports=frozenset({-1}))

    def test_invalid_direction(self):
        with self.assertRaises(ValueError):
            PacketFilter(port_direction="unknown")


if __name__ == "__main__":
    unittest.main()
