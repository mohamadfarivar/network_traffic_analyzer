import unittest
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from traffic_analyzer.models import PacketRecord
from traffic_analyzer.packet_parser import parse_packet


TEST_TIMESTAMP = 1_761_636_600.0


class TestPacketParser(unittest.TestCase):
    def parse_test_packet(self, packet):
        """Give a synthetic packet a reproducible timestamp."""
        packet.time = TEST_TIMESTAMP
        return parse_packet(packet)

    def test_ipv4_tcp_packet(self):
        packet = (
            Ether(
                src="02:00:00:00:00:01",
                dst="02:00:00:00:00:02",
            )
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=53000, dport=443)
            / Raw(load=b"test")
        )

        record = self.parse_test_packet(packet)

        self.assertIsInstance(record, PacketRecord)
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.source_ip, "192.0.2.10")
        self.assertEqual(record.destination_ip, "198.51.100.20")
        self.assertEqual(record.source_mac, "02:00:00:00:00:01")
        self.assertEqual(record.destination_mac, "02:00:00:00:00:02")
        self.assertEqual(record.source_port, 53000)
        self.assertEqual(record.destination_port, 443)
        self.assertEqual(record.observed_bytes, len(packet))
        self.assertEqual(
            record.timestamp,
            datetime.fromtimestamp(
                TEST_TIMESTAMP,
                tz=timezone.utc,
            ),
        )

    def test_ipv6_udp_packet(self):
        packet = (
            Ether()
            / IPv6(
                src="2001:db8::1",
                dst="2001:db8::2",
            )
            / UDP(sport=50000, dport=53)
            / Raw(load=b"test")
        )

        record = self.parse_test_packet(packet)

        self.assertEqual(record.protocol, "UDP")
        self.assertEqual(record.source_ip, "2001:db8::1")
        self.assertEqual(record.destination_ip, "2001:db8::2")
        self.assertEqual(record.source_port, 50000)
        self.assertEqual(record.destination_port, 53)

    def test_icmp_has_no_transport_ports(self):
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / ICMP()
        )

        record = self.parse_test_packet(packet)

        self.assertEqual(record.protocol, "ICMP")
        self.assertIsNone(record.source_port)
        self.assertIsNone(record.destination_port)

    def test_icmpv6_is_classified(self):
        packet = (
            IPv6(src="2001:db8::1", dst="2001:db8::2")
            / ICMPv6EchoRequest()
        )

        record = self.parse_test_packet(packet)

        self.assertEqual(record.protocol, "ICMPv6")
        self.assertIsNone(record.source_port)
        self.assertIsNone(record.destination_port)

    def test_arp_addresses(self):
        packet = (
            Ether(
                src="02:00:00:00:00:01",
                dst="ff:ff:ff:ff:ff:ff",
            )
            / ARP(
                op=1,
                hwsrc="02:00:00:00:00:01",
                psrc="192.0.2.10",
                hwdst="00:00:00:00:00:00",
                pdst="192.0.2.1",
            )
        )

        record = self.parse_test_packet(packet)

        self.assertEqual(record.protocol, "ARP")
        self.assertEqual(record.source_ip, "192.0.2.10")
        self.assertEqual(record.destination_ip, "192.0.2.1")
        self.assertEqual(record.source_mac, "02:00:00:00:00:01")
        self.assertEqual(record.destination_port, None)

    def test_unknown_ethernet_payload(self):
        packet = Ether() / Raw(load=b"opaque data")

        record = self.parse_test_packet(packet)

        self.assertEqual(record.protocol, "Ethernet-other")
        self.assertIsNone(record.source_ip)
        self.assertIsNone(record.destination_ip)

    def test_missing_timestamp_is_handled(self):
        packet = Ether() / IP(
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        packet.time = float("nan")

        record = parse_packet(packet)

        self.assertIsNone(record.timestamp)
        self.assertEqual(record.protocol, "IPv4-other")


if __name__ == "__main__":
    unittest.main()