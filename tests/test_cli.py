
import unittest

from traffic_analyzer.cli import ( # type: ignore
    build_parser,
    create_packet_filter,
    parse_ip_address,
    parse_port,
    parse_protocol,
    positive_float,
    positive_int,
)


class TestCLI(unittest.TestCase):

    def test_default_arguments(self):
        parser = build_parser()

        args = parser.parse_args([
            "--interface",
            "test-interface",
        ])

        self.assertEqual(args.interface, "test-interface")
        self.assertEqual(args.interval, 1.0)
        self.assertEqual(args.top, 5)
        self.assertFalse(args.quiet)

    def test_repeated_filter_arguments(self):
        parser = build_parser()

        args = parser.parse_args([
            "--interface", "test-interface",
            "--src-ip", "192.0.2.10",
            "--src-ip", "192.0.2.20",
            "--dst-ip", "198.51.100.20",
            "--protocol", "tcp",
            "--protocol", "udp",
            "--port", "443",
            "--port", "80",
            "--port-direction", "destination",
        ])

        packet_filter = create_packet_filter(args)

        self.assertEqual(
            packet_filter.source_ips,
            frozenset({"192.0.2.10", "192.0.2.20"}),
        )

        self.assertEqual(
            packet_filter.destination_ips,
            frozenset({"198.51.100.20"}),
        )

        self.assertEqual(
            packet_filter.protocols,
            frozenset({"TCP", "UDP"}),
        )

        self.assertEqual(
            packet_filter.ports,
            frozenset({443, 80}),
        )

        self.assertEqual(
            packet_filter.port_direction,
            "destination",
        )

    def test_ip_address_validation(self):
        self.assertEqual(
            parse_ip_address("192.0.2.10"),
            "192.0.2.10",
        )

        self.assertEqual(
            parse_ip_address("2001:0db8::1"),
            "2001:db8::1",
        )

        with self.assertRaises(Exception):
            parse_ip_address("invalid-address")

    def test_port_validation(self):
        self.assertEqual(parse_port("443"), 443)
        self.assertEqual(parse_port("0"), 0)
        self.assertEqual(parse_port("65535"), 65535)

        with self.assertRaises(Exception):
            parse_port("70000")

        with self.assertRaises(Exception):
            parse_port("-1")

        with self.assertRaises(Exception):
            parse_port("not-a-port")

    def test_protocol_validation(self):
        self.assertEqual(parse_protocol("tcp"), "TCP")
        self.assertEqual(parse_protocol("icmpv6"), "ICMPV6")

        with self.assertRaises(Exception):
            parse_protocol("INVALID")

    def test_positive_integer_validation(self):
        self.assertEqual(positive_int("10"), 10)

        with self.assertRaises(Exception):
            positive_int("0")

        with self.assertRaises(Exception):
            positive_int("-5")

    def test_positive_float_validation(self):
        self.assertEqual(positive_float("2.5"), 2.5)

        with self.assertRaises(Exception):
            positive_float("0")

        with self.assertRaises(Exception):
            positive_float("nan")

        with self.assertRaises(Exception):
            positive_float("inf")

    def test_port_direction_requires_port(self):
        parser = build_parser()

        args = parser.parse_args([
            "--interface", "test-interface",
            "--port-direction", "source",
        ])

        with self.assertRaises(ValueError):
            create_packet_filter(args)


if __name__ == "__main__":
    unittest.main()
