import argparse
import ipaddress
import logging
import math
import sys

from dataclasses import dataclass
from scapy.packet import Packet # type: ignore

from .capture import capture_packets, get_interfaces
from .filters import PacketFilter, SUPPORTED_PROTOCOLS
from .models import PacketRecord
from .packet_parser import parse_packet
from .statistics import TrafficStatistics


logger = logging.getLogger(__name__)


@dataclass
class ProcessingSummary:
    """Track packet processing outcomes during a capture."""

    parsed_packets: int = 0
    filtered_packets: int = 0
    parse_errors: int = 0
    statistics_errors: int = 0
    analyzed_packets: int = 0


def positive_int(value: str) -> int:
    """Parse a positive integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Value must be a whole number."
        ) from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be greater than zero."
        )

    return number


def positive_float(value: str) -> float:
    """Parse a finite positive floating-point number."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Value must be a number."
        ) from exc

    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError(
            "Value must be finite and greater than zero."
        )

    return number


def parse_ip_address(value: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid IP address: {value}"
        ) from exc


def parse_port(value: str) -> int:
    """Validate a TCP/UDP port number."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Port must be an integer."
        ) from exc

    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            "Port must be between 0 and 65535."
        )

    return port


def parse_protocol(value: str) -> str:
    """Validate and normalize a supported protocol name."""
    protocol = value.strip().upper()

    if protocol not in SUPPORTED_PROTOCOLS:
        raise argparse.ArgumentTypeError(
            f"Unsupported protocol: {value}. "
            f"Supported protocols: {', '.join(sorted(SUPPORTED_PROTOCOLS))}"
        )

    return protocol


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="network-traffic-analyzer",
        description=(
            "Capture and analyze network traffic on a selected interface."
        ),
        epilog=(
            "Multiple values within the same filter use OR. "
            "Different filter types use AND."
        ),
    )

    # Interface selection
    parser.add_argument(
        "--interface",
        help="Exact interface name returned by --list-interfaces.",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List Scapy capture interfaces.",
    )

    # Capture limits
    limits = parser.add_mutually_exclusive_group()

    limits.add_argument(
        "--count",
        type=positive_int,
        help="Stop after this many packets are delivered to the application.",
    )

    limits.add_argument(
        "--duration",
        type=positive_float,
        help="Stop after this many seconds.",
    )

    # IP filters
    parser.add_argument(
        "--src-ip",
        action="append",
        type=parse_ip_address,
        metavar="IP",
        help="Filter by source IP. Repeatable.",
    )

    parser.add_argument(
        "--dst-ip",
        action="append",
        type=parse_ip_address,
        metavar="IP",
        help="Filter by destination IP. Repeatable.",
    )

    # Protocol filter
    parser.add_argument(
        "--protocol",
        action="append",
        type=parse_protocol,
        choices=sorted(SUPPORTED_PROTOCOLS),
        metavar="PROTOCOL",
        help=(
            "Filter by protocol. Repeatable. "
            "Examples: TCP, UDP, ICMP, ICMPv6, ARP."
        ),
    )

    # Port filters
    parser.add_argument(
        "--port",
        action="append",
        type=parse_port,
        metavar="PORT",
        help="Filter by TCP/UDP port. Repeatable.",
    )

    parser.add_argument(
        "--port-direction",
        choices=("source", "destination", "either"),
        default=None,
        help=(
            "Select which port field to check. "
            "Default: either."
        ),
    )

    # Statistics configuration
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=1.0,
        help="Traffic-rate bucket duration in seconds. Default: 1.",
    )

    parser.add_argument(
        "--top",
        type=positive_int,
        default=5,
        help="Number of top IPs, ports, and endpoint pairs to display.",
    )

    # Presentation
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Hide individual packet lines and show the final report only.",
    )

    return parser


def create_packet_filter(args: argparse.Namespace) -> PacketFilter:
    """Convert parsed CLI arguments into a validated PacketFilter."""

    if args.port_direction and not args.port:
        raise ValueError(
            "--port-direction requires at least one --port argument."
        )

    return PacketFilter(
        source_ips=frozenset(args.src_ip or []),
        destination_ips=frozenset(args.dst_ip or []),
        protocols=frozenset(args.protocol or []),
        ports=frozenset(args.port or []),
        port_direction=args.port_direction or "either",
    )


def describe_filter(packet_filter: PacketFilter) -> str:
    """Create a readable description of the active filters."""

    if not packet_filter.is_active:
        return "No packet filters (all parsed packets included)."

    descriptions = []

    if packet_filter.source_ips:
        descriptions.append(
            f"source IP={','.join(sorted(packet_filter.source_ips))}"
        )

    if packet_filter.destination_ips:
        descriptions.append(
            f"destination IP={','.join(sorted(packet_filter.destination_ips))}"
        )

    if packet_filter.protocols:
        descriptions.append(
            f"protocol={','.join(sorted(packet_filter.protocols))}"
        )

    if packet_filter.ports:
        ports = ",".join(
            str(port) for port in sorted(packet_filter.ports)
        )

        descriptions.append(
            f"ports={ports} ({packet_filter.port_direction})"
        )

    return " AND ".join(descriptions)


def format_record(
    packet_number: int,
    record: PacketRecord,
) -> str:
    """Format a PacketRecord for terminal output."""

    if record.timestamp is None:
        timestamp = "unknown-time"
    else:
        timestamp = record.timestamp.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")

    source = record.source_ip or record.source_mac or "-"
    destination = record.destination_ip or record.destination_mac or "-"

    if (
        record.source_port is not None
        and record.destination_port is not None
    ):
        ports = (
            f"{record.source_port}->{record.destination_port}"
        )
    else:
        ports = "-"

    return (
        f"{packet_number:04d} | {timestamp} | {record.protocol} | "
        f"{source} -> {destination} | "
        f"ports={ports} | bytes={record.observed_bytes}"
    )


def make_packet_handler(
    statistics: TrafficStatistics,
    packet_filter: PacketFilter,
    processing: ProcessingSummary,
    quiet: bool = False,
):
    """Create a callback that parses, filters, and analyzes packets."""

    def handle_packet(packet: Packet, packet_number: int) -> None:

        # First: extract metadata.
        try:
            record = parse_packet(packet)
            processing.parsed_packets += 1

        except Exception as exc:
            processing.parse_errors += 1

            logger.warning(
                "Could not parse packet %d: %s: %s",
                packet_number,
                type(exc).__name__,
                exc,
            )
            return

        # Second: apply the configured filters.
        if not packet_filter.matches(record):
            processing.filtered_packets += 1
            return

        # Third: update traffic statistics.
        try:
            statistics.add(record)
            processing.analyzed_packets += 1

        except Exception as exc:
            processing.statistics_errors += 1

            logger.warning(
                "Could not analyze packet %d: %s: %s",
                packet_number,
                type(exc).__name__,
                exc,
            )
            return

        # Fourth: optionally display the matching packet.
        if not quiet:
            print(
                format_record(packet_number, record),
                flush=True,
            )

    return handle_packet


def print_processing_summary(
    callback_count: int,
    processing: ProcessingSummary,
) -> None:
    """Display how packets moved through the processing pipeline."""

    print("\n[Packet Processing Summary]")

    print(
        f"Packets delivered to application: {callback_count}"
    )

    print(
        f"Successfully parsed packets:      {processing.parsed_packets}"
    )

    print(
        f"Filtered out packets:              {processing.filtered_packets}"
    )

    print(
        f"Parsing errors:                    {processing.parse_errors}"
    )

    print(
        f"Statistics processing errors:      {processing.statistics_errors}"
    )

    print(
        f"Packets included in statistics:    {processing.analyzed_packets}"
    )


def print_statistics(
    statistics: TrafficStatistics,
    top_limit: int = 5,
) -> None:
    """Print the final traffic statistics report."""

    print("\n")
    print("=" * 72)
    print("NETWORK TRAFFIC STATISTICS REPORT")
    print("=" * 72)

    print(f"Analyzed packets:       {statistics.total_packets}")
    print(
        f"Total observed bytes:   {statistics.total_observed_bytes}"
    )

    print(
        "Packets without usable timestamps: "
        f"{statistics.packets_without_usable_timestamp}"
    )

    # Protocol breakdown
    print("\n[Protocol Statistics]")

    protocols = statistics.protocol_summary()

    if not protocols:
        print("No matching packet records.")

    for protocol, values in protocols.items():
        print(
            f"{protocol:<18} "
            f"Packets: {values['packets']:<8} "
            f"Bytes: {values['observed_bytes']}"
        )

    # Top source addresses
    print("\n[Top Source IP Addresses]")

    for address, count in statistics.top_source_ips(top_limit):
        print(f"{address:<45} {count} packets")

    # Top destination addresses
    print("\n[Top Destination IP Addresses]")

    for address, count in statistics.top_destination_ips(top_limit):
        print(f"{address:<45} {count} packets")

    # Top transport ports
    for protocol in ("TCP", "UDP"):
        print(f"\n[Top {protocol} Destination Ports]")

        ports = statistics.top_ports(
            protocol,
            direction="destination",
            limit=top_limit,
        )

        if not ports:
            print("No port records.")

        for port, count in ports:
            print(f"Port {port:<10} {count} packets")

    # Endpoint pairs
    print("\n[Top Source -> Destination Pairs]")

    pairs = statistics.top_endpoint_pairs(top_limit)

    if not pairs:
        print("No endpoint pairs available.")

    for source, destination, packets, byte_count in pairs:
        print(
            f"{source} -> {destination} | "
            f"Packets: {packets} | Bytes: {byte_count}"
        )

    # Traffic rates
    print("\n[Traffic Rates - Latest 10 Buckets]")

    rates = statistics.time_series()

    if not rates:
        print("No usable timestamps available.")

    for rate in rates[-10:]:
        print(
            f"{rate.interval_start.isoformat()} | "
            f"{rate.packets_per_second:.2f} packets/s | "
            f"{rate.bytes_per_second:.2f} bytes/s"
        )

    print("=" * 72)


def main() -> int:
    """Run the command-line application."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    parser = build_parser()
    args = parser.parse_args()

    # Interface discovery
    try:
        interfaces = get_interfaces()

    except RuntimeError as exc:
        logger.error("%s", exc)
        return 2

    if args.list_interfaces:
        if not interfaces:
            logger.error("Scapy returned no interfaces.")
            return 2

        print("Available Scapy interfaces:")

        for name, description in interfaces:
            if description:
                print(f"  {name} — {description}")
            else:
                print(f"  {name}")

        return 0

    # Interface validation
    if not args.interface:
        parser.error(
            "Specify --interface or use --list-interfaces."
        )

    interface_names = {
        name for name, _ in interfaces
    }

    if args.interface not in interface_names:
        logger.error(
            "Interface %r was not found. "
            "Run --list-interfaces and copy the exact name.",
            args.interface,
        )
        return 2

    # Validate filters
    try:
        packet_filter = create_packet_filter(args)

    except ValueError as exc:
        parser.error(str(exc))

    logger.info("Selected interface: %s", args.interface)
    logger.info("Packet filters: %s", describe_filter(packet_filter))

    if args.count is not None:
        logger.info(
            "Capture stops after %d packets are delivered to the application.",
            args.count,
        )

    elif args.duration is not None:
        logger.info(
            "Capture duration: %.2f seconds.",
            args.duration,
        )

    else:
        logger.info("Capture stops when you press Ctrl+C.")

    logger.info(
        "Statistics interval: %.2f seconds.",
        args.interval,
    )

    logger.info(
        "Payloads are not exported or retained by this application."
    )

    # Initialize the analysis engine.
    statistics = TrafficStatistics(
        interval_seconds=args.interval,
        max_time_buckets=3600,
    )

    processing = ProcessingSummary()

    packet_handler = make_packet_handler(
        statistics=statistics,
        packet_filter=packet_filter,
        processing=processing,
        quiet=args.quiet,
    )

    if not args.quiet:
        print(
            "\nPACKET | TIMESTAMP (UTC) | PROTOCOL | "
            "SOURCE -> DESTINATION | PORTS | OBSERVED BYTES"
        )

    # Start capture.
    try:
        callback_count = capture_packets(
            interface=args.interface,
            on_packet=packet_handler,
            count=args.count,
            duration=args.duration,
        )

    except (RuntimeError, ValueError) as exc:
        logger.error("%s", exc)
        logger.error(
            "Check Npcap, interface selection, and capture permissions."
        )
        return 2

    # Print final reports.
    print_processing_summary(
        callback_count,
        processing,
    )

    print_statistics(
        statistics,
        top_limit=args.top,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
