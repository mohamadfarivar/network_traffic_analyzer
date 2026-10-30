import argparse
import logging
import math
import sys

from scapy.packet import Packet # type: ignore

from .capture import capture_packets, get_interfaces
from .models import PacketRecord
from .packet_parser import parse_packet # type: ignore
from .statistics import TrafficStatistics

logger = logging.getLogger(__name__)


def positive_int(value: str) -> int:
    """Parse a positive integer for --count."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Count must be a whole number."
        ) from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "Count must be greater than zero."
        )

    return number


def positive_float(value: str) -> float:
    """Parse a finite positive number for --duration."""
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Duration must be a number."
        ) from exc

    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError(
            "Duration must be a finite number greater than zero."
        )

    return number


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Capture and summarize live network traffic."
    )

    parser.add_argument(
        "--interface",
        help="Exact interface name shown by --list-interfaces.",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List interfaces available to Scapy, then exit.",
    )

    limits = parser.add_mutually_exclusive_group()
    limits.add_argument(
        "--count",
        type=positive_int,
        help="Stop after capturing this many packets.",
    )
    limits.add_argument(
        "--duration",
        type=positive_float,
        help="Stop after this many seconds.",
    )

    return parser


def format_record(
    packet_number: int,
    record: PacketRecord,
) -> str:
    """Format one structured packet record for terminal output."""
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
        ports = f"{record.source_port}->{record.destination_port}"
    else:
        ports = "-"

    return (
        f"{packet_number:04d} | {timestamp} | {record.protocol} | "
        f"{source} -> {destination} | "
        f"ports={ports} | bytes={record.observed_bytes}"
    )


def make_packet_handler(statistics: TrafficStatistics):
    """Create a callback that parses, analyzes, and displays packets."""

    def handle_packet(packet: Packet, packet_number: int) -> None:
        try:
            record = parse_packet(packet)
            statistics.add(record)

        except Exception as exc:
            logger.warning(
                "Could not process packet %d: %s: %s",
                packet_number,
                type(exc).__name__,
                exc,
            )
            return

        print(
            format_record(packet_number, record),
            flush=True,
        )

    return handle_packet


def print_statistics(statistics: TrafficStatistics) -> None:
    """Print the final traffic statistics report."""

    print("\n")
    print("=" * 65)
    print("TRAFFIC STATISTICS REPORT")
    print("=" * 65)

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
        print("No packet records available.")

    for protocol, values in protocols.items():
        print(
            f"{protocol:<15} "
            f"Packets: {values['packets']:<8} "
            f"Bytes: {values['observed_bytes']}"
        )

    # Source IP addresses
    print("\n[Top Source IP Addresses]")

    for address, count in statistics.top_source_ips():
        print(f"{address:<40} {count} packets")

    # Destination IP addresses
    print("\n[Top Destination IP Addresses]")

    for address, count in statistics.top_destination_ips():
        print(f"{address:<40} {count} packets")

    # TCP and UDP ports
    for protocol in ("TCP", "UDP"):
        print(f"\n[Top {protocol} Destination Ports]")

        ports = statistics.top_ports(
            protocol,
            direction="destination",
        )

        for port, count in ports:
            print(f"Port {port:<10} {count} packets")

    # Directional endpoint pairs
    print("\n[Top Source -> Destination Pairs]")

    for source, destination, packets, byte_count in (
        statistics.top_endpoint_pairs()
    ):
        print(
            f"{source} -> {destination} | "
            f"Packets: {packets} | Bytes: {byte_count}"
        )

    # Traffic rates
    print("\n[Traffic Rates - Latest 10 Buckets]")

    rates = statistics.time_series()

    if not rates:
        print("No usable timestamps available.")
    else:
        for rate in rates[-10:]:
            print(
                f"{rate.interval_start.isoformat()} | "
                f"{rate.packets_per_second:.2f} packets/s | "
                f"{rate.bytes_per_second:.2f} bytes/s"
            )

    print("=" * 65)


def display_packet(packet: Packet, packet_number: int) -> None:
    """Parse a captured packet and print its metadata."""
    try:
        record = parse_packet(packet)
    except Exception as exc:
        logger.warning(
            "Could not parse packet %d: %s: %s",
            packet_number,
            type(exc).__name__,
            exc,
        )
        return

    print(format_record(packet_number, record), flush=True)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    parser = build_parser()
    args = parser.parse_args()

    try:
        interfaces = get_interfaces()
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 2

    if args.list_interfaces:
        if not interfaces:
            logger.error("Scapy returned no capture interfaces.")
            return 2

        print("Available Scapy interfaces:")

        for name, description in interfaces:
            if description:
                print(f"  {name} — {description}")
            else:
                print(f"  {name}")

        return 0

    if not args.interface:
        parser.error(
            "Specify --interface or use --list-interfaces."
        )

    interface_names = {name for name, _ in interfaces}

    if args.interface not in interface_names:
        logger.error(
            "Interface %r was not found. Run --list-interfaces "
            "and copy the exact name.",
            args.interface,
        )
        return 2

    if args.count is not None:
        stop_condition = f"after {args.count} packets"
    elif args.duration is not None:
        stop_condition = f"after {args.duration} seconds"
    else:
        stop_condition = "when you press Ctrl+C"

    logger.info("Selected interface: %s", args.interface)
    logger.info("Capture will stop %s.", stop_condition)
    logger.info("Payloads will not be written to disk.")

    print(
        "PACKET | TIMESTAMP (UTC) | PROTOCOL | "
        "SOURCE -> DESTINATION | PORTS | OBSERVED BYTES"
    )

    statistics = TrafficStatistics(
        interval_seconds=1.0,
        max_time_buckets=3600,
    )

    packet_handler = make_packet_handler(statistics)

    try:
        captured = capture_packets(
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

    logger.info(
        "Capture callback invocations: %d",
        captured,
    )

    logger.info(
        "Successfully analyzed records: %d",
        statistics.total_packets,
    )

    print_statistics(statistics)

    return 0


if __name__ == "__main__":
    sys.exit(main())