import argparse
import logging
import math
import sys

from .capture import capture_packets, get_interfaces


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
        parser.error("Specify --interface or use --list-interfaces.")

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

    try:
        captured = capture_packets(
            interface=args.interface,
            count=args.count,
            duration=args.duration,
        )
    except (RuntimeError, ValueError) as exc:
        logger.error("%s", exc)
        logger.error(
            "Check Npcap, interface selection, and capture permissions."
        )
        return 2

    logger.info("Capture finished. Packets processed: %d", captured)
    return 0


if __name__ == "__main__":
    sys.exit(main())