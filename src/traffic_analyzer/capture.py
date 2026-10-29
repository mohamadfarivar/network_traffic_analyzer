import logging
import math
from typing import Callable

from scapy.all import conf, get_if_list, sniff # type: ignore
from scapy.packet import Packet # type: ignore


logger = logging.getLogger(__name__)

PacketHandler = Callable[[Packet, int], None]


def get_interfaces() -> list[tuple[str, str]]:
    """Return available Scapy interface names and descriptions."""
    try:
        names = get_if_list()
        descriptions = {}

        for interface in conf.ifaces.values():
            name = getattr(interface, "name", None)
            description = getattr(interface, "description", "")
            network_name = getattr(interface, "network_name", "")

            if name:
                descriptions[name] = description or network_name or ""

        return [
            (name, str(descriptions.get(name, "")))
            for name in names
        ]

    except Exception as exc:
        raise RuntimeError(
            f"Unable to enumerate capture interfaces: {exc}"
        ) from exc


def capture_packets(
    interface: str,
    on_packet: PacketHandler,
    count: int | None = None,
    duration: float | None = None,
) -> int:
    """Capture packets and pass each packet to a callback.

    Scapy does not accumulate the captured packets in a result list.
    """
    if count is not None and count <= 0:
        raise ValueError("Packet count must be greater than zero.")

    if duration is not None and (
        not math.isfinite(duration) or duration <= 0
    ):
        raise ValueError(
            "Duration must be a finite number greater than zero."
        )

    if count is not None and duration is not None:
        raise ValueError("Choose either count or duration, not both.")

    available_names = {
        name for name, _ in get_interfaces()
    }

    if interface not in available_names:
        raise RuntimeError(
            f"Interface {interface!r} is not available to Scapy."
        )

    packet_count = 0

    def handle_packet(packet: Packet) -> None:
        nonlocal packet_count

        packet_count += 1
        on_packet(packet, packet_count)

    options = {
        "iface": interface,
        "prn": handle_packet,
        "store": False,
        "promisc": False,
    }

    if count is not None:
        options["count"] = count

    if duration is not None:
        options["timeout"] = duration

    try:
        sniff(**options)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user.")
    except Exception as exc:
        raise RuntimeError(
            f"Capture failed on {interface!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    return packet_count