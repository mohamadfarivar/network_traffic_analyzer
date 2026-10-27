from datetime import datetime

from scapy.all import (
    ARP,
    Ether,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    conf,
    get_if_list,
    sniff,
)


def get_interfaces() -> list[tuple[str, str]]:
    """Return Scapy interface names and available descriptions."""
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


def format_packet(packet, packet_number: int) -> str:
    """Format a captured packet as a metadata-only summary."""
    try:
        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).astimezone().isoformat(timespec="milliseconds")
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        timestamp = "unknown-time"

    # Determine the most specific protocol this version supports.
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(ARP):
        protocol = "ARP"
    elif packet.haslayer(IPv6):
        protocol = "IPv6-other"
    elif packet.haslayer(IP):
        protocol = "IP-other"
    elif packet.haslayer(Ether):
        protocol = "Ethernet-other"
    else:
        protocol = "OTHER"

    # Prefer network-layer addresses, with ARP and Ethernet fallbacks.
    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst
    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst
    elif packet.haslayer(ARP):
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
    elif packet.haslayer(Ether):
        source = packet[Ether].src
        destination = packet[Ether].dst
    else:
        source = "-"
        destination = "-"

    # Ports are available for TCP and UDP packets.
    if packet.haslayer(TCP):
        ports = f"{packet[TCP].sport}->{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        ports = f"{packet[UDP].sport}->{packet[UDP].dport}"
    else:
        ports = "-"

    observed_bytes = len(packet)

    return (
        f"{packet_number:04d} | {timestamp} | {protocol} | "
        f"{source} -> {destination} | "
        f"ports={ports} | bytes={observed_bytes}"
    )


def capture_packets(
    interface: str,
    count: int | None = None,
    duration: float | None = None,
) -> int:
    """Capture live packets and print metadata without retaining the packet list."""
    if count is not None and count <= 0:
        raise ValueError("Packet count must be greater than zero.")

    if duration is not None and duration <= 0:
        raise ValueError("Duration must be greater than zero.")

    if count is not None and duration is not None:
        raise ValueError("Choose either count or duration, not both.")

    available_names = {name for name, _ in get_interfaces()}

    if interface not in available_names:
        raise ValueError(
            f"Interface {interface!r} is not in Scapy's interface list. "
            "Run --list-interfaces and copy an exact interface name."
        )

    packet_number = 0

    def handle_packet(packet) -> None:
        nonlocal packet_number
        packet_number += 1
        print(format_packet(packet, packet_number), flush=True)

    print(
        "PACKET | TIMESTAMP | PROTOCOL | SOURCE -> DESTINATION "
        "| PORTS | OBSERVED BYTES"
    )

    capture_options = {
        "iface": interface,
        "prn": handle_packet,
        "store": False,
        "promisc": False,
    }

    if count is not None:
        capture_options["count"] = count

    if duration is not None:
        capture_options["timeout"] = duration

    try:
        sniff(**capture_options)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as exc:
        raise RuntimeError(
            f"Capture failed on {interface!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    return packet_number