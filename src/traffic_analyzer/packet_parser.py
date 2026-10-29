import math
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP # type: ignore
from scapy.layers.inet6 import IPv6 # type: ignore
from scapy.layers.l2 import ARP, Ether # type: ignore
from scapy.packet import Packet # type: ignore

from .models import PacketRecord


def _optional_text(value: object) -> str | None:
    """Convert a field to text, preserving missing values as None."""
    if value is None:
        return None

    text = str(value)
    return text if text else None


def _parse_timestamp(packet: Packet) -> datetime | None:
    """Convert Scapy's packet timestamp into an aware UTC datetime."""
    try:
        timestamp = float(packet.time)

        if not math.isfinite(timestamp):
            return None

        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        )

    except (
        AttributeError,
        OSError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        return None


def _classify_protocol(packet: Packet) -> str:
    """Return a useful protocol label for the packet."""
    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    # Scapy represents ICMPv6 message types using multiple layer classes.
    if any(
        getattr(layer, "__name__", "").startswith("ICMPv6")
        for layer in packet.layers()
    ):
        return "ICMPv6"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(IP):
        return "IPv4-other"

    if packet.haslayer(IPv6):
        return "IPv6-other"

    if packet.haslayer(Ether):
        return "Ethernet-other"

    return "OTHER"


def parse_packet(packet: Packet) -> PacketRecord:
    """Extract metadata from one Scapy packet without storing its payload."""
    source_ip = None
    destination_ip = None

    # Read network-layer endpoints where available.
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        source_ip = _optional_text(ip_layer.src)
        destination_ip = _optional_text(ip_layer.dst)

    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        source_ip = _optional_text(ipv6_layer.src)
        destination_ip = _optional_text(ipv6_layer.dst)

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        source_ip = _optional_text(arp_layer.psrc)
        destination_ip = _optional_text(arp_layer.pdst)

    # Read link-layer endpoints when an Ethernet header is present.
    source_mac = None
    destination_mac = None

    if packet.haslayer(Ether):
        ethernet_layer = packet[Ether]
        source_mac = _optional_text(ethernet_layer.src)
        destination_mac = _optional_text(ethernet_layer.dst)

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        source_mac = _optional_text(arp_layer.hwsrc)
        destination_mac = _optional_text(arp_layer.hwdst)

    # Only TCP and UDP have source and destination ports in this model.
    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        transport_layer = packet[TCP]
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)

    elif packet.haslayer(UDP):
        transport_layer = packet[UDP]
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)

    return PacketRecord(
        timestamp=_parse_timestamp(packet),
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_mac=source_mac,
        destination_mac=destination_mac,
        protocol=_classify_protocol(packet),
        source_port=source_port,
        destination_port=destination_port,
        observed_bytes=len(packet),
    )