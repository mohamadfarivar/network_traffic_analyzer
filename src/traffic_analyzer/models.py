from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Metadata extracted from one observed network packet.

    Timestamps are timezone-aware UTC values when available.
    IP and MAC addresses and transport ports may be absent.
    observed_bytes is the length of Scapy's packet representation.
    """

    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_mac: str | None
    destination_mac: str | None
    protocol: str
    source_port: int | None
    destination_port: int | None
    observed_bytes: int