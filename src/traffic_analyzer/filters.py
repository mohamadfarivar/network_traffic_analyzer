
import ipaddress
from dataclasses import dataclass


SUPPORTED_PROTOCOLS = frozenset({
    "TCP",
    "UDP",
    "ICMP",
    "ICMPV6",
    "ARP",
    "IPV4-OTHER",
    "IPV6-OTHER",
    "ETHERNET-OTHER",
    "OTHER",
})


@dataclass(frozen=True, slots=True)
class PacketFilter:
    """A collection of filters applied to parsed packet records.

    Multiple values within one category use OR.
    Different categories use AND.

    IP addresses are exact matches, not network prefixes.
    """

    source_ips: frozenset[str] = frozenset()
    destination_ips: frozenset[str] = frozenset()
    protocols: frozenset[str] = frozenset()
    ports: frozenset[int] = frozenset()
    port_direction: str = "either"

    def __post_init__(self) -> None:
        """Validate and normalize filter configuration."""

        object.__setattr__(
            self,
            "source_ips",
            self._normalize_addresses(self.source_ips),
        )

        object.__setattr__(
            self,
            "destination_ips",
            self._normalize_addresses(self.destination_ips),
        )

        object.__setattr__(
            self,
            "protocols",
            self._normalize_protocols(self.protocols),
        )

        object.__setattr__(
            self,
            "ports",
            self._normalize_ports(self.ports),
        )

        direction = self.port_direction.lower()

        if direction not in ("source", "destination", "either"):
            raise ValueError(
                "Port direction must be source, destination, or either."
            )

        object.__setattr__(self, "port_direction", direction)

    @staticmethod
    def _normalize_addresses(values) -> frozenset[str]:
        """Validate and normalize IPv4 and IPv6 addresses."""
        if isinstance(values, str):
            values = (values,)

        normalized = set()

        try:
            for value in values:
                if not isinstance(value, str):
                    raise ValueError("IP addresses must be strings.")

                normalized.add(
                    str(ipaddress.ip_address(value.strip()))
                )

        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid IP filter: {exc}") from exc

        return frozenset(normalized)

    @staticmethod
    def _normalize_protocols(values) -> frozenset[str]:
        """Validate and normalize protocol names."""
        if isinstance(values, str):
            values = (values,)

        normalized = set()

        try:
            for value in values:
                if not isinstance(value, str):
                    raise ValueError("Protocol names must be strings.")

                protocol = value.strip().upper()

                if protocol not in SUPPORTED_PROTOCOLS:
                    raise ValueError(
                        f"Unsupported protocol: {value}"
                    )

                normalized.add(protocol)

        except TypeError as exc:
            raise ValueError(
                f"Invalid protocol configuration: {exc}"
            ) from exc

        return frozenset(normalized)

    @staticmethod
    def _normalize_ports(values) -> frozenset[int]:
        """Validate TCP and UDP port numbers."""
        if isinstance(values, int) and not isinstance(values, bool):
            values = (values,)

        normalized = set()

        try:
            for port in values:
                if (
                    isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 0 <= port <= 65535
                ):
                    raise ValueError(
                        f"Invalid port: {port}. "
                        "Valid ports are integers from 0 to 65535."
                    )

                normalized.add(port)

        except TypeError as exc:
            raise ValueError(
                f"Invalid port configuration: {exc}"
            ) from exc

        return frozenset(normalized)

    @staticmethod
    def _normalize_record_ip(address: str | None) -> str | None:
        """Normalize an address extracted from a packet."""
        if not isinstance(address, str) or not address.strip():
            return None

        try:
            return str(ipaddress.ip_address(address.strip()))
        except ValueError:
            return None

    @staticmethod
    def _valid_record_port(port: int | None) -> bool:
        return (
            isinstance(port, int)
            and not isinstance(port, bool)
            and 0 <= port <= 65535
        )

    def matches(self, record) -> bool:
        """Return True if a PacketRecord passes every configured filter."""

        # Source IP: match any configured source address.
        if self.source_ips:
            source_ip = self._normalize_record_ip(
                record.source_ip
            )

            if source_ip not in self.source_ips:
                return False

        # Destination IP: match any configured destination address.
        if self.destination_ips:
            destination_ip = self._normalize_record_ip(
                record.destination_ip
            )

            if destination_ip not in self.destination_ips:
                return False

        # Protocol: match any configured protocol.
        if self.protocols:
            protocol = (
                record.protocol.upper()
                if isinstance(record.protocol, str)
                else ""
            )

            if protocol not in self.protocols:
                return False

        # Port: match source, destination, or either.
        if self.ports:
            source_port = record.source_port
            destination_port = record.destination_port

            source_matches = (
                self._valid_record_port(source_port)
                and source_port in self.ports
            )

            destination_matches = (
                self._valid_record_port(destination_port)
                and destination_port in self.ports
            )

            if self.port_direction == "source":
                port_matches = source_matches

            elif self.port_direction == "destination":
                port_matches = destination_matches

            else:
                port_matches = (
                    source_matches or destination_matches
                )

            if not port_matches:
                return False

        return True

    @property
    def is_active(self) -> bool:
        """Return whether at least one filter is configured."""
        return any((
            self.source_ips,
            self.destination_ips,
            self.protocols,
            self.ports,
        ))
