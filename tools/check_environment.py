import platform
import sys

try:
    import scapy # type: ignore
    from scapy.all import conf, get_if_list # type: ignore
except ImportError as exc:
    print(f"Scapy import failed: {exc}")
    print("Check that the project's virtual environment is active.")
    sys.exit(1)


def main() -> None:
    print("=== Network Traffic Analyzer: Environment Check ===")
    print(f"Operating system: {platform.platform()}")
    print(f"Python version: {sys.version.split()[0]}")
    print(f"Scapy version: {scapy.__version__}")

    print("\n=== Scapy Capture Interfaces ===")

    try:
        interfaces = list(get_if_list())

        if not interfaces:
            print("No capture interfaces were returned.")
            print("Check Npcap installation and interface visibility.")
            sys.exit(2)

        for name in interfaces:
            print(f"- {name}")

        print("\n=== Interface Descriptions ===")

        for interface in conf.ifaces.values():
            name = getattr(interface, "name", "<unknown>")
            description = getattr(
                interface, "description", "<no description>"
            )
            print(f"- Capture name: {name}")
            print(f"  Description: {description}")

        print("\nInterface enumeration completed.")

    except Exception as exc:
        print(f"Interface enumeration failed: {type(exc).__name__}: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()