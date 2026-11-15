# Network Traffic Analyzer

A Python-based tool for real-time network packet capture, traffic analysis, filtering, and reporting.

Network Traffic Analyzer is a personal engineering project developed to monitor and analyze network traffic using Python, Scapy, and Npcap.

The application captures packets from a selected network interface, extracts packet metadata, calculates traffic statistics, and exports reports in CSV and JSON formats.

> **Status:** Under Development

## Features

- Real-time packet capture using Scapy and Npcap.
- IPv4 and IPv6 packet parsing.
- TCP, UDP, ICMP, ICMPv6, and ARP classification.
- Source and destination IP address analysis.
- TCP and UDP port statistics.
- Packet and byte counters.
- Traffic rates over time.
- Configurable IP, protocol, and port filters.
- Command-line interface (CLI).
- CSV and JSON report generation.
- Automated tests using Python `unittest`.

## Technologies

- Python
- Scapy
- Npcap
- argparse
- collections.Counter
- dataclasses
- unittest
- CSV and JSON
- Git and GitHub

## Architecture

The project uses a modular architecture:

```text
Network Adapter
      |
    Npcap
      |
   Capture
      |
 Packet Parser
      |
 PacketRecord
      |
   Filters
      |
  Statistics
      |
    Export
   /      \
 CSV      JSON
```

### Main Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Command-line interface |
| `capture.py` | Live packet capture |
| `packet_parser.py` | Packet metadata extraction |
| `models.py` | Packet data models |
| `filters.py` | Traffic filtering |
| `statistics.py` | Traffic statistics |
| `export.py` | CSV and JSON reporting |

## Installation

**Requirements:**
- Windows 11
- Python 3.10+
- Npcap
- Git

Install Npcap from: https://npcap.com/

Clone the repository:

```powershell
git clone https://github.com/YOUR_USERNAME/network-traffic-analyzer.git

cd network-traffic-analyzer
```

Create and activate a virtual environment:

```powershell
py -m venv .venv

.\.venv\Scripts\Activate.ps1
```

Install the project:

```powershell
python -m pip install --upgrade pip

python -m pip install -e .
```

## Usage

**List available network interfaces:**

```powershell
python -m traffic_analyzer.cli --list-interfaces
```

**Capture network traffic:**

```powershell
python -m traffic_analyzer.cli --interface "YOUR_INTERFACE" --duration 30
```

**Capture a specific number of packets:**

```powershell
python -m traffic_analyzer.cli --interface "YOUR_INTERFACE" --count 100
```

**Filter TCP traffic:**

```powershell
python -m traffic_analyzer.cli --interface "YOUR_INTERFACE" --duration 30 --protocol TCP
```

**Filter by destination port:**

```powershell
python -m traffic_analyzer.cli --interface "YOUR_INTERFACE" --duration 30 --port 443 --port-direction destination
```

**Export reports:**

```powershell
python -m traffic_analyzer.cli --interface "YOUR_INTERFACE" --duration 30 --quiet --export-json reports/report.json --export-csv reports/report.csv
```

Use `--help` to see all available options.

## Testing

Run the complete test suite:

```powershell
python -m unittest discover -s tests -v
```

The tests cover packet parsing, traffic statistics, filtering, CLI configuration, and data export.

Synthetic packet records are used to test core functionality without requiring live network traffic.

## Project Structure

```text
network-traffic-analyzer/
│
├── src/
│   └── traffic_analyzer/
│       ├── cli.py
│       ├── capture.py
│       ├── packet_parser.py
│       ├── models.py
│       ├── filters.py
│       ├── statistics.py
│       └── export.py
│
├── tests/
├── docs/
├── examples/
├── pyproject.toml
├── .gitignore
└── README.md
```

## Limitations

- Currently focused on Windows 11.
- Requires Npcap for Windows packet capture.
- Packet visibility depends on the network interface and capture configuration.
- Filtering is performed in Python after packet capture.
- IP filtering currently supports exact addresses, not CIDR ranges.
- Endpoint statistics do not represent reconstructed network flows.
- Traffic measurements do not guarantee exact physical link utilization.
- Advanced intrusion detection and machine-learning features are not implemented.

## Security and Privacy

- Intended only for authorized network monitoring.
- Packet payloads are not intentionally saved or exported.
- Reports contain aggregated network metadata.
- No external traffic-upload service is included.
- Sensitive reports and packet captures should not be published.


