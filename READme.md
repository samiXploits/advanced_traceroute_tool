# Auto Traceroute Tool

## Overview
The Auto Traceroute Tool is an advanced network exploration utility that automates traceroute operations, retrieves geographical and ISP details of each hop, and presents the results in multiple formats.

## Features
- Cross-Platform Support (Windows, Linux, macOS)
- Multiple Protocols: ICMP, TCP, UDP traceroute
- Hostname Resolution Control
- Multi-Threaded Execution for multiple targets
- GeoIP Lookup using `ip-api.com`
- Multiple Output Formats: JSON, CSV, HTML with interactive maps
- Detailed Reports with tabular visualization

## Dependencies
Ensure the following Python packages are installed before running the script:

```sh
pip install requests folium tabulate
```

## Usage
Run the script with the desired target(s):

```sh
python auto_tracert.py <target>
```

### Available Arguments
| Argument | Description |
|----------|-------------|
| `<target>` | IP or domain name to trace |
| `-p, --protocol` | Traceroute protocol (`icmp`, `tcp`, `udp`) |
| `--port` | Destination port for TCP/UDP traceroute |
| `-m, --max-hops` | Maximum number of hops (default: 30) |
| `-t, --timeout` | Timeout per hop in seconds (default: 5) |
| `-q, --probes` | Number of probes per hop (default: 3) |
| `-n, --no-resolve` | Do not resolve hostnames |
| `-v, --verbose` | Enable verbose output |
| `--json` | Save results in JSON format |
| `--csv` | Save results in CSV format |
| `--html` | Generate an HTML report with an interactive map |

## Example Usage

Traceroute to `example.com` with default settings:

```sh
python auto_tracert.py example.com
```

Using TCP on port `443`:

```sh
python auto_tracert.py example.com -p tcp --port 443
```

Saving results in all formats:

```sh
python auto_tracert.py example.com --json --csv --html
```

## Output Formats
- Console Output: Displays results in a formatted table.
- JSON Report: Structured JSON file in the `reports/` directory.
- CSV Report: Easily importable format for data analysis.
- HTML Report: Interactive map generated using Folium.

## Notes
- Ensure `traceroute` (Linux/macOS) or `tracert` (Windows) is installed.
- Some ISPs and firewalls may block ICMP or other traceroute methods.

## License
This tool is provided for educational and research purposes only. Use responsibly.

