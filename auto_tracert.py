import os
import platform
import subprocess
import argparse
import re
import json
import csv
import requests
import folium
from datetime import datetime
from functools import lru_cache
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate  # For table formatting

# Constants
IP_API_URL = "http://ip-api.com/json/"
DEFAULT_TIMEOUT = 5
DEFAULT_MAX_HOPS = 30
DEFAULT_PROBES = 3
CACHE_SIZE = 100  # Number of IP locations to cache
REPORT_FOLDER = "reports"  # Folder to save reports

def print_banner():
    """Print the tool's banner with improved styling."""
    banner = """
    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                                                                            ║
    ║         ██████╗ ███████╗██████╗     ██████╗  ██████╗ ██╗███████╗          ║
    ║        ██╔═══██╗██╔════╝██╔══██╗   ██╔════╝ ██╔═══██╗██║██╔════╝          ║
    ║        ██║   ██║███████╗██████╔╝   ██║  ███╗██║   ██║██║███████╗          ║
    ║        ██║   ██║╚════██║██╔══██╗   ██║   ██║██║   ██║██║╚════██║          ║
    ║        ╚██████╔╝███████║██║  ██║   ╚██████╔╝╚██████╔╝██║███████║          ║
    ║         ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═════╝  ╚═════╝ ╚═╝╚══════╝          ║
    ║                                                                            ║
    ║                  Advanced Auto Traceroute Tool                             ║
    ║                                                                            ║
    ╚════════════════════════════════════════════════════════════════════════════╝
    ║                                                                            ║
    ║        Crafted for Network Explorers and Problem Solvers!                  ║
    ║                                                                            ║
    ╚════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def ensure_report_folder():
    """Ensure the 'reports' folder exists."""
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)
        print(f"Created '{REPORT_FOLDER}' folder.")

def get_ip_location(ip, retries=3, delay=2):
    """Get location details for a given IP address with retries and caching."""
    if ip == "N/A":
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": None, "lon": None}

    for attempt in range(retries):
        try:
            response = requests.get(f"{IP_API_URL}{ip}", timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": data.get("lat", None),
                    "lon": data.get("lon", None)
                }
            else:
                return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": None, "lon": None}
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {ip}: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": None, "lon": None}

def parse_traceroute_output(output, system):
    """Parse traceroute output and extract hop information."""
    hops = []
    lines = output.strip().splitlines()

    if system == "Windows":
        # Windows tracert output parsing
        for line in lines[3:]:  # Skip header lines
            if line.strip():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                hop_num = parts[0]
                if hop_num.isdigit():
                    rtts = []
                    for rtt_str in parts[1:4]:  # Extract RTT values (up to 3 probes)
                        if rtt_str != "*" and rtt_str.endswith("ms"):
                            try:
                                rtts.append(float(rtt_str[:-2]))  # Remove "ms" and convert to float
                            except ValueError:
                                pass  # Ignore invalid RTT values
                    ip_address = next((part for part in parts if re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", part)), "N/A")
                    hostname = " ".join(parts[parts.index(ip_address) + 1:]) if ip_address != "N/A" else "N/A"
                    hops.append({
                        'hop': hop_num,
                        'rtts': rtts,
                        'ip_address': ip_address,
                        'hostname': hostname if hostname != ip_address else "N/A",
                        'location': get_ip_location(ip_address)
                    })

    elif system in ["Linux", "Darwin"]:  # Darwin is macOS
        # Linux/macOS traceroute output parsing
        for line in lines[1:]:  # Skip first line (traceroute to ...)
            if line.strip():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                hop_num = parts[0]
                if hop_num.isdigit():
                    rtts = [float(rtt) for rtt in parts[1:4] if len(parts) >= 4 and parts[1] != "*"]
                    ip_address = next((part for part in parts if re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", part)), "N/A")
                    hostname = parts[parts.index(ip_address) - 1] if ip_address != "N/A" and parts[parts.index(ip_address) - 1].endswith('.') else "N/A"
                    hops.append({
                        'hop': hop_num,
                        'rtts': rtts,
                        'ip_address': ip_address,
                        'hostname': hostname if hostname != ip_address else "N/A",
                        'location': get_ip_location(ip_address)
                    })

    return hops

def perform_traceroute(target, protocol="icmp", port=None, max_hops=DEFAULT_MAX_HOPS, timeout=DEFAULT_TIMEOUT, num_probes=DEFAULT_PROBES, resolve_hostname=True, verbose=False):
    """Perform a traceroute to the target and return parsed results."""
    system = platform.system()
    command = []

    if system == "Windows":
        command = ["tracert", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target]
    elif system in ["Linux", "Darwin"]:  # Darwin is macOS
        command = ["traceroute"]
        if protocol == "icmp":
            command.append("-I")
        elif protocol == "tcp" and port:
            command.extend(["-T", "-p", str(port)])
        elif protocol == "udp" and port:
            command.extend(["-U", "-p", str(port)])
        command.extend(["-m", str(max_hops), "-w", str(timeout), "-q", str(num_probes)])
        if not resolve_hostname:
            command.append("-n")
        command.append(target)
    else:
        print(f"Unsupported OS: {system}")
        return None

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=timeout * (max_hops + 2))

        if process.returncode == 0:
            output_text = stdout.decode(errors='ignore')
            if verbose:
                print("Raw traceroute output:")
                print(output_text)
                print("-" * 30)
            hops_data = parse_traceroute_output(output_text, system)
            return hops_data
        else:
            error_text = stderr.decode(errors='ignore')
            print(f"Error during traceroute: Return Code: {process.returncode}")
            if error_text:
                print(f"Stderr: {error_text}")
            return None

    except subprocess.TimeoutExpired:
        print(f"Traceroute timed out after {timeout * (max_hops + 2)} seconds.")
        return None
    except FileNotFoundError:
        print(f"Error: Traceroute command not found. Make sure 'traceroute' (Linux/macOS) or 'tracert' (Windows) is installed.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def save_results_json(results, filename):
    """Save traceroute results to a JSON file."""
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to JSON file: {filename}")
        return True
    except Exception as e:
        print(f"Error saving JSON to {filename}: {e}")
        return False

def save_results_csv(results, filename):
    """Save traceroute results to a CSV file."""
    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Hop", "IP Address", "Hostname", "Country", "City", "ISP", "RTTs (ms)"])
            for target, hops in results.items():
                for hop in hops:
                    rtt_str = ", ".join(map(str, [f"{r:.2f}" for r in hop['rtts']])) if hop['rtts'] else "*"
                    writer.writerow([hop['hop'], hop['ip_address'], hop['hostname'], hop['location']['country'], hop['location']['city'], hop['location']['isp'], rtt_str])
        print(f"Results saved to CSV file: {filename}")
        return True
    except Exception as e:
        print(f"Error saving CSV to {filename}: {e}")
        return False

def generate_html_report(results, filename):
    """Generate an HTML report with an interactive map."""
    try:
        m = folium.Map(location=[20, 0], zoom_start=2)
        for target, hops in results.items():
            for hop in hops:
                if hop['location'] and hop['location']['lat'] and hop['location']['lon']:
                    popup_content = f"<b>Target:</b> {target}<br><b>Hop {hop['hop']}:</b> {hop['hostname']}<br>({hop['ip_address']})<br><b>Location:</b> {hop['location']['city']}, {hop['location']['country']}<br><b>ISP:</b> {hop['location']['isp']}<br><b>RTTs (ms):</b> {', '.join(map(str, [f'{r:.2f}' for r in hop['rtts']])) if hop['rtts'] else '*'}"
                    folium.Marker(
                        location=[hop['location']['lat'], hop['location']['lon']],
                        popup=folium.Popup(popup_content, max_width=300)
                    ).add_to(m)
        m.save(filename)
        print(f"HTML report saved to: {filename}")
        return True
    except Exception as e:
        print(f"Error generating HTML report to {filename}: {e}")
        return False

def display_results_table(results):
    """Display traceroute results in a table format."""
    for target, hops in results.items():
        print(f"\nTraceroute results for {target}:")
        table_data = []
        for hop in hops:
            rtt_str = ", ".join(map(str, [f"{r:.2f}" for r in hop['rtts']])) if hop['rtts'] else "*"
            table_data.append([
                hop['hop'],
                hop['ip_address'],
                hop['hostname'],
                hop['location']['country'],
                hop['location']['city'],
                hop['location']['isp'],
                rtt_str
            ])
        print(tabulate(table_data, headers=["Hop", "IP Address", "Hostname", "Country", "City", "ISP", "RTTs (ms)"], tablefmt="pretty"))

def main():
    print_banner()
    ensure_report_folder()
    parser = argparse.ArgumentParser(description="Advanced Traceroute Tool")
    parser.add_argument("targets", nargs='+', help="Target hostnames or IP addresses (space-separated)")
    parser.add_argument("-p", "--protocol", default="icmp", choices=['icmp', 'tcp', 'udp'], help="Protocol to use (icmp, tcp, udp)")
    parser.add_argument("--port", type=int, help="Destination port for TCP/UDP traceroute")
    parser.add_argument("-m", "--max-hops", type=int, default=DEFAULT_MAX_HOPS, help="Maximum number of hops")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout per hop in seconds")
    parser.add_argument("-q", "--probes", type=int, default=DEFAULT_PROBES, help="Number of probes per hop")
    parser.add_argument("-n", "--no-resolve", action="store_true", help="Do not resolve hostnames")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--json", action="store_true", help="Save results in JSON format")
    parser.add_argument("--csv", action="store_true", help="Save results in CSV format")
    parser.add_argument("--html", action="store_true", help="Generate an HTML report with map")
    args = parser.parse_args()

    if args.protocol in ['tcp', 'udp'] and args.port is None:
        print("Warning: Using TCP or UDP protocol without specifying a port. Some traceroute implementations may behave unexpectedly.")

    results = {}
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(perform_traceroute, target, args.protocol, args.port, args.max_hops, args.timeout, args.probes, not args.no_resolve, args.verbose): target for target in args.targets}
        for future in as_completed(futures):
            target = futures[future]
            hops = future.result()
            if hops:
                results[target] = hops
            else:
                print(f"Traceroute failed or returned no data for {target}. Skipping saving results for this target.")

    if results:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        for target, hops in results.items():
            target_name = target.replace(".", "_")  # Replace dots with underscores for filenames
            if args.json:
                save_results_json({target: hops}, os.path.join(REPORT_FOLDER, f"traceroute_results_{target_name}_{timestamp}.json"))
            if args.csv:
                save_results_csv({target: hops}, os.path.join(REPORT_FOLDER, f"traceroute_results_{target_name}_{timestamp}.csv"))
            if args.html:
                generate_html_report({target: hops}, os.path.join(REPORT_FOLDER, f"traceroute_report_{target_name}_{timestamp}.html"))
        if args.verbose:
            display_results_table(results)
    else:
        print("No traceroute results to save.")

if __name__ == "__main__":
    main()