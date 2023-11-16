import nmap
import json
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymetasploit3.msfrpc import MsfRpcClient
from tqdm import tqdm
import argparse
import os
import signal
import sys
import time

# Function to set up logging
def setup_logging(log_file=None, verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

# Function to parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Nmap Scan and Check against NVD and Metasploit")
    parser.add_argument('hosts', nargs='+', help="Hosts to scan (e.g., '192.168.1.0/24')", metavar='HOST')
    parser.add_argument('--ports', help="Ports to scan (e.g., '22-80')", default='22-80', metavar='PORT_RANGE')
    parser.add_argument('--output', help="Output file to save the scan results", default="scan_results.json", metavar='OUTPUT_FILE')
    parser.add_argument('--msf-password', help="Metasploit RPC password", required=True, metavar='PASSWORD')
    parser.add_argument('--msf-port', help="Metasploit RPC port", default=55553, metavar='PORT', type=int)
    parser.add_argument('--max-concurrent-scans', help="Maximum number of concurrent scans", default=10, type=int, metavar='MAX_SCANS')
    parser.add_argument('--log-file', help="Log file to save script output (optional)", metavar='LOG_FILE')
    parser.add_argument('--verbose', help="Enable verbose mode for debugging", action='store_true')
    parser.add_argument('--retry-count', help="Number of retry attempts for failed scans", default=3, type=int, metavar='RETRIES')
    parser.add_argument('--output-format', help="Output format for scan results (json/csv/html)", default="json", metavar='FORMAT')
    parser.add_argument('--timeout', help="Timeout for each scan in seconds", default=600, type=int, metavar='TIMEOUT')
    parser.add_argument('--output-directory', help="Directory to save scan results and logs", default="output", metavar='OUTPUT_DIR')
    return parser.parse_args()

# Function to validate IP network
def is_valid_ip_network(address):
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False

# Function to validate port range
def is_valid_port_range(port_range):
    try:
        start_port, end_port = (int(p) for p in port_range.split('-'))
        return 0 <= start_port <= 65535 and 0 <= end_port <= 65535
    except ValueError:
        return False

# Function to scan a single host
def scan_host(host, ports, logger, retry_count=3, timeout=600):
    for _ in range(retry_count):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=host, arguments=f'-p {ports} -sV', timeout=timeout)
            return scanner[host]
        except nmap.PortScannerError as e:
            logger.error(f"Error scanning host {host}: {e}")
            continue
        except Exception as e:
            logger.error(f"Unexpected error while scanning host {host}: {e}")
            break
    return {}

# Main function
def main():
    args = parse_arguments()
    logger = setup_logging(args.log_file, args.verbose)

    def signal_handler(sig, frame):
        logger.info("Scan interrupted by the user.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Validate IP range and port range
    if not all(is_valid_ip_network(host) for host in args.hosts):
        logger.error("Invalid IP range format.")
        exit(1)

    if not is_valid_port_range(args.ports):
        logger.error("Invalid port range format.")
        exit(1)

    # Initialize Metasploit RPC Client
    try:
        msf = MsfRpcClient(args.msf_password, port=args.msf_port)
    except Exception as e:
        logger.error(f"Failed to initialize Metasploit RPC client: {e}")
        exit(1)

    # Set up ThreadPoolExecutor for concurrent scanning
    try:
        with ThreadPoolExecutor(max_workers=args.max_concurrent_scans) as executor:
            # Dictionary to store future to host mappings
            future_to_host = {executor.submit(scan_host, host, args.ports, logger, args.retry_count, args.timeout): host for host in args.hosts}
            # Use tqdm for progress indication
            progress_bars = tqdm(as_completed(future_to_host), total=len(args.hosts), desc=f'Scanning (0/{len(args.hosts)})', unit='host')
            completed_scans = 0

            # Result dictionary
            results = {}
            # Collect results as they are completed
            for future in progress_bars:
                host = future_to_host[future]
                try:
                    result = future.result()
                    if result:
                        results[host] = result
                    completed_scans += 1
                    progress_bars.set_description(f'Scanning ({completed_scans}/{len(args.hosts)})')
                except Exception as e:
                    logger.error(f"Error obtaining scan result for {host}: {e}")
                    results[host] = {}

        # Create the output directory if it doesn't exist
        output_directory = args.output_directory
        os.makedirs(output_directory, exist_ok=True)

        # Save or process results based on the selected output format
        output_file_path = os.path.join(output_directory, args.output)
        with open(output_file_path, 'w') as file_out:
            if args.output_format == "json":
                json.dump(results, file_out, indent=4)
                logger.info(f"Scan results have been saved to {output_file_path}.")
            elif args.output_format == "csv":
                # Implement CSV output format here
                pass
            elif args.output_format == "html":
                # Implement HTML output format here
                pass
            else:
                logger.error("Invalid output format. Supported formats: json, csv, html")
    except KeyboardInterrupt:
        logger.info("Scan interrupted by the user.")

if __name__ == "__main__":
    main()
