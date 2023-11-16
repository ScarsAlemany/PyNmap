import nmap
import logging
import ipaddress
import socket
from pymetasploit3.msfrpc import MsfRpcClient
import sys
import argparse
import json

# Function to set up logging
def setup_logging(log_file=None, verbose=False):
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=3)
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)

    return logger

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

# Function to check if a host is up using ICMP ping
def is_host_up(host):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=host, arguments='-sn', timeout=60)
        return host in scanner.all_hosts()
    except Exception as e:
        logger.error(f"Error checking if host {host} is up: {e}")
        return False

# Function to check if a port is open using a socket connection
def is_port_open(host, port, timeout=10):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception as e:
        logger.error(f"Error checking if port {port} is open on host {host}: {e}")
        return False

# Function to scan a single host
def scan_host(host, ports, logger, retry_count=3, timeout=600):
    for _ in range(retry_count):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=host, arguments=f'-p {ports} -sV -f', timeout=timeout)
            return scanner[host]
        except nmap.PortScannerError as e:
            logger.error(f"Error scanning host {host}: {e}")
            continue
        except Exception as e:
            logger.error(f"Unexpected error while scanning host {host}: {e}")
            break
    return {}

# Establish a connection to the MSF RPC server
def msf_connect(password, server='127.0.0.1', port=55553):
    try:
        client = MsfRpcClient(password, server=server, port=port)
        return client
    except Exception as e:
        print(f"Failed to connect to Metasploit RPC: {e}")
        sys.exit(1)

# Function to check if a module exists in Metasploit
def check_module_exists(client, module_type, module_name):
    modules = client.modules.list[module_type]
    return module_name in modules

# Main function to handle command line arguments and call the scan functions
def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument('--hosts', type=str, required=True, help='Comma-separated list of hosts to scan')
    parser.add_argument('--ports', type=str, default='22-80', help='Port range to scan, e.g., "22-80"')
    parser.add_argument('--log-file', type=str, help='Path to the log file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--msf-password', type=str, required=True, help='Password for the Metasploit RPC server')
    parser.add_argument('--msf-module-type', type=str, required=True, help='Type of the Metasploit module to check')
    parser.add_argument('--msf-module-name', type=str, required=True, help='Name of the Metasploit module to check')

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(log_file=args.log_file, verbose=args.verbose)

    # Validate the hosts and port range
    hosts = args.hosts.split(',')
    ports = args.ports

    if not all(is_valid_ip_network(host) for host in hosts):
        logger.error("Invalid host list provided.")
