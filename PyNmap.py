from flask import Flask, request, render_template, jsonify
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
import socket

app = Flask(__name__)

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

# Flask route for the home page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Extract data from form
        hosts = request.form.get('hosts')
        ports = request.form.get('ports', '22-80')
        # ... (other form fields)

        # Prepare arguments for scanning
        args = {
            'hosts': hosts.split(','),  # Split the hosts by comma
            'ports': ports,
            # ... (other arguments)
        }

        # Call your main scanning function here with the provided arguments
        results = scan_network(args)
        
        # Return the results as JSON or render another template
        return jsonify(results)

    return render_template('index.html')

# Function to start the scanning (this is a placeholder, modify according to your script's logic)
def scan_network(args):
    # Your scanning logic goes here
    # For example, you might call scan_host() for each host
    return {"result": "Scanning completed"}

if __name__ == '__main__':
    app.run(debug=True)
