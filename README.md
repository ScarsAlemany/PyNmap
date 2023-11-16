Description

This Network Scan Utility is a Python script that leverages nmap to perform network scans and interacts with the Metasploit framework. It provides a command-line interface for specifying targets, ports, and various other options. The script supports output in different formats and includes features like retries for failed scans, verbose logging, and signal handling for graceful termination.

Features

Perform nmap scans on specified hosts or IP ranges.
Check results against the NVD and Metasploit databases.
Retry failed scans a specified number of times.
Save scan results in JSON, CSV, or HTML formats (JSON implemented, others are placeholders).
Output logging to both console and file.
Verbose mode for debugging purposes.
Signal handling for graceful script interruption.
Configure scan timeout to prevent indefinitely long scans.
Organize scan results and logs into a specified output directory.
Prerequisites
Python 3.6+
nmap: https://nmap.org/download.html
pymetasploit3: Can be installed via pip install pymetasploit3
Installation
Clone the repository or download the script directly to your local machine.

git clone https://github.com/ScarsAlemany/PyNmap
cd network-scan-utility

(Optional) Install the required Python packages:

pip install -r requirements.txt

Usage

Run the script with the following command, replacing the placeholder arguments with your own:

python network_scan.py [hosts...] [options]
Options:

--ports PORT_RANGE: Specify the ports to scan (default: '22-80').

--output OUTPUT_FILE: Set the output file for the scan results (default: 'scan_results.json').

--msf-password PASSWORD: The password for Metasploit RPC (required).

--msf-port PORT: Metasploit RPC port (default: 55553).

--max-concurrent-scans MAX_SCANS: Maximum number of concurrent scans (default: 10).

--log-file LOG_FILE: Log file to save script output (optional).

--verbose: Enable verbose mode for debugging.

--retry-count RETRIES: Number of retry attempts for failed scans (default: 3).

--output-format FORMAT: Output format for scan results (json/csv/html) (default: "json").

--timeout TIMEOUT: Timeout for each scan in seconds (default: 600).

--output-directory OUTPUT_DIR: Directory to save scan results and logs (default: "output").


Example:

python network_scan.py 192.168.1.0/24 --ports 22-443 --output-directory scan_data --log-file scan.log --verbose
License
This script is open source and licensed under the MIT License.
