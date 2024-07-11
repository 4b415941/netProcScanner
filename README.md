# netProcScanner

This PowerShell script provides comprehensive scanning capabilities for active network connections and running processes across Windows, Linux, and macOS systems. It identifies listening TCP connections and correlates them with their respective processes, capturing process names and file paths. The script calculates SHA256 hashes of these process files and queries VirusTotal API to assess their security status. If a file is flagged as suspicious by VirusTotal, the script logs the finding for further investigation, providing a valuable tool for security analysts and administrators.

## Features

- **Platform Support**: Works on Windows, Linux, and macOS.
- **Network Connections**: Identifies and logs active TCP connections in listening state.
- **Process Management**: Retrieves process names and file paths associated with active connections.
- **VirusTotal Integration**: Queries VirusTotal API using SHA256 hashes to check file reputations.
- **Logging**: Logs scan results and suspicious findings to a timestamped log file (`ScanResults_yyyyMMdd_HHmmss.log`).

## Requirements

- PowerShell 5.1 or later on Windows.
- Bash shell on Linux or macOS for Unix-style process listing.
- VirusTotal API key (replace 'YourVirusTotalApiKey' in the script).

## Usage

1. Clone the repository or download the `NetProcScanner.ps1` script.
2. Open PowerShell or terminal.
3. Run the script:
   ```bash
   PowerShell -ExecutionPolicy Bypass -File NetProcScanner.ps1

## Disclaimer

1. Use this script responsibly and ensure compliance with applicable laws and regulations.
2. VirusTotal API usage is subject to their terms of service and rate limits.