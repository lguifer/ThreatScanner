# Malicious Checker

A Python script that checks for malicious indicators using VirusTotal, AlienVault OTX, and ThreatFox. This tool allows you to scan IPs, domains, URLs, file hashes, and even whole files containing multiple IPs or hostnames.

## Features

- **VirusTotal**: Check IPs, domains, URLs, or file hashes.
- **AlienVault OTX**: Query malicious indicators by IP, domain, URL, or file hash.
- **ThreatFox**: Search for indicators of compromise (IOCs) on ThreatFox.
- **Multithreaded Processing**: Supports multiple simultaneous queries for faster results.

## Requirements

- Python 3.6+
- Required libraries: `requests`, `argparse`, `OTXv2`, `concurrent.futures`, `urllib3`

Install dependencies with:
```bash
pip install requests OTXv2 urllib3
```

## Setup

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/malicious-checker.git
    cd malicious-checker
    ```

2. Insert your API keys for VirusTotal and AlienVault OTX in the script:
    ```python
    API_VT_KEY = '<put-your-api-key>'  # VirusTotal API key
    API_AV_KEY = '<put-your-api-key>'  # AlienVault OTX API key
    ```

## Usage

Run the script with the following arguments:

```bash
python3 malicious_checker.py --engine <engines> [options]
```

### Arguments

- **--engine**: Choose the intelligence engines to use: `threatfox`, `otx`, `virustotal`, or `all`.
- **--ip**: Specify an IP address to check (e.g., `4.4.4.4`).
- **--host**: Specify a hostname to check (e.g., `www.example.com`).
- **--url**: Specify a URL to check (e.g., `http://www.example.com`).
- **--hash**: Specify a file hash to check (e.g., `7b42b35832855ab4ff37ae9b8fa9e571`).
- **--file**: Path to a file to check.
- **--hostfile**: File containing multiple hostnames, each on a new line.
- **--IPfile**: File containing multiple IP addresses, each on a new line.

### Examples

#### Checking a single IP with VirusTotal
```bash
python3 malicious_checker.py --ip 8.8.8.8 --engine virustotal
```

#### Checking a URL on all engines
```bash
python3 malicious_checker.py --url "http://example.com" --engine all
```

#### Checking a file with multiple hosts
```bash
python3 malicious_checker.py --hostfile hosts.txt --engine otx
```

## License

This project is licensed under the MIT License.
```
