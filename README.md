# ThreatScanner

**ThreatScanner** is a Python-based tool designed to quickly scan and analyze threat indicators (IPs, domains, URLs, files, and hashes) using multiple intelligence sources like **VirusTotal**, **AlienVault OTX**, and **ThreatFox**. This script helps identify potential threats and gather detailed information on them.

## Features

- Query analysis of IPs, hostnames, URLs, files, and hashes.
- Integration with VirusTotal, AlienVault OTX, and ThreatFox APIs.
- Concurrent execution to enhance performance when analyzing multiple items.
- Supports batch analysis from text files.

## Requirements

- Python 3.6+
- Python libraries specified in `requirements.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ThreatScanner.git
   cd ThreatScanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up API keys in the code:
   - Open the main script and replace `<put-your-api-key>` with your own **VirusTotal** and **AlienVault OTX** API keys.

## Usage

Run the script with the necessary arguments to specify the type of analysis and the intelligence engines.

```bash
python ThreatScanner.py [options]
```

### Options

- `--ip` : IP address (e.g., `4.4.4.4`).
- `--host` : Hostname (e.g., `www.example.com`).
- `--url` : Full URL (e.g., `http://www.example.com`).
- `--hash` : Hash of the file to check (e.g., `7b42b35832855ab4ff37ae9b8fa9e571`).
- `--file` : Path to a file to analyze its hash.
- `--hostfile` : File with a list of hostnames.
- `--IPfile` : File with a list of IP addresses.
- `--engine` : Specify intelligence engines to use (`threatfox`, `otx`, `virustotal`, `all`).

### Examples

- Check an IP across all platforms:
  ```bash
  python ThreatScanner.py --ip 8.8.8.8 --engine all
  ```

- Analyze multiple domains in AlienVault OTX:
  ```bash
  python ThreatScanner.py --hostfile domains.txt --engine otx
  ```
