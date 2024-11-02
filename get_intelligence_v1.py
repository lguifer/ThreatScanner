#!/usr/bin/env python3
import argparse
import hashlib
import requests
import json
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from OTXv2 import OTXv2
import get_malicious
import pdb
import re
import base64

# API keys and endpoints
API_VT_KEY = '7f268c7b079195b08862e0b58aec8d040da3820bdd787a78f42ab63a2be89b90'  # VirusTotal API key
API_AV_KEY = '63ae7b7730e499194ac41e24f1d70bd41ea4dd4229d0d2d6647eb866fc3c575c'  # AlienVault OTX API key
VT_URL = 'https://www.virustotal.com/api/v3/'
OTX_SERVER = 'https://otx.alienvault.com/'
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"

# Instantiate OTX object
otx = OTXv2(API_AV_KEY, server=OTX_SERVER, user_agent=USER_AGENT)

# General variable for max workers
max_workers = 100

# Argument configuration
parser = argparse.ArgumentParser(description='Malicious Checker with VirusTotal, AlienVault OTX, and ThreatFox')
parser.add_argument('--ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument('--host', help='Hostname eg; www.example.com', required=False)
parser.add_argument('--url', help='URL eg; http://www.example.com', required=False)
parser.add_argument('--hash', help='Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument('--file', help='Path to a file, eg; malware.exe', required=False)
parser.add_argument('--hostfile', help='File with multiple hosts', required=False)
parser.add_argument('--IPfile', help='File with multiple IPs', required=False)
parser.add_argument(
    '--engine',
    help='Specify which intelligence engines to use: threatfox, av-OTX, virustotal, or all',
    choices=['threatfox', 'otx', 'virustotal', 'all'],
    nargs="+",
    required=True
)
args = vars(parser.parse_args())

def vt_request(endpoint):
    """Makes a request to the VirusTotal API."""
    headers = {
        "x-apikey": API_VT_KEY
    }
    response = requests.get(f"{VT_URL}{endpoint}", headers=headers)
    return response.json()

def check_virustotal(item_type, item_value):
    """Checks if an IP, hostname, URL, or hash is malicious."""
    try:
        response = None
        comments = None

        if item_type == "ip":
            response = vt_request(f"ip_addresses/{item_value}")
            comments = vt_request(f"ip_addresses/{item_value}/collections")
        
        elif item_type == "host":
            response = vt_request(f"domains/{item_value}")
            comments = vt_request(f"domains/{item_value}/collections")
        elif item_type == "url":
            # Convert the string to bytes
            filtered_url = re.sub(r'^(http://|https://|ftp://|ftps://|www\.)', '', item_value)
            string_bytes = filtered_url.encode('utf-8')

            # Encode to Base64
            base64_bytes = base64.b64encode(string_bytes)

            # Convert back to string
            base64_string = base64_bytes.decode('utf-8')
            response = vt_request(f"urls/{base64_string}")
            comments = vt_request(f"urls/{base64_string}/collections")
        elif item_type == "file":
            response = vt_request(f"files/{item_value}")
            comments = vt_request(f"files/{item_value}/collections")
#        pdb.set_trace()
        if response and response.get('data'):
            alerts = response['data']['attributes']['last_analysis_stats']
            if alerts and (alerts['malicious'] != 0 or alerts['suspicious'] != 0):
                description_text = "; ".join([f"Description: {collection['attributes']['name']}" for collection in comments["data"]])
                print(f"VirusTotal: {item_type.capitalize()} detected: {item_value} -- Malicious: {alerts['malicious']} -- Suspicious: {alerts['suspicious']} -- {description_text}")
                #print("\n---------------------------------------------------------")
        
    except Exception as e:
        pass

def check_av_otx(item_type, item_value):
    """Check if an item is malicious on AlienVault OTX."""
    try:
        alerts = None
        if item_type == "ip":
            alerts = get_malicious.ip(otx, item_value)
        elif item_type == "host":
            alerts = get_malicious.hostname(otx, item_value)
        elif item_type == "url":
            alerts = get_malicious.url(otx, item_value)
        elif item_type == "hash":
            alerts = get_malicious.file(otx, item_value)
#        pdb.set_trace()
        if alerts:
            print(f'AlienVault OTX: {item_type.capitalize()} detected: {item_value} -- Alerts: {alerts}')
            #print("\n---------------------------------------------------------")
    except Exception as e:
        print(e)

def check_threatfox(item_type, search_term):
    """Searches ThreatFox for indicators of compromise (IOC) using the given search term."""
    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
    data = {
        'query': 'search_ioc',
        'search_term': search_term
    }
    json_data = json.dumps(data)
    response = pool.request("POST", "/api/v1/", body=json_data, headers={'Content-Type': 'application/json'})
    
    # Asegúrate de convertir la respuesta JSON a un diccionario
    response_data = json.loads(response.data.decode("utf-8", "ignore"))
    
    if response_data["query_status"] == "ok":  
        for item in response_data.get("data", []):  # 'data' puede no existir
            print(f"ThreatFox: {item_type.capitalize()} detected: {item['ioc']}, Malware: {item['malware']}, Confidence: {item['confidence_level']}%, "
                  f"First Seen: {item['first_seen']}, Last Seen: {item['last_seen']}, Details: {item['malware_malpedia']}")
            #print("\n---------------------------------------------------------")
    else:
        #print(f"No results found for {search_term}. Response: {response_data}")  # Manejo de errores si no hay resultados
        pass

def check_file(file_path):
    """Check if a file is malicious based on its hash."""
    try:
        file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        check_virustotal("files", file_hash)
        check_av_otx("hash", file_hash)
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")

def process_file(file, item_type):
    """Process a file with multiple entries (hosts or IPs)."""
    try:
        with open(file, 'r') as f:
            items = [item.strip() for item in f]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_engines, item_type, item): item for item in items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"Error processing {item_type} {item}: {e}")
    except Exception as e:
        print(f"Error processing {item_type} file {file}: {e}")

def check_engines(item_type, item_value):
    """Check the specified item with all selected engines."""
    for engine in args['engine']:
        if engine == 'virustotal':
            check_virustotal(item_type, item_value)
        elif engine == 'otx':
            check_av_otx(item_type, item_value)
        elif engine == 'threatfox':
            check_threatfox(item_type, item_value)

# Main script logic
if args['ip']:
    check_engines("ip", args['ip'])

if args['host']:
    check_engines("host", args['host'])

if args['url']:
    check_engines("url", args['url'])

if args['hash']:
    check_engines("files", args['hash'])

if args['file']:
    check_file(args['file'])

if args['hostfile']:
    process_file(args['hostfile'], "host")

if args['IPfile']:
    process_file(args['IPfile'], "ip")

if 'threatfox' in args['engine'] and args.get('search'):
    check_threatfox(args['search'])
