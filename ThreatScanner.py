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
import re
import base64
import logging
from datetime import datetime
import socket



# API keys and endpoints
API_VT_KEY = ''  # VirusTotal API key
API_AV_KEY = ''  # AlienVault OTX API key
VT_URL = 'https://www.virustotal.com/api/v3/'
OTX_SERVER = 'https://otx.alienvault.com/'
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0"

# Instantiate OTX object
otx = OTXv2(API_AV_KEY, server=OTX_SERVER, user_agent=USER_AGENT)

# General variable for max workers
max_workers = 10

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

class CustomFormatter(logging.Formatter):
    """Formato personalizado para incluir milisegundos en los registros."""
    def formatTime(self, record, datefmt=None):
        """Sobrescribe el formato de tiempo para agregar milisegundos."""
        ct = datetime.fromtimestamp(record.created)
        if datefmt:
            s = ct.strftime(datefmt)
        else:
            s = ct.strftime("%Y-%m-%d %H:%M:%S")
        return f"{s},{int(record.msecs):03d}"  # Agrega milisegundos manualmente

# Configuración del logger
def setup_logger():
    """Configura el logger para escribir en /var/log/intel.log."""
    logger = logging.getLogger("Intel")
    logger.setLevel(logging.INFO)

    hostname = socket.gethostname()  # Obtiene el nombre del host
    formatter = CustomFormatter(
        #f'%(asctime)s {hostname} Intel[1]: %(message)s',
        #datefmt='%Y-%m-%d %H:%M:%S'
        f'%(message)s',

   )

    file_handler = logging.FileHandler("/var/log/intel.log", mode='a')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger

# Inicializar el logger
threat_logger = setup_logger()

# Función para escribir mensajes al log
def write_to_file(engine, message):
    """Escribe un mensaje en el log con un formato específico."""
    log_message = f"{message}"
    threat_logger.info(log_message)

def vt_request(endpoint):
    headers = {"x-apikey": API_VT_KEY}
    response = requests.get(f"{VT_URL}{endpoint}", headers=headers)
    return response.json()

def check_virustotal(item_type, item_value):
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
            filtered_url = re.sub(r'^(http://|https://|ftp://|ftps://|www\.)', '', item_value)
            base64_string = base64.b64encode(filtered_url.encode('utf-8')).decode('utf-8')
            response = vt_request(f"urls/{base64_string}")
            comments = vt_request(f"urls/{base64_string}/collections")
        elif item_type == "file":
            response = vt_request(f"files/{item_value}")
            comments = vt_request(f"files/{item_value}/collections")

        if response and response.get('data'):
            alerts = response['data']['attributes']['last_analysis_stats']
            if alerts and (alerts['malicious'] != 0 or alerts['suspicious'] != 0):
                description_text = "; ".join(
                    [f"Description: {collection['attributes']['name']}" for collection in comments["data"]]
                )
                message = (f"VirusTotal: {item_type.capitalize()} detected: {item_value} -- Malicious: "
                           f"{alerts['malicious']} -- Suspicious: {alerts['suspicious']} -- {description_text}")
                print(message)
                write_to_file("virustotal", message)

    except Exception as e:
        print(f"Error in VirusTotal check: {e}")

def check_av_otx(item_type, item_value):
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

        if alerts:
            message = f'AlienVault OTX: {item_type.capitalize()} detected: {item_value} -- Alerts: {alerts}'
            print(message)
            write_to_file("otx", message)
    except Exception as e:
        print(f"Error in AlienVault OTX check: {e}")

def check_threatfox(item_type, search_term):
    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
    data = {'query': 'search_ioc', 'search_term': search_term}
    json_data = json.dumps(data)
    response = pool.request("POST", "/api/v1/", body=json_data, headers={'Content-Type': 'application/json'})
    response_data = json.loads(response.data.decode("utf-8", "ignore"))

    if response_data["query_status"] == "ok":
        for item in response_data.get("data", []):
            message = (f"ThreatFox: Search: {search_term} | {item_type.capitalize()} detected: {item['ioc']} | Malware: "
                       f"{item['malware']} | Confidence: {item['confidence_level']}% | First Seen: {item['first_seen']} | "
                       f"Last Seen: {item['last_seen']} | Details: {item['malware_malpedia']}")
            print(message)
            write_to_file("threatfox", message)

def check_file(file_path):
    try:
        file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
        check_virustotal("files", file_hash)
        check_av_otx("hash", file_hash)
    except Exception as e:
        print(f"Error checking file {file_path}: {e}")

def process_file(file, item_type):
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
    for engine in args['engine']:
        if engine == 'virustotal':
            check_virustotal(item_type, item_value)
        elif engine == 'otx':
            check_av_otx(item_type, item_value)
        elif engine == 'threatfox':
            check_threatfox(item_type, item_value)
        elif engine == 'all':
            check_virustotal(item_type, item_value)
            check_av_otx(item_type, item_value)
            check_threatfox(item_type, item_value)

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




