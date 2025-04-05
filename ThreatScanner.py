#!/usr/bin/env python3
import argparse
import configparser
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
import logging.handlers
from datetime import datetime
import socket
import subprocess
import pdb
import tldextract  # Librería para extraer dominio y sufijo
import glob
import threading
import time
import ipaddress  # Para validar direcciones IP

# --- Función para validar dominio público ---
def is_valid_public_domain(domain: str) -> bool:
    """
    Verifica si un dominio es válido para internet:
      - No termina en ".local"
      - Contiene al menos un punto.
      - No contiene guiones bajos (que no son comunes en hostnames públicos)
    """
    if domain.lower().endswith('.local'):
        return False
    if '.' not in domain:
        return False
    if '_' in domain:
        return False
    return True

# --- Cargar configuración desde el fichero ---
config = configparser.ConfigParser()
config.read("scanner.conf")

API_VT_KEY   = config.get("DEFAULT", "API_VT_KEY", fallback="")
API_AV_KEY   = config.get("DEFAULT", "API_AV_KEY", fallback="")
VT_URL       = config.get("DEFAULT", "VT_URL", fallback="https://www.virustotal.com/api/v3/")
OTX_SERVER   = config.get("DEFAULT", "OTX_SERVER", fallback="https://otx.alienvault.com/")
USER_AGENT   = config.get("DEFAULT", "USER_AGENT", fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0")
max_workers  = config.getint("DEFAULT", "max_workers", fallback=10)

# Instanciar objeto OTX
otx = OTXv2(API_AV_KEY, server=OTX_SERVER, user_agent=USER_AGENT)

# Constantes para los ficheros de persistencia
PROCESSED_IPS_FILE = "processed_ips.txt"
PROCESSED_HOSTS_FILE = "processed_hosts.txt"

# Inicializar locks para acceso a ficheros
processed_ips_lock = threading.Lock()
processed_hosts_lock = threading.Lock()

# Argumentos de línea de comandos
parser = argparse.ArgumentParser(
    description='Malicious Checker with VirusTotal, AlienVault OTX, and ThreatFox'
)
parser.add_argument('--ip', help='IP ej: 4.4.4.4', required=False)
parser.add_argument('--host', help='Hostname ej: www.example.com', required=False)
parser.add_argument('--url', help='URL ej: http://www.example.com', required=False)
parser.add_argument('--hash', help='Hash de un archivo ej: 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument('--file', help='Ruta a un archivo, ej: malware.exe', required=False)
parser.add_argument('--hostfile', help='Archivo con múltiples host', required=False)
parser.add_argument('--IPfile', help='Archivo con múltiples IPs', required=False)
parser.add_argument('--skip-ids', help='Análisis directo sin soporte de NIDS (Zeek o Suricata)', action='store_true')
parser.add_argument(
    '--engine',
    help='Especifica qué motores de inteligencia usar: threatfox, otx, virustotal o all',
    choices=['threatfox', 'otx', 'virustotal', 'all'],
    nargs="+",
    required=True
)
parser.add_argument('--log-format', help='Logging format: json or syslog', choices=['json', 'syslog'], default='json')
parser.add_argument('--process-zeek', help='Monitorea continuamente los logs de Zeek', action='store_true')
args = vars(parser.parse_args())

# --- Formateadores de logging ---
class JSONFormatter(logging.Formatter):
    """Formato personalizado para logging en formato JSON."""
    def format(self, record):
        log_record = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'hostname': socket.gethostname(),
            'level': record.levelname,
            'message': record.getMessage(),
            'engine': getattr(record, 'engine', 'unknown')
        }
        return json.dumps(log_record)

class SyslogFormatter(logging.Formatter):
    """Formato personalizado para logging en formato Syslog."""
    def format(self, record):
        hostname = socket.gethostname()
        timestamp = datetime.fromtimestamp(record.created).isoformat()
        return f"{timestamp} {hostname} Intel[1]: {record.getMessage()}"

def setup_logger(log_format):
    """Configura el logger para escribir en /var/log/intel.log."""
    logger = logging.getLogger("Intel")
    logger.setLevel(logging.INFO)
    if log_format == 'json':
        formatter = JSONFormatter()
    else:
        formatter = SyslogFormatter()
    file_handler = logging.FileHandler("/var/log/intel.log", mode='a')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

# Inicializar el logger
threat_logger = setup_logger(args['log_format'])

def write_to_file(engine, message):
    """Escribe un mensaje en el log con un formato específico."""
    threat_logger.info(message, extra={'engine': engine})

# --- Funciones de persistencia mediante ficheros ---
def already_processed(ioc: str, filename: str, lock: threading.Lock) -> bool:
    """Utiliza grep para comprobar si el IOC ya está en el fichero."""
    with lock:
        try:
            result = subprocess.run(
                ["grep", "-Fxq", ioc, filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

def mark_processed(ioc: str, filename: str, lock: threading.Lock):
    """Añade el IOC al fichero de persistencia."""
    with lock:
        with open(filename, 'a') as f:
            f.write(ioc + "\n")

def vt_request(endpoint):
    headers = {"x-apikey": API_VT_KEY}
    response = requests.get(f"{VT_URL}{endpoint}", headers=headers, timeout=10)
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
                # Si la búsqueda es por host, filtrar solo aquellos IOCs cuyo dominio coincida
                if item_type == "host" and comments and comments.get("data"):
                    valid_descriptions = []
                    for collection in comments["data"]:
                        candidate = collection['attributes']['name']
                        search_ext = tldextract.extract(item_value)
                        candidate_ext = tldextract.extract(candidate)
                        effective_search = f"{search_ext.domain}.{search_ext.suffix}"
                        effective_candidate = f"{candidate_ext.domain}.{candidate_ext.suffix}"
                        if effective_search == effective_candidate:
                            valid_descriptions.append(f"Description: {candidate}")
                    if not valid_descriptions:
                        return
                    description_text = "; ".join(valid_descriptions)
                else:
                    if comments and comments.get("data"):
                        description_text = "; ".join(
                            [f"Description: {collection['attributes']['name']}" for collection in comments["data"]]
                        )
                    else:
                        description_text = ""
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
    global ip_src, ip_dst, port_src, port_dst
    pool = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
    data = {'query': 'search_ioc', 'search_term': search_term}
    json_data = json.dumps(data)
    response = pool.request("POST", "/api/v1/", body=json_data, headers={'Content-Type': 'application/json'}, timeout=10)
    response_data = json.loads(response.data.decode("utf-8", "ignore"))
    if response_data["query_status"] == "ok":
        for item in response_data.get("data", []):
            candidate = item['ioc']
            if item_type == "host":
                search_ext = tldextract.extract(search_term)
                candidate_ext = tldextract.extract(candidate)
                effective_search = f"{search_ext.domain}.{search_ext.suffix}"
                effective_candidate = f"{candidate_ext.domain}.{candidate_ext.suffix}"
                if effective_search != effective_candidate:
                    continue
            message = (f"ThreatFox: Search: {search_term} | {item_type.capitalize()} detected: {candidate} | Malware: "
                       f"{item['malware']} | Confidence: {item['confidence_level']}% | First Seen: {item['first_seen']} | "
                       f"Last Seen: {item['last_seen']} | Details: \"{item['malware_malpedia']}\" | Context: ip_src: {ip_src} port_src: {port_src} ip_dest: {ip_dst} port_dest: {port_dst}")
            print(message)
            write_to_file("threatfox", message)
        ip_src = ""
        ip_dst = ""
        port_src = ""
        port_dst = ""

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
            items = [item.strip() for item in f if item.strip()]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_engines, item_type, item): item for item in items}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error processing {item_type} {futures[future]}: {e}")
    except Exception as e:
        print(f"Error processing {item_type} file {file}: {e}")

def execute_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        return ", ".join(result.stdout.splitlines())
    else:
        print(f"Error ejecutando el comando: {command}")
        print(result.stderr)
        return None

def check_engines(item_type, item_value):
    global ip_src, port_src, ip_dst, port_dst

    # Para búsquedas por host, validar que el dominio es válido
    if item_type == "host" and not is_valid_public_domain(item_value):
        write_to_file("scanner", f"Se omite {item_value}: dominio no válido para internet.")
        print(f"Se omite {item_value}: dominio no válido para internet.")
        return

    if not args['skip_ids']:
        command_get_ip_src = f"grep {item_value} /opt/zeek/logs/current/*.log | awk '{{print $3}}' | grep -E '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$' | sort -u"
        command_get_port_src = f"grep {item_value} /opt/zeek/logs/current/*.log | awk '{{print $4}}' | grep -E '^[0-9]{{1,5}}$' | sort -u"
        command_get_ip_dst = f"grep {item_value} /opt/zeek/logs/current/*.log | awk '{{print $5}}' | grep -E '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$' | sort -u"
        command_get_port_dst = f"grep {item_value} /opt/zeek/logs/current/*.log | awk '{{print $6}}' | grep -E '^[0-9]{{1,5}}$' | sort -u"
        ip_src = execute_command(command_get_ip_src)
        port_src = execute_command(command_get_port_src)
        ip_dst = execute_command(command_get_ip_dst)
        port_dst = execute_command(command_get_port_dst)

    for engine in args['engine']:
        write_to_file("scanner", f"Procesando motor {engine} para {item_value}")
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

# --- Función para procesar continuamente un archivo de log de Zeek ---
def process_zeek_file(filepath):
    proc = subprocess.Popen(["tail", "-n0", "-F", filepath],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True)
    while True:
        line = proc.stdout.readline()
        if not line:
            time.sleep(1)
            continue
        if line.startswith("#"):
            continue
        fields = line.strip().split()
        # Si es conn.log: procesar IPs
        if "conn.log" in filepath:
            if len(fields) >= 5:
                src = fields[2]
                dst = fields[4]
                # Procesar IP origen
                try:
                    ipaddress.ip_address(src)
                    if not already_processed(src, PROCESSED_IPS_FILE, processed_ips_lock):
                        mark_processed(src, PROCESSED_IPS_FILE, processed_ips_lock)
                        write_to_file("zeek", f"Nueva IP origen detectada: {src}")
                        check_engines("ip", src)
                except ValueError:
                    # No es una IP, se asume host
                    if not already_processed(src, PROCESSED_HOSTS_FILE, processed_hosts_lock):
                        mark_processed(src, PROCESSED_HOSTS_FILE, processed_hosts_lock)
                        write_to_file("zeek", f"Nuevo host detectado: {src}")
                        check_engines("host", src)
                # Procesar IP destino
                try:
                    ipaddress.ip_address(dst)
                    if not already_processed(dst, PROCESSED_IPS_FILE, processed_ips_lock):
                        mark_processed(dst, PROCESSED_IPS_FILE, processed_ips_lock)
                        write_to_file("zeek", f"Nueva IP destino detectada: {dst}")
                        check_engines("ip", dst)
                except ValueError:
                    if not already_processed(dst, PROCESSED_HOSTS_FILE, processed_hosts_lock):
                        mark_processed(dst, PROCESSED_HOSTS_FILE, processed_hosts_lock)
                        write_to_file("zeek", f"Nuevo host detectado: {dst}")
                        check_engines("host", dst)
        # Si es dns.log: procesar el campo "query" (se asume índice 9)
        elif "dns.log" in filepath:
            if len(fields) > 9:
                query = fields[9]
                if not already_processed(query, PROCESSED_HOSTS_FILE, processed_hosts_lock):
                    mark_processed(query, PROCESSED_HOSTS_FILE, processed_hosts_lock)
                    write_to_file("zeek", f"Nuevo host (DNS query) detectado: {query}")
                    check_engines("host", query)

# --- Función para iniciar el procesamiento continuo de logs de Zeek ---
def process_zeek_logs():
    # Filtrar únicamente los logs de conn.log y dns.log
    files = glob.glob("/opt/zeek/logs/current/*conn.log") + glob.glob("/opt/zeek/logs/current/*dns.log")
    threads = []
    for f in files:
        t = threading.Thread(target=process_zeek_file, args=(f,))
        t.daemon = True
        t.start()
        threads.append(t)
    # Mantener el proceso activo
    for t in threads:
        t.join()

# --- Inicio del procesamiento según argumentos ---
print("Iniciando ciclo de comprobaciones...")
write_to_file("scanner", "Iniciando ciclo de comprobaciones...")

if args.get('process_zeek'):
    # Modo continuo: procesar únicamente los logs de Zeek (conn.log y dns.log)
    process_zeek_logs()
else:
    if args.get('ip'):
        check_engines("ip", args['ip'])
    if args.get('host'):
        check_engines("host", args['host'])
    if args.get('url'):
        check_engines("url", args['url'])
    if args.get('hash'):
        check_engines("files", args['hash'])
    if args.get('file'):
        check_file(args['file'])
    if args.get('hostfile'):
        process_file(args['hostfile'], "host")
    if args.get('IPfile'):
        process_file(args['IPfile'], "ip")

