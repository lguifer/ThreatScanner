# ThreatScanner - FAQ

Este documento responde a las preguntas frecuentes (FAQ) sobre el funcionamiento y uso de **ThreatScanner**, una herramienta de detección de IOCs basada en VirusTotal, AlienVault OTX y ThreatFox.

---

### ¿Qué hace ThreatScanner?

ThreatScanner analiza IPs, dominios, URLs y hashes de archivos para detectar amenazas conocidas mediante consultas a:

- [VirusTotal](https://www.virustotal.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Abuse.ch ThreatFox](https://threatfox.abuse.ch/)

También puede analizar listas de indicadores o entradas individuales por línea de comandos, sin necesidad de integración con NIDS.

---

### ¿Cómo se usa?

Ejemplos:

```bash
# Analizar una IP con todos los motores
python3 threatscanner.py --ip 8.8.8.8 --engine all

# Analizar dominios desde un archivo con VirusTotal y OTX
python3 threatscanner.py --hostfile dominios.txt --engine virustotal otx

# Ejecutar el análisis sin usar información contextual de Zeek
python3 threatscanner.py --ip 1.1.1.1 --engine all --skip-ids
```

---

### ¿Qué configuración requiere?

Debes crear un archivo `ThreatScanner.conf` con estas claves:

```ini
[DEFAULT]
API_VT_KEY = tu_api_key_virustotal
API_AV_KEY = tu_api_key_otx
API_TF_KEY = tu_api_key_threatfox
VT_URL = https://www.virustotal.com/api/v3/
OTX_SERVER = https://otx.alienvault.com/
USER_AGENT = Mozilla/5.0 (...)
max_workers = 10
```

---

### ¿Qué hace el parámetro --skip-ids?

Cuando se incluye `--skip-ids`, ThreatScanner desactiva la búsqueda de contexto en logs de Zeek (como IPs relacionadas o puertos), y consulta directamente los indicadores proporcionados. Es útil para entornos sin NIDS o análisis rápido.

---

### ¿Evita escaneos duplicados?

Sí. ThreatScanner guarda los IOCs ya procesados en:

- `processed_ips.txt`
- `processed_hosts.txt`

Usa `grep` para evitar repetir consultas.

---

### ¿Dónde se guarda el log?

Por defecto en:

```
/var/log/intel.log
```

Formato configurable:

- `--log-format json`
- `--log-format syslog`

---

### ¿Puedo controlar qué motor usar?

Sí, con el argumento `--engine`, puedes usar uno o varios:

- `virustotal`
- `otx`
- `threatfox`
- `all`

---

### ¿Puede analizar archivos?

Sí. Puedes pasar un hash con `--hash` o un archivo con `--file` (se calcula su hash MD5 automáticamente).

---

### ¿Qué pasa si un motor no responde?

El error se imprime en consola y en el log, pero no interrumpe el resto del análisis.

---

### ¿Detecta falsos positivos?

No. ThreatScanner solo informa de coincidencias con fuentes OSINT. La interpretación final depende del analista.

---

### ¿Contribuciones?

Puedes abrir issues o pull requests en GitHub. El código está modularizado para facilitar mejoras por comunidad.

---

### ¿Soporta TLS o APIs privadas?

Sí. Las API keys se gestionan desde el archivo de configuración, y puedes adaptar el cliente a endpoints TLS si lo deseas.

---

### ¿Hay soporte para exportar los resultados?

Actualmente los logs se guardan en `/var/log/intel.log`. Puedes usar `jq` o `awk` para procesarlos.
