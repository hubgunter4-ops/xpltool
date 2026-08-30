#!/usr/bin/env python3
"""
=============================================================================
  XPL TOOLKIT — Vulnerability Exploitation Interactive Framework
  Basado en la skill "xpl" de Manus
=============================================================================
  Flujo:  Sesión → Reconocimiento → Verificación → CVE Lookup → Exploits
          → Ejecución → Post-Explotación → Reporte
  Incluye: verificación/instalación de herramientas, detección automática,
           integración de cve_lookup.py con API Key NVD.
=============================================================================
"""

import os
import sys
import re
import json
import csv
import time
import datetime
import subprocess
import argparse
import shlex
import shutil

# =============================================================================
#  CONFIGURACIÓN GLOBAL
# =============================================================================

NVD_API_KEY = "c135c920-d9f5-48d3-8a94-8c200a43aea2"
SESSIONS_DIR = os.path.expanduser("/home/ubuntu/sessions")
SKILL_DIR = os.path.expanduser("/home/ubuntu/skills/xpl")

WORDLISTS = {
    "ssh_users": os.path.join(SKILL_DIR, "references/wordlists/ssh_users.txt"),
    "ssh_pass":   os.path.join(SKILL_DIR, "references/wordlists/ssh_pass.txt"),
    "web_common": os.path.join(SKILL_DIR, "references/wordlists/web_common.txt"),
    "db_default": os.path.join(SKILL_DIR, "references/wordlists/db_default.txt"),
}

NMAP_SCRIPTS = {
    "general":  "vuln,auth,default",
    "http":     "http-vuln-*,http-enum,http-auth",
    "smb":      "smb-vuln-*,smb-enum-shares,smb-os-discovery",
    "ssh":      "ssh-auth-methods,ssh-run",
    "ftp":      "ftp-anon,ftp-vuln-*,ftp-syst",
    "database": "mysql-vuln-*,postgresql-vuln-*,ms-sql-info",
    "rdp":      "rdp-vuln-ms12-020,rdp-ntlm-info",
}

# Servicios reconocidos → herramientas + scripts recomendados
SERVICE_DETECTION = {
    "ssh":     {"port": 22,   "tools": ["hydra", "medusa"],         "scripts": "ssh"},
    "ftp":     {"port": 21,   "tools": ["hydra"],                   "scripts": "ftp"},
    "smb":     {"port": 445,  "tools": ["smbclient", "enum4linux"], "scripts": "smb"},
    "http":    {"port": 80,   "tools": ["httpx", "nmap"],           "scripts": "http"},
    "https":   {"port": 443,  "tools": ["httpx", "nmap"],           "scripts": "http"},
    "mysql":   {"port": 3306, "tools": ["hydra", "mysql"],          "scripts": "database"},
    "postgres":{"port": 5432, "tools": ["hydra", "psql"],           "scripts": "database"},
    "mssql":   {"port": 1433, "tools": ["hydra"],                   "scripts": "database"},
    "rdp":     {"port": 3389, "tools": ["hydra", "xfreerdp"],       "scripts": "rdp"},
    "dns":     {"port": 53,   "tools": ["dig", "dnsrecon"],         "scripts": "general"},
}

AUTHORIZATION_CHOICES = {
    "1": {"label": "Authorized pentest — proceed",       "action": "full"},
    "2": {"label": "CTF / Lab environment — proceed",    "action": "full"},
    "3": {"label": "Verify only, don't exploit",         "action": "verify"},
    "4": {"label": "Cancel",                              "action": "cancel"},
}


# =============================================================================
#  UTILIDADES DE COLORES Y FORMATEO
# =============================================================================

class Colors:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

def color(text, color_code):
    return f"{color_code}{text}{Colors.RESET}"

def banner():
    print(color("""
 ╔══════════════════════════════════════════════════════════╗
 ║           XPL TOOLKIT — Vulnerability Framework          ║
 ║          Basado en la skill "xpl" de Manus               ║
 ╚══════════════════════════════════════════════════════════╝
""", Colors.CYAN))

def section(title):
    print(f"\n{color('='*60, Colors.BLUE)}")
    print(f"  {color(title, Colors.BOLD)}")
    print(f"{color('='*60, Colors.BLUE)}\n")

def step(num, title):
    print(f"\n  {color(f'[Fase {num}]', Colors.YELLOW)} {color(title, Colors.BOLD)}")

def info(msg):
    print(f"  {color('[INFO]', Colors.BLUE)} {msg}")

def warn(msg):
    print(f"  {color('[WARN]', Colors.YELLOW)} {msg}")

def success(msg):
    print(f"  {color('[OK]', Colors.GREEN)} {msg}")

def error(msg):
    print(f"  {color('[ERROR]', Colors.RED)} {msg}")


# =============================================================================
#  VERIFICACIÓN E INSTALACIÓN DE HERRAMIENTAS
# =============================================================================

REQUIRED_TOOLS = {
    "nmap":       {"install": "sudo apt-get install -y nmap",                  "pkg": "nmap"},
    "hydra":      {"install": "sudo apt-get install -y hydra",                 "pkg": "hydra"},
    "sqlmap":     {"install": "sudo apt-get install -y sqlmap",                "pkg": "sqlmap"},
    "searchsploit":{"install": "sudo apt-get install -y exploitdb",            "pkg": "exploitdb"},
    "httpx":      {"install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "pkg": "httpx"},
    "cewl":       {"install": "sudo apt-get install -y cewl",                  "pkg": "cewl"},
    "gcc":        {"install": "sudo apt-get install -y gcc",                   "pkg": "gcc"},
    "subfinder":  {"install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "pkg": "subfinder"},
    "enum4linux": {"install": "sudo apt-get install -y enum4linux",            "pkg": "enum4linux"},
    "smbclient":  {"install": "sudo apt-get install -y smbclient",             "pkg": "smbclient"},
    "gobuster":   {"install": "sudo apt-get install -y gobuster",              "pkg": "gobuster"},
    "metasploit": {"install": "sudo apt-get install -y metasploit-framework",  "pkg": "metasploit-framework"},
}

def tool_installed(name):
    """Verifica si una herramienta está instalada."""
    return shutil.which(name) is not None

def check_and_install_tools(selected_tools=None):
    """Verifica qué herramientas están instaladas y ofrece instalar las faltantes."""
    section("VERIFICACIÓN DE HERRAMIENTAS")

    if selected_tools is None:
        selected_tools = list(REQUIRED_TOOLS.keys())

    installed = []
    missing = []

    for tool in selected_tools:
        cfg = REQUIRED_TOOLS.get(tool, {})
        if tool_installed(tool):
            installed.append(tool)
            success(f"{tool} — instalado")
        else:
            missing.append(tool)
            warn(f"{tool} — NO instalado")

    print(f"\n  {color('Instaladas:', Colors.GREEN)} {', '.join(installed) if installed else 'Ninguna'}")
    print(f"  {color('Faltantes:',  Colors.RED)}   {', '.join(missing) if missing else 'Ninguna'}")

    if missing:
        print(f"\n  ¿Deseas instalar las herramientas faltantes? (s/n): ", end="")
        choice = input().strip().lower()
        if choice in ("s", "si", "y", "yes"):
            for tool in missing:
                cfg = REQUIRED_TOOLS.get(tool, {})
                install_cmd = cfg.get("install", "")
                if not install_cmd:
                    continue
                info(f"Instalando {tool}...")
                try:
                    result = subprocess.run(
                        shlex.split(install_cmd),
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        success(f"{tool} instalado correctamente")
                    else:
                        error(f"Fallo al instalar {tool}: {result.stderr[:200]}")
                except subprocess.TimeoutExpired:
                    error(f"Timeout instalando {tool}")
                except Exception as e:
                    error(f"Error instalando {tool}: {e}")
        else:
            info("Continuando con las herramientas disponibles...")

    return installed + ([t for t in missing if tool_installed(t)])


# =============================================================================
#  GESTIÓN DE SESIÓN
# =============================================================================

def sanitize(text):
    return re.sub(r'[^a-zA-Z0-9]', '_', text)

def init_session(target):
    """Inicializa la estructura de sesión para un objetivo."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    target_sanitized = sanitize(target)
    session_name = f"{target_sanitized}_{timestamp}"
    base_dir = os.path.join(SESSIONS_DIR, session_name)
    assets_dir = os.path.join(base_dir, "assets")

    os.makedirs(assets_dir, exist_ok=True)

    session_md = os.path.join(base_dir, "session.md")
    with open(session_md, "w") as f:
        f.write(f"# Session: {target}\n\n")
        f.write(f"- **Target**: {target}\n")
        f.write(f"- **Start Time**: {timestamp}\n")
        f.write(f"- **Status**: IN PROGRESS\n\n")
        f.write("## Timeline\n")
        f.write("| Timestamp | Action | Result |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| {timestamp} | Session Created | Initialized structure |\n")

    return base_dir

def log_to_session(session_dir, action, result="—"):
    """Agrega una entrada a la línea de tiempo de la sesión."""
    session_md = os.path.join(session_dir, "session.md")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    with open(session_md, "a") as f:
        f.write(f"| {timestamp} | {action} | {result} |\n")

def update_session_status(session_dir, status):
    """Actualiza el estado de la sesión."""
    session_md = os.path.join(session_dir, "session.md")
    if not os.path.exists(session_md):
        return
    with open(session_md, "r") as f:
        content = f.read()
    content = content.replace("**Status**: IN PROGRESS", f"**Status**: {status}")
    with open(session_md, "w") as f:
        f.write(content)


# =============================================================================
#  CONTROL DE AUTORIZACIÓN
# =============================================================================

def request_authorization(target):
    """Solicita confirmación explícita del usuario antes de acciones intrusivas."""
    print(f"\n{color('━'*60, Colors.YELLOW)}")
    print(color("  ⚠  ADVERTENCIA DE AUTORIZACIÓN  ⚠", Colors.YELLOW))
    print(f"{color('━'*60, Colors.YELLOW)}")
    print(f"\n  El objetivo es: {color(target, Colors.BOLD)}")
    print(f"\n  La explotación enviará payloads de ataque al objetivo y puede")
    print(f"  causar interrupción del servicio. Por favor, confirma:")
    print(f"\n  1) Authorized pentest — proceed")
    print(f"  2) CTF / Lab environment — proceed")
    print(f"  3) Verify only, don't exploit")
    print(f"  4) Cancel")
    print(f"\n  Tu elección [1-4]: ", end="")
    choice = input().strip()

    if choice in AUTHORIZATION_CHOICES:
        auth = AUTHORIZATION_CHOICES[choice]
        print(f"\n  Selección: {color(auth['label'], Colors.GREEN)}")
        return auth["action"]
    else:
        warn("Entrada no válida. Cancelando.")
        return "cancel"


# =============================================================================
#  RECONOCIMIENTO WEB (httpx + subdominios)
# =============================================================================

def web_recon(target, session_dir):
    """Realiza reconocimiento web: subdominios, probing con httpx, detección de tech."""
    step(2, "Reconocimiento Web (httpx)")

    # Intentar enumerar subdominios con subfinder
    subdomains_file = os.path.join(session_dir, "assets/subdomains.txt")
    httpx_results = os.path.join(session_dir, "assets/httpx_results.txt")

    if tool_installed("subfinder"):
        info("Enumerando subdominios con Subfinder...")
        try:
            subprocess.run(
                ["subfinder", "-d", target, "-o", subdomains_file, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            if os.path.exists(subdomains_file):
                with open(subdomains_file) as f:
                    subs = [l.strip() for l in f if l.strip()]
                success(f"Subdominios encontrados: {len(subs)}")
                for s in subs[:10]:
                    print(f"      • {s}")
                if len(subs) > 10:
                    print(f"      ... y {len(subs)-10} más")
            else:
                info("No se encontraron subdominios. Usando el dominio principal.")
        except Exception as e:
            error(f"Error en Subfinder: {e}")
    else:
        info("Subfinder no disponible. Usando el dominio principal como objetivo.")
        # Crear archivo con el dominio principal
        with open(subdomains_file, "w") as f:
            f.write(f"https://{target}\nhttp://{target}\n")

    # Probing con httpx
    if tool_installed("httpx"):
        info("Probing URLs con httpx...")
        cmd = [
            "httpx", "-l", subdomains_file,
            "-title", "-status-code", "-tech-detect",
            "-silent", "-o", httpx_results
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if os.path.exists(httpx_results):
                with open(httpx_results) as f:
                    lines = [l.strip() for l in f if l.strip()]
                success(f"URLs activas detectadas: {len(lines)}")
                for line in lines[:15]:
                    print(f"      {line}")
                log_to_session(session_dir, "httpx probing", f"{len(lines)} URLs")
            else:
                warn("httpx no produjo resultados.")
        except Exception as e:
            error(f"Error en httpx: {e}")
    else:
        warn("httpx no disponible. Saltando probing web.")

    # Detección de tecnología
    info("Detección de tecnología del objetivo web...")
    tech_detected = detect_web_technology(target)
    if tech_detected:
        success(f"Tecnologías detectadas: {tech_detected}")
        log_to_session(session_dir, "Tech detection", tech_detected)
    else:
        info("No se pudieron detectar tecnologías automáticamente.")

    return httpx_results if os.path.exists(httpx_results) else None


def detect_web_technology(target):
    """Detecta tecnología web usando httpx o peticiones directas."""
    try:
        if tool_installed("httpx"):
            result = subprocess.run(
                ["httpx", "-u", f"https://{target}", "-td", "-silent"],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                return result.stdout.strip()
    except Exception:
        pass

    # Fallback: peticiones directas
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://{target}",
            headers={"User-Agent": "XPL-Toolkit/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            server = headers.get("Server", headers.get("server", ""))
            x_powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
            technologies = []
            if server:
                technologies.append(f"Server: {server}")
            if x_powered:
                technologies.append(f"X-Powered-By: {x_powered}")
            return " | ".join(technologies) if technologies else None
    except Exception:
        return None


# =============================================================================
#  VERIFICACIÓN DE VULNERABILIDAD (Nmap)
# =============================================================================

def verify_vulnerability(target, auth_mode, session_dir, service="general"):
    """Verifica vulnerabilidades usando scripts Nmap (modo seguro)."""
    step(3, "Verificación de Vulnerabilidad (Nmap)")

    scripts = NMAP_SCRIPTS.get(service, NMAP_SCRIPTS["general"])
    info(f"Scripts Nmap: {scripts}")
    info(f"Ejecutando: nmap -sV -Pn --script {scripts} {target}")

    nmap_output = os.path.join(session_dir, "assets/nmap_verify.txt")
    cmd = ["nmap", "-sV", "-Pn", f"--script={scripts}", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr

        with open(nmap_output, "w") as f:
            f.write(output)

        # Analizar resultados
        vulns_found = re.findall(r'VULNERABLE|CVE-|CRITICAL|HIGH|Vulnerability', output)
        if vulns_found:
            success(f"Posibles vulnerabilidades detectadas: {len(vulns_found)} hallazgos")
            # Mostrar líneas relevantes
            for line in output.split('\n'):
                if any(kw in line for kw in ["VULNERABLE", "CVE-", "state:", "Vulnerability"]):
                    print(f"      {line.strip()}")
        else:
            info("No se detectaron vulnerabilidades evidentes en la verificación.")

        log_to_session(session_dir, f"Nmap verify ({service})", f"{len(vulns_found)} hallazgos")
        return output
    except subprocess.TimeoutExpired:
        error("Nmap: timeout tras 300 segundos")
        return ""
    except Exception as e:
        error(f"Nmap error: {e}")
        return ""


# =============================================================================
#  DETECCIÓN AUTOMÁTICA DE SERVICIOS
# =============================================================================

def detect_services(target):
    """Detecta servicios abiertos mediante un escaneo rápido con Nmap."""
    step(0, "Detección Automática de Servicios")

    info(f"Escaneando puertos abiertos en {target}...")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-Pn", "--top-ports", "100", "--open", "-q", target],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout

        # Parsear servicios detectados
        services = []
        for line in output.split('\n'):
            # Patrón: 22/tcp   open  ssh     OpenSSH 8.2
            match = re.match(r'\s*(\d+)/tcp\s+open\s+(\S+)\s+(.*)', line)
            if match:
                port = match.group(1)
                svc = match.group(2)
                version = match.group(3).strip()
                services.append({"port": port, "service": svc, "version": version})
                print(f"      {color(port, Colors.CYAN)}/tcp  {svc:<15} {version}")

        if not services:
            info("No se detectaron servicios abiertos o el objetivo no respondió.")

        # Intentar mapear a servicios conocidos
        for svc in services:
            for known_name, known_cfg in SERVICE_DETECTION.items():
                if known_name in svc["service"].lower():
                    svc["mapped"] = known_name
                    break

        return services
    except Exception as e:
        error(f"Error en detección de servicios: {e}")
        return []


# =============================================================================
#  CVE LOOKUP (integrado con cve_lookup.py)
# =============================================================================

def cve_lookup_query(keyword, limit=50, min_severity=None, output_format="table", out_file=None):
    """
    Busca CVEs usando la API del NVD directamente (con API Key integrada).
    Basado en la lógica de cve_lookup.py.
    """
    step(4, "CVE Lookup (NVD API)")

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}

    import urllib.parse, urllib.error, urllib.request

    all_vulns = []
    start_index = 0
    page_size = min(limit, 200) if limit else 200
    delay = 0.6  # API key permite requests más frecuentes

    print(f"\n  {color(f'Buscando CVEs para:', Colors.YELLOW)} {keyword}")
    print(f"  {color(f'API Key NVD:', Colors.DIM)} {NVD_API_KEY[:8]}...")

    while True:
        params = {
            "keywordSearch": keyword,
            "startIndex": str(start_index),
            "resultsPerPage": str(page_size),
        }
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"User-Agent": "XPL-Toolkit/1.0"})
        req.add_header("apiKey", NVD_API_KEY)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                error("Error 403: límite de peticiones excedido. Espera unos segundos.")
            else:
                error(f"Error HTTP {e.code}: {e.reason}")
            break
        except urllib.error.URLError as e:
            error(f"Error de red: {e.reason}")
            break

        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        total_results = data.get("totalResults", len(all_vulns))

        print(f"  ... {len(all_vulns)}/{total_results} resultados obtenidos")

        start_index += page_size
        if limit and len(all_vulns) >= limit:
            all_vulns = all_vulns[:limit]
            break
        if start_index >= total_results:
            break

        time.sleep(delay)

    # Parsear resultados
    parsed = []
    for item in all_vulns:
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "N/A")
        published = cve_obj.get("published", "")

        # CVSS
        metrics = cve_obj.get("metrics", {})
        cvss_score = cvss_severity = cvss_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                entry = metrics[key][0]
                cvss_data = entry.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString", "")
                break

        # Descripción
        description = ""
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        parsed.append({
            "cve_id": cve_id,
            "published": published,
            "cvss_score": cvss_score,
            "severity": cvss_severity,
            "vector": cvss_vector or "",
            "description": description,
        })

    # Filtrar por severidad
    if min_severity:
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 0)
        parsed = [r for r in parsed
                  if SEVERITY_ORDER.get((r["severity"] or "").upper(), 0) >= threshold]

    # Salida
    if output_format == "table":
        if not parsed:
            print("\n  No se encontraron CVEs para esa búsqueda.")
        else:
            print(f"\n  {'CVE ID':<18} {'Severidad':<10} {'CVSS':<6} {'Publicado':<12} Descripción")
            print(f"  {'-'*100}")
            for r in parsed:
                score = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "N/A"
                sev = r["severity"] or "N/A"
                pub = r["published"][:10] if r["published"] else "N/A"
                desc = r["description"]
                desc_short = (desc[:70] + "...") if len(desc) > 70 else desc
                print(f"  {r['cve_id']:<18} {sev:<10} {score:<6} {pub:<12} {desc_short}")
            print(f"\n  Total: {len(parsed)} CVE(s) encontrados.")

    elif output_format == "json":
        path = out_file or "cve_results.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2, ensure_ascii=False)
        success(f"Resultados exportados a {path}")

    elif output_format == "csv":
        path = out_file or "cve_results.csv"
        fieldnames = ["cve_id", "published", "cvss_score", "severity", "vector", "description"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(parsed)
        success(f"Resultados exportados a {path}")

    return parsed


# =============================================================================
#  BÚSQUEDA DE EXPLOITS (searchsploit)
# =============================================================================

def search_exploits(service, version=None):
    """Busca exploits usando searchsploit."""
    step(5, "Búsqueda de Exploits (ExploitDB)")

    if not tool_installed("searchsploit"):
        warn("searchsploit no disponible. Intentando instalar...")
        try:
            subprocess.run(shlex.split("sudo apt-get install -y exploitdb"),
                           capture_output=True, text=True, timeout=60)
        except Exception:
            error("No se pudo instalar searchsploit.")
            return []

    query = service
    if version:
        query = f"{service} {version}"

    info(f"Buscando exploits para: {query}")
    try:
        result = subprocess.run(
            ["searchsploit", query, "--disable-colour", "--exclude", "DOS"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        # Parsear líneas de exploits
        exploits = []
        lines = output.strip().split('\n')
        for line in lines:
            # Buscar patrón: | path/to/exploit | CVE-XXXX-XXXX |
            if "|" in line and ("remote" in line.lower() or "local" in line.lower() or "webapps" in line.lower()):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2:
                    exploits.append({
                        "path": parts[0],
                        "title": parts[1] if len(parts) > 1 else "",
                    })

        if exploits:
            success(f"Exploits encontrados: {len(exploits)}")
            for i, ex in enumerate(exploits[:20], 1):
                print(f"      {i}. {ex['title']}")
        else:
            info("No se encontraron exploits con ese criterio.")

        return exploits
    except Exception as e:
        error(f"Error en searchsploit: {e}")
        return []


# =============================================================================
#  FUERZA BRUTA (Hydra)
# =============================================================================

def brute_force(target, service, session_dir):
    """Ejecuta fuerza bruta contra un servicio usando Hydra y wordlists de la skill."""
    step(5, "Fuerza Bruta (Hydra)")

    wordlist_users = WORDLISTS.get("ssh_users", "")
    wordlist_pass  = WORDLISTS.get("ssh_pass", "")

    # Determinar wordlist según servicio
    if service in ("ssh", "ftp"):
        users_wl = WORDLISTS.get("ssh_users", "")
        pass_wl  = WORDLISTS.get("ssh_pass", "")
    elif service in ("mysql", "postgres", "mssql"):
        users_wl = WORDLISTS.get("db_default", "")
        pass_wl  = WORDLISTS.get("db_default", "")
    else:
        users_wl = WORDLISTS.get("ssh_users", "")
        pass_wl  = WORDLISTS.get("ssh_pass", "")

    if not tool_installed("hydra"):
        warn("Hydra no disponible.")
        return None

    info(f"Hydra -L {users_wl} -P {pass_wl} {target} {service}")
    output_file = os.path.join(session_dir, "assets/hydra_output.txt")

    try:
        result = subprocess.run(
            ["hydra", "-L", users_wl, "-P", pass_wl,
             target, service, "-t", "4", "-f", "-V",
             "-o", output_file],
            capture_output=True, text=True, timeout=600
        )
        output = result.stdout + result.stderr

        with open(output_file, "w") as f:
            f.write(output)

        # Buscar credenciales encontradas
        creds = re.findall(r'\[.*\]\[.*\] host: \S+   login: (\S+)   password: (\S+)', output)
        if creds:
            success(f"Credenciales encontradas: {len(creds)}")
            for user, passwd in creds:
                print(f"      Usuario: {user} | Password: {passwd}")
            log_to_session(session_dir, f"Brute force {service}", "SUCCESS")
        else:
            info("No se encontraron credenciales válidas.")
            log_to_session(session_dir, f"Brute force {service}", "No results")

        return output
    except subprocess.TimeoutExpired:
        error("Hydra: timeout tras 600 segundos")
        return ""
    except Exception as e:
        error(f"Error en Hydra: {e}")
        return ""


# =============================================================================
#  DICIONARIOS PERSONALIZADOS (cewl)
# =============================================================================

def generate_wordlist(url, output_path, depth=2, min_len=5):
    """Genera wordlist personalizada con cewl."""
    section("Generación de Wordlist Personalizada (cewl)")

    if not tool_installed("cewl"):
        warn("cewl no disponible. Intentando instalar...")
        try:
            subprocess.run(shlex.split("sudo apt-get install -y cewl"),
                           capture_output=True, text=True, timeout=60)
        except Exception:
            error("No se pudo instalar cewl.")
            return False

    info(f"Generando wordlist desde: {url}")
    info(f"Profundidad: {depth} | Longitud mínima: {min_len}")

    try:
        result = subprocess.run(
            ["cewl", url, "-d", str(depth), "-m", str(min_len), "-w", output_path],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists(output_path):
            with open(output_path) as f:
                words = [l.strip() for l in f if l.strip()]
            success(f"Wordlist generada: {len(words)} palabras en {output_path}")
            log_to_session(None, "cewl wordlist", f"{len(words)} palabras")
            return True
        else:
            error("cewl no generó el archivo de salida.")
            return False
    except Exception as e:
        error(f"Error en cewl: {e}")
        return False


# =============================================================================
#  EXECUCIÓN DE EXPLOIT (Metasploit / SQLMap / Manual)
# =============================================================================

def execute_exploit(target, exploit_info, auth_mode, session_dir):
    """Ejecuta un exploit según el tipo."""
    step(6, "Ejecución de Exploit")

    if auth_mode == "verify":
        warn("Modo 'Verify only' activo. No se ejecutan exploits.")
        return None

    exploit_type = exploit_info.get("type", "")
    module = exploit_info.get("module", "")
    options = exploit_info.get("options", {})

    # --- Metasploit ---
    if exploit_type == "metasploit":
        return run_metasploit(target, module, options, session_dir)

    # --- SQLMap ---
    elif exploit_type == "sqlmap":
        return run_sqlmap(target, options, session_dir)

    # --- Manual (Python / C / shell) ---
    elif exploit_type == "manual":
        return run_manual_exploit(exploit_info, session_dir)

    else:
        warn(f"Tipo de exploit desconocido: {exploit_type}")
        return None


def run_metasploit(target, module, options, session_dir):
    """Ejecuta un módulo de Metasploit."""
    if not tool_installed("msfconsole"):
        warn("Metasploit no disponible. Intentando instalar...")
        return None

    info(f"Módulo: {module}")
    info(f"RHOSTS: {target}")

    # Construir comandos msfconsole
    msf_commands = [f"use {module}", f"set RHOSTS {target}"]
    for opt_name, opt_val in options.items():
        msf_commands.append(f"set {opt_name} {opt_val}")
    msf_commands.extend(["run", "exit"])

    resource_file = os.path.join(session_dir, "assets/msf_resource.rc")
    with open(resource_file, "w") as f:
        f.write("\n".join(msf_commands) + "\n")

    output_file = os.path.join(session_dir, "assets/msf_output.txt")
    info("Ejecutando Metasploit...")

    try:
        result = subprocess.run(
            ["msfconsole", "-r", resource_file, "-q"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
        with open(output_file, "w") as f:
            f.write(output)

        # Buscar indicaciones de éxito
        if "Meterpreter" in output or "Session" in output:
            success("Sesión Metasploit establecida")
        else:
            info("No se detectó sesión activa.")

        return output
    except Exception as e:
        error(f"Error en Metasploit: {e}")
        return ""


def run_sqlmap(target, options, session_dir):
    """Ejecuta SQLMap contra un objetivo."""
    if not tool_installed("sqlmap"):
        warn("sqlmap no disponible.")
        return None

    url = options.get("url", target)
    params = options.get("params", "")

    cmd = ["sqlmap", "-u", url, "--batch", "--risk=3", "--level=3"]
    if params:
        cmd.extend(["--data", params])

    cmd.extend(["--dbs", "--batch"])

    info(f"Ejecutando sqlmap contra: {url}")
    output_file = os.path.join(session_dir, "assets/sqlmap_output.txt")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        with open(output_file, "w") as f:
            f.write(output)

        if "is vulnerable" in output or "available databases" in output:
            success("SQLi confirmada o bases de datos enumeradas")
        else:
            info("No se detectó SQLi.")

        return output
    except Exception as e:
        error(f"Error en SQLMap: {e}")
        return ""


def run_manual_exploit(exploit_info, session_dir):
    """Ejecuta un exploit manual (Python, C compilado, etc.)."""
    exploit_path = exploit_info.get("path", "")
    lang = exploit_info.get("language", "py")
    target = exploit_info.get("target", "")
    target_port = exploit_info.get("port", "")

    if not exploit_path or not os.path.exists(exploit_path):
        error(f"Archivo de exploit no encontrado: {exploit_path}")
        return None

    if lang == "py":
        cmd = ["python3", exploit_path]
        if target:
            cmd.append(target)
        if target_port:
            cmd.append(target_port)
    elif lang in ("c", "cpp"):
        binary = exploit_path + ".bin"
        info(f"Compilando exploit C/C++...")
        compiler = "gcc" if lang == "c" else "g++"
        try:
            subprocess.run(
                [compiler, exploit_path, "-o", binary, "-lssl", "-lcrypto"],
                capture_output=True, text=True, timeout=60
            )
        except Exception as e:
            error(f"Error compilando: {e}")
            return None
        os.chmod(binary, 0o755)
        cmd = [binary]
        if target:
            cmd.append(target)
        if target_port:
            cmd.append(target_port)
    elif lang == "pl":
        cmd = ["perl", exploit_path]
        if target:
            cmd.append(target)
    else:
        cmd = [exploit_path]

    info(f"Ejecutando exploit: {' '.join(cmd)}")
    output_file = os.path.join(session_dir, "assets/exploit_output.txt")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        with open(output_file, "w") as f:
            f.write(output)

        if output.strip():
            print(f"\n  {color('--- Salida del Exploit ---', Colors.YELLOW)}")
            for line in output.strip().split('\n')[:50]:
                print(f"  {line}")
            print(f"  {color('--- Fin ---', Colors.YELLOW)}")

        return output
    except Exception as e:
        error(f"Error ejecutando exploit: {e}")
        return ""


# =============================================================================
#  POST-EXPLOTACIÓN
# =============================================================================

def post_exploitation(session_dir):
    """Ejecuta comandos básicos de post-explotación si hay acceso."""
    step(7, "Post-Explotación")
    info("Comandos de post-explotación (si hay shell activo):")
    info("  whoami, hostname, id, ip a / ifconfig, uname -a, cat /etc/passwd")
    print(f"\n  {color('Nota:', Colors.YELLOW)} Estos comandos se ejecutan dentro de la sesión")
    print(f"  comprometida (Meterpreter, SSH, etc.). Requiere acceso previo.")

    log_to_session(session_dir, "Post-exploitation", "Comandos listados")


# =============================================================================
#  REPORTE
# =============================================================================

def generate_report(target, vulnerability, session_dir, status, cve_id="",
                    tool="", module="", options="", access_level="",
                    host_info="", raw_output="", remediation=""):
    """Genera el reporte de explotación usando la plantilla."""
    section("Reporte y Documentación")

    template_path = os.path.join(SKILL_DIR, "templates/exploit_report_template.md")
    if os.path.exists(template_path):
        with open(template_path) as f:
            template = f.read()
    else:
        # Plantilla fallback
        template = """# Exploit Attempt Report: {{vulnerability}}

## Executive Summary
- **Target**: {{target}}
- **Vulnerability**: {{vulnerability}} ({{cve}})
- **Status**: {{status}} (Success/Failure)
- **Timestamp**: {{timestamp}}

## Methodology
- **Tool Used**: {{tool}}
- **Configuration**:
  - Module/Script: `{{module}}`
  - Options: `{{options}}`

## Evidence
```text
{{raw_output}}
```

## Access Gained
- **User/Privileges**: {{access_level}}
- **Host Info**: {{host_info}}

## Remediation
{{remediation_steps}}
"""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = template.replace("{{vulnerability}}", vulnerability or "N/A")
    report = report.replace("{{target}}", target)
    report = report.replace("{{cve}}", cve_id or "N/A")
    report = report.replace("{{status}}", status)
    report = report.replace("{{timestamp}}", timestamp)
    report = report.replace("{{tool}}", tool or "N/A")
    report = report.replace("{{module}}", module or "N/A")
    report = report.replace("{{options}}", options or "N/A")
    report = report.replace("{{raw_output}}", raw_output or "(sin evidencia)")
    report = report.replace("{{access_level}}", access_level or "N/A")
    report = report.replace("{{host_info}}", host_info or "N/A")
    report = report.replace("{{remediation_steps}}", remediation or "N/A")

    vuln_safe = sanitize(vulnerability or "unknown")
    report_path = os.path.join(session_dir, "assets", f"exploit_{vuln_safe}.md")

    with open(report_path, "w") as f:
        f.write(report)

    success(f"Reporte generado: {report_path}")
    log_to_session(session_dir, "Report generated", report_path)
    update_session_status(session_dir, "COMPLETED")

    return report_path


# =============================================================================
#  FLUJO DE TRABAJO PRINCIPAL (INTERACTIVO)
# =============================================================================

def interactive_mode(args):
    """Modo interactivo: guía al usuario paso a paso."""
    banner()

    # ── Entrada del objetivo ──
    if args.target:
        target = args.target
    else:
        target = input(f"\n  {color('Objetivo (IP o dominio):', Colors.BOLD)} ").strip()
        if not target:
            error("No se proporcionó un objetivo. Saliendo.")
            sys.exit(1)

    # ── Tipo de prueba ──
    if args.vulnerability:
        vuln_or_service = args.vulnerability
    else:
        vuln_or_service = input(f"  {color('Vulnerabilidad o servicio a probar:', Colors.BOLD)} ").strip()
        if not vuln_or_service:
            vuln_or_service = "general"

    info(f"Objetivo: {target} | Prueba: {vuln_or_service}")

    # ── Fase 1: Sesión ──
    step(1, "Gestión de Sesión")
    session_dir = init_session(target)
    info(f"Sesión iniciada en: {session_dir}")
    success("Estructura de sesión creada")

    # ── Verificación de herramientas ──
    available_tools = check_and_install_tools()

    # ── Detección automática de servicios ──
    services = detect_services(target)

    # Mapear servicio si el usuario proporcionó uno
    mapped_service = vuln_or_service.lower()
    if mapped_service in SERVICE_DETECTION:
        svc_cfg = SERVICE_DETECTION[mapped_service]
        print(f"  {color('Servicio mapeado:', Colors.CYAN)} {mapped_service} → scripts={svc_cfg['scripts']}")
    elif services:
        for s in services:
            if "mapped" in s:
                mapped_service = s["mapped"]
                break
    else:
        mapped_service = "general"

    # ── Autorización ──
    auth_mode = request_authorization(target)
    if auth_mode == "cancel":
        warn("Operación cancelada por el usuario.")
        update_session_status(session_dir, "CANCELLED")
        sys.exit(0)

    log_to_session(session_dir, "Authorization", auth_mode)

    # ── Fase 2: Reconocimiento Web ──
    httpx_file = None
    if vuln_or_service in ("web-recon", "http", "https") or any(
        s.get("mapped") in ("http", "https") for s in services
    ):
        httpx_file = web_recon(target, session_dir)
    else:
        info("Reconocimiento web saltado (objetivo no web o no solicitado).")

    # ── Fase 3: Verificación (Nmap) ──
    nmap_output = ""
    if auth_mode in ("verify", "full"):
        nmap_output = verify_vulnerability(target, auth_mode, session_dir, mapped_service)

    # ── Fase 4: CVE Lookup ──
    cve_results = []
    cve_query = f"{mapped_service}"
    if services:
        for s in services:
            if s.get("version"):
                cve_query = f"{s['service']} {s['version']}"
                break

    print(f"\n  {color('━━━ CVE Lookup ━━━', Colors.CYAN)}")
    print(f"  Query automática: {cve_query}")
    cve_choice = input(f"  ¿Ejecutar búsqueda CVE? (s/n) [s]: ").strip().lower()
    if cve_choice != "n":
        sev_filter = input(f"  Severidad mínima? (LOW/MEDIUM/HIGH/CRITICAL) [ninguna]: ").strip().upper()
        sev_filter = sev_filter if sev_filter in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else None
        cve_results = cve_lookup_query(cve_query, limit=30, min_severity=sev_filter)

        if cve_results:
            log_to_session(session_dir, "CVE Lookup", f"{len(cve_results)} CVEs")

    # ── Fase 5: Exploits / Fuerza Bruta ──
    exploit_output = ""
    if auth_mode == "full":
        print(f"\n  {color('━━━ Exploits y Fuerza Bruta ━━━', Colors.CYAN)}")

        # Wordlists personalizadas
        if vuln_or_service in ("web-recon", "http", "https"):
            wl_choice = input(f"  ¿Generar wordlist personalizada con cewl? (s/n) [n]: ").strip().lower()
            if wl_choice == "s":
                wl_url = input(f"  URL para cewl [{target}]: ").strip() or target
                wl_out = os.path.join(session_dir, "assets/custom_wordlist.txt")
                generate_wordlist(wl_url, wl_out)

        # Fuerza bruta
        if mapped_service in ("ssh", "ftp", "mysql", "postgres", "mssql"):
            bf_choice = input(f"  ¿Ejecutar fuerza bruta contra {mapped_service}? (s/n) [n]: ").strip().lower()
            if bf_choice == "s":
                exploit_output = brute_force(target, mapped_service, session_dir)

        # Búsqueda de exploits
        sp_choice = input(f"  ¿Buscar exploits con searchsploit? (s/n) [n]: ").strip().lower()
        if sp_choice == "s":
            ver = ""
            if services:
                for s in services:
                    if s.get("version"):
                        ver = s["version"]
                        break
            exploits = search_exploits(mapped_service, ver)

            if exploits:
                ex_choice = input(f"  ¿Ejecutar algún exploit? (s/n) [n]: ").strip().lower()
                if ex_choice == "s":
                    ex_idx = input(f"  Número del exploit a ejecutar: ").strip()
                    try:
                        ex_idx = int(ex_idx) - 1
                        if 0 <= ex_idx < len(exploits):
                            exploit_info = {
                                "type": "manual",
                                "path": exploits[ex_idx]["path"],
                                "language": "py",
                                "target": target,
                            }
                            exploit_output = execute_exploit(
                                target, exploit_info, auth_mode, session_dir
                            ) or ""
                    except ValueError:
                        error("Índice inválido.")

        # SQLi
        if vuln_or_service.startswith("sqli") or "sqli" in vuln_or_service.lower():
            sqlmap_choice = input(f"  ¿Ejecutar SQLMap? (s/n) [s]: ").strip().lower()
            if sqlmap_choice != "n":
                url = target
                if len(vuln_or_service.split()) > 1:
                    url = vuln_or_service.split()[-1]
                exploit_info = {"type": "sqlmap", "options": {"url": url}}
                exploit_output = execute_exploit(target, exploit_info, auth_mode, session_dir) or ""

    # ── Fase 6: Post-Explotación ──
    if auth_mode == "full" and exploit_output:
        post_exploitation(session_dir)

    # ── Fase 7: Reporte ──
    report_path = generate_report(
        target=target,
        vulnerability=vuln_or_service,
        session_dir=session_dir,
        status="SUCCESS" if exploit_output else ("VERIFY" if auth_mode == "verify" else "INFO"),
        cve_id=", ".join(r["cve_id"] for r in cve_results[:3]) if cve_results else "",
        tool=", ".join(available_tools[:5]),
        module=vuln_or_service,
        options=nmap_output[:200] if nmap_output else "",
        raw_output=exploit_output[:2000] if exploit_output else "",
        access_level="N/A",
        host_info="N/A",
        remediation="Consultar CVE y aplicar parches correspondientes."
    )

    # ── Resumen Final ──
    section("RESUMEN DE LA SESIÓN")
    print(f"  {color('Target:', Colors.BOLD)} {target}")
    print(f"  {color('Prueba:', Colors.BOLD)}  {vuln_or_service}")
    print(f"  {color('Modo:', Colors.BOLD)}   {auth_mode}")
    print(f"  {color('Servicios:', Colors.BOLD)} {len(services)} detectados")
    print(f"  {color('CVEs:', Colors.BOLD)}    {len(cve_results)} encontrados")
    print(f"  {color('Sesión:', Colors.BOLD)}  {session_dir}")
    print(f"  {color('Reporte:', Colors.BOLD)} {report_path}")
    print()


def cve_only_mode(query, min_severity, output_format, out_file):
    """Modo exclusivo CVE Lookup."""
    banner()
    section("CVE Lookup — Modo Exclusivo")
    results = cve_lookup_query(query, limit=50, min_severity=min_severity,
                               output_format=output_format, out_file=out_file)
    return results


# =============================================================================
#  CLI PARSER
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="XPL Toolkit — Framework interactivo de explotación de vulnerabilidades",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  Interactivo:
    python3 xpl_toolkit.py 192.168.1.10 ms17-010
    python3 xpl_toolkit.py example.com web-recon

  Solo CVE Lookup:
    python3 xpl_toolkit.py --cve-only "apache 2.4.49"
    python3 xpl_toolkit.py --cve-only "openssh 8.2" --min-severity HIGH
    python3 xpl_toolkit.py --cve-only "log4j" --output json --out resultados.json

  Solo herramientas:
    python3 xpl_toolkit.py --check-tools
        """
    )
    parser.add_argument("target", nargs="?", help="Objetivo (IP o dominio)")
    parser.add_argument("vulnerability", nargs="?", help="Vulnerabilidad o servicio")
    parser.add_argument("--cve-only", help="Solo búsqueda CVE, sin interacción completa")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Filtrar CVEs por severidad mínima")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table",
                        help="Formato de salida CVE")
    parser.add_argument("--out", help="Archivo de salida para CVE (json/csv)")
    parser.add_argument("--check-tools", action="store_true",
                        help="Solo verificar e instalar herramientas")

    args = parser.parse_args()

    if args.cve_only:
        cve_only_mode(args.cve_only, args.min_severity, args.output, args.out)
    elif args.check_tools:
        banner()
        check_and_install_tools()
    elif args.target:
        interactive_mode(args)
    else:
        # Modo completamente interactivo (sin argumentos)
        args.target = None
        args.vulnerability = None
        interactive_mode(args)


if __name__ == "__main__":
    main()
