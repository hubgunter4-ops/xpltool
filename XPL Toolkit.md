# XPL Toolkit

> **Advanced Vulnerability Exploitation Framework** — Basado en la skill `xpl` de Manus

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

Framework interactivo y automatizado para pruebas de penetración autorizadas, reconocimiento web, verificación de vulnerabilidades, búsqueda de CVEs, y documentación de hallazgos. Incluye modo batch para pipelines CI/CD.

---

## Estructura del Repositorio

```
xpl-toolkit/
├── README.md                          ← Este archivo
├── SKILL.md                           ← Definición original de la skill xpl
├── LICENSE                            ← Licencia MIT
├── scripts/
│   ├── xpl_toolkit.py                 ← Toolkit v1 (interactivo básico)
│   ├── xpl_toolkit_v2.py             ← Toolkit v2 (avanzado, todas las mejoras)
│   ├── cve_lookup.py                  ← Script independiente CVE Lookup (NVD API)
│   ├── manage_session.py              ← Gestión de sesiones de pentesting
│   └── generate_wordlist.py           ← Generación de wordlists con cewl
├── references/
│   ├── compilation_workflow.md        ← Guía de compilación de exploits C/C++
│   ├── exploit_search_guide.md        ← Guía de búsqueda en ExploitDB
│   ├── httpx_guide.md                 ← Guía de reconocimiento web con httpx
│   ├── nmap_scripts.md                ← Referencia de scripts Nmap
│   └── wordlists/
│       ├── ssh_users.txt              ← 18 usuarios SSH comunes
│       ├── ssh_pass.txt               ← 22 contraseñas SSH comunes
│       ├── db_default.txt             ← 1336 contraseñas por defecto (DB/servicios)
│       └── web_common.txt             ← 4752 rutas/directorios web comunes
├── templates/
│   └── exploit_report_template.md     ← Plantilla de reporte de explotación
├── docs/
│   └── changelog.md                   ← Historial de cambios
└── wordlists/                         ← Wordlists descargadas de SecLists
```

---

## Características

| Versión | Características |
| :--- | :--- |
| **v1** (`xpl_toolkit.py`) | Interactivo básico: sesión, reconocimiento, Nmap, CVE lookup, exploits, fuerza bruta, reportes Markdown |
| **v2** (`xpl_toolkit_v2.py`) | Paralelización, UI/UX mejorada, detección WAF/SSL/TLS, caché SQLite de CVEs, modo batch, reportes HTML con gráficos, exploits LFI/RFI/XXE/SSRF/Deserialización, seguridad avanzada, wordlist management, logging rotativo |

---

## Uso Rápido

### Toolkit v2 (recomendado)

```bash
# Interactivo completo
python3 scripts/xpl_toolkit_v2.py 192.168.1.10 smb

# Solo CVE Lookup (con caché y API Key NVD)
python3 scripts/xpl_toolkit_v2.py --cve-only "apache httpd 2.4" --min-severity HIGH

# Exportar CVEs a JSON
python3 scripts/xpl_toolkit_v2.py --cve-only "log4j" --output json --out cves.json

# Modo batch (sin interacción, para cron/pipelines)
python3 scripts/xpl_toolkit_v2.py --batch 192.168.1.10 smb --batch-auth verify

# Verificar herramientas
python3 scripts/xpl_toolkit_v2.py --check-tools

# Descargar wordlists de SecLists
python3 scripts/xpl_toolkit_v2.py --download-seclists

# Estadísticas de caché
python3 scripts/xpl_toolkit_v2.py --cache-stats
```

### Toolkit v1 (básico)

```bash
python3 scripts/xpl_toolkit.py 192.168.1.10 ms17-010
python3 scripts/xpl_toolkit.py example.com web-recon
python3 scripts/xpl_toolkit.py --cve-only "apache 2.4.49"
python3 scripts/xpl_toolkit.py --check-tools
```

### CVE Lookup independiente

```bash
python3 scripts/cve_lookup.py "openssh 8.2"
python3 scripts/cve_lookup.py "wordpress 6.1" --min-severity HIGH
python3 scripts/cve_lookup.py "log4j" --output json --out resultados.json
```

---

## Herramientas Requeridas

| Herramienta | Propósito | Instalación |
| :--- | :--- | :--- |
| `nmap` | Escaneo de puertos y scripts de vulnerabilidad | `apt install nmap` |
| `httpx` | Probing HTTP/HTTPS y detección de tecnología | `go install github.com/projectdiscovery/httpx/...` |
| `hydra` | Fuerza bruta contra servicios | `apt install hydra` |
| `sqlmap` | Detección y explotación de SQL Injection | `apt install sqlmap` |
| `searchsploit` | Búsqueda en ExploitDB | `apt install exploitdb` |
| `metasploit-framework` | Framework de explotación | `apt install metasploit-framework` |
| `subfinder` | Enumeración de subdominios | `go install github.com/projectdiscovery/subfinder/...` |
| `gobuster` | Descubrimiento de directorios web | `apt install gobuster` |
| `cewl` | Generación de wordlists personalizadas | `apt install cewl` |
| `gcc` | Compilación de exploits C/C++ | `apt install gcc g++` |

El toolkit detecta automáticamente qué herramientas faltan y ofrece instalarlas.

---

## Flujo de Trabajo

```
1. Sesión → 2. Herramientas → 3. Servicios → 4. Detección Avanzada
   → 5. Autorización → 6. Reconocimiento → 7. Verificación (Nmap)
   → 8. CVE Lookup → 9. Exploits/Brute Force → 10. Post-Explotación
   → 11. Reporte
```

---

## Control de Autorización

Antes de cualquier acción intrusiva, el toolkit solicita confirmación explícita:

| Opción | Acción |
| :--- | :--- |
| `1` Authorized pentest | Explotación completa autorizada |
| `2` CTF / Lab environment | Entorno controlado de práctica |
| `3` Verify only | Solo verificación pasiva (seguro) |
| `4` Cancel | Detener y sugerir escaneo pasivo |

---

## Seguridad

- Validación de targets (IP/dominio) antes de cualquier acción
- Sanitización de paths anti path-traversal
- Log de auditoría JSON (`audit.log`) con timestamp, acción, target y severidad
- Rate-limiting automático en consultas NVD
- No se ejecutan ataques DoS sin confirmación explícita

---

## Mejoras v2 vs v1

| Mejora | Descripción |
| :--- | :--- |
| Paralelización | Banner grabbing y probing con ThreadPoolExecutor (8 workers) |
| UI/UX | Menús interactivos, barras de progreso, spinner, colores |
| Detección avanzada | WAF (9 proveedores), SSL/TLS analysis, banner grabbing (16 puertos) |
| Caché CVEs | SQLite local con TTL 24h, hashing SHA-256 |
| Modo batch | Ejecución no interactiva para cron/pipelines |
| Reportes HTML | Gráficos Plotly, estadísticas visuales, badges |
| Exploits adicionales | LFI, RFI, XXE, SSRF, Insecure Deserialization |
| Seguridad | Class Security, auditoría, sanitización |
| Wordlist management | Descarga SecLists, merge, dedup |
| Logging | RotatingFileHandler, SIGINT handler |

---

## Licencia

MIT License. Ver `LICENSE` para detalles.

> **Aviso**: Este toolkit es para uso en pruebas de penetración **autorizadas** únicamente. El uso no autorizado contra sistemas de terceros es ilegal.
