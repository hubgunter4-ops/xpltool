# XPL Toolkit

> **Toolkit de reconocimiento y verificación de seguridad autorizada.** Incluye flujos interactivos y batch, consulta de CVE, caché local, auditoría y reportes HTML/Markdown.

## Archivos del repositorio

| Archivo | Descripción |
| --- | --- |
| `xpl_toolkit_v2.py` | Implementación recomendada, con validación de objetivos, caché NVD, detección de servicios, reportes y modo batch. |
| `xpl_toolkit.py` | Implementación v1 del flujo interactivo y consulta de CVE. |
| `exploitdb_30.sh` | Módulo Bash con treinta consultas agrupadas a ExploitDB. |
| `tests/test_toolkits.py` | Pruebas unitarias locales, sin red y sin herramientas externas. |
| `README.md` | Instalación, ejemplos de uso y resumen de mejoras. |

## Instalación

El requisito base es Python 3.11 o posterior. Las herramientas de reconocimiento son opcionales y se detectan en tiempo de ejecución: `nmap`, `httpx`, `subfinder`, `gobuster`, `searchsploit`, `hydra`, `sqlmap`, `cewl` y `msfconsole`, entre otras.

La clave del NVD se configura únicamente mediante el entorno:

```bash
export NVD_API_KEY="tu-clave-nvd"
```

No se deben almacenar credenciales en el código ni en el control de versiones.

## Uso recomendado

El flujo interactivo v2 se inicia así:

```bash
python3 xpl_toolkit_v2.py 192.168.1.10 smb
python3 xpl_toolkit_v2.py example.com web-recon
```

El modo batch no interactivo usa `verify` por defecto y valida el objetivo antes de iniciar acciones:

```bash
python3 xpl_toolkit_v2.py --batch example.com web-recon --batch-auth verify
```

Las consultas CVE pueden exportarse a JSON o CSV:

```bash
python3 xpl_toolkit_v2.py --cve-only "apache httpd 2.4" --min-severity HIGH
python3 xpl_toolkit_v2.py --cve-only "log4j" --output json --out cves.json
python3 xpl_toolkit_v2.py --cache-stats
```

El módulo de consultas ExploitDB requiere un objetivo y un directorio de salida:

```bash
bash exploitdb_30.sh <target> <output_dir>
```

## Flujo de autorización

Antes de acciones dirigidas al objetivo, el toolkit solicita un modo de autorización. `verify` permite únicamente verificaciones; `full` habilita el flujo de pruebas activas configurado por el usuario; `cancel` detiene la sesión. El modo batch no solicita entrada y debe invocarse con la autorización elegida de forma explícita.

> Este proyecto no debe utilizarse contra sistemas de terceros sin permiso documentado. Las salidas de reconocimiento y los reportes pueden contener información sensible y deben protegerse.

## Mejoras aplicadas en la versión revisada

| Área | Mejora |
| --- | --- |
| Secretos | Se retiró la clave NVD embebida y se sustituyó por `NVD_API_KEY`. |
| Validación | IPs, IPv6 y nombres DNS se validan antes de crear sesiones o lanzar herramientas. |
| Código | Se corrigieron el alias `metasploit`/`msfconsole`, el registro de wordlists sin sesión y la inicialización de resultados HTTP. |
| Caché | Las respuestas vacías se tratan como aciertos de caché y el parámetro de antigüedad se respeta. Los reintentos HTTP 403 son limitados. |
| Seguridad | La detección WAF es pasiva en la revisión; los datos externos se escapan en reportes HTML. |
| Logging | Los handlers no se duplican al inicializar logging más de una vez. |
| Bash | `Xpldb.md` se convirtió en `exploitdb_30.sh`, se corrigieron las continuaciones de línea y los escapes de `$service` y `$2`. |
| Calidad | Se añadieron README, `.gitignore` y pruebas unitarias reproducibles. |

## Verificación local

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile xpl_toolkit.py xpl_toolkit_v2.py
bash -n exploitdb_30.sh
```

Las validaciones anteriores no realizan conexiones de red, no ejecutan escaneos y no lanzan herramientas de explotación.
