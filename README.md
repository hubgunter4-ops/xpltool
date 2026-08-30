# XPL Toolkit

Toolkit de **reconocimiento y verificación de seguridad para activos autorizados**, escrito en Python y Bash. El repositorio incluye un flujo interactivo, un modo batch orientado a automatizaciones y consultas de CVE mediante la API pública del NVD.

> **Uso responsable:** utilízalo únicamente sobre sistemas propios, laboratorios o activos con autorización explícita. El modo `verify` es la opción predeterminada para el modo batch; las pruebas activas y cualquier intento de explotación requieren una autorización independiente y documentada.

## Estructura

| Archivo | Propósito |
| --- | --- |
| `xpl_toolkit_v2.py` | Versión recomendada, con caché CVE, reportes HTML/Markdown, validación, auditoría y modo batch. |
| `xpl_toolkit.py` | Versión v1 compatible con el flujo interactivo básico. |
| `exploitdb_30.sh` | Consultas agrupadas a ExploitDB, ejecutables sobre un objetivo y directorio de salida indicados. |
| `XPL Toolkit.md` | Descripción ampliada del flujo y de las capacidades del proyecto. |
| `tests/test_toolkits.py` | Pruebas unitarias sin red ni herramientas externas. |

## Requisitos

Se requiere Python 3.11 o posterior. Las herramientas externas son opcionales y el toolkit informa cuando no están instaladas: `nmap`, `httpx`, `subfinder`, `gobuster`, `searchsploit`, `hydra`, `sqlmap`, `cewl` y, según el caso, `msfconsole`.

La clave del NVD, si se dispone de ella, debe configurarse mediante una variable de entorno y nunca debe escribirse en el código:

```bash
export NVD_API_KEY="tu-clave-nvd"
```

## Uso

Para iniciar el flujo interactivo recomendado:

```bash
python3 xpl_toolkit_v2.py 192.168.1.10 smb
python3 xpl_toolkit_v2.py example.com web-recon
```

Para una ejecución no interactiva y segura por defecto:

```bash
python3 xpl_toolkit_v2.py --batch example.com web-recon --batch-auth verify
```

Otros modos disponibles:

```bash
python3 xpl_toolkit_v2.py --cve-only "apache httpd 2.4" --min-severity HIGH
python3 xpl_toolkit_v2.py --cve-only "log4j" --output json --out cves.json
python3 xpl_toolkit_v2.py --check-tools
python3 xpl_toolkit_v2.py --download-seclists
python3 xpl_toolkit_v2.py --cache-stats
```

El módulo Bash se ejecuta con dos argumentos obligatorios:

```bash
bash exploitdb_30.sh <target> <output_dir>
```

## Mejoras incorporadas

| Mejora | Resultado |
| --- | --- |
| Gestión de secretos | Se eliminó la clave NVD embebida de v1 y v2; ahora se lee desde `NVD_API_KEY`. |
| Validación de entradas | Se validan IPs y nombres DNS antes de crear sesiones o ejecutar comandos. |
| Correcciones de ejecución | Se arregló el alias `metasploit`/`msfconsole`, el registro de wordlists sin sesión y la inicialización de resultados HTTP. |
| Caché CVE | Las respuestas vacías cacheadas se reconocen correctamente y los reintentos ante HTTP 403 están limitados. |
| Reportes | Los valores procedentes del objetivo, NVD y servicios se escapan antes de insertarse en HTML. |
| Logging | Se evita duplicar handlers cuando se inicializa el logger más de una vez. |
| Módulo Bash | Se renombró desde `Xpldb.md`, se añadió una interfaz CLI y se corrigieron escapes de `$service` y `$2`. |
| Mantenibilidad | Se añadieron `.gitignore`, pruebas unitarias y documentación de ejecución reproducible. |

## Pruebas

Las pruebas no hacen conexiones de red ni lanzan `nmap`, `hydra`, `sqlmap`, `searchsploit` u otras herramientas externas:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile xpl_toolkit.py xpl_toolkit_v2.py
bash -n exploitdb_30.sh
```

Los artefactos locales como la caché SQLite, logs, sesiones y wordlists descargadas están excluidos mediante `.gitignore`.
