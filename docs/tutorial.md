# Tutorial de XPL Toolkit

Este tutorial utiliza modos locales y direcciones reservadas. No realiza una evaluación activa.

## 1. Consultar la interfaz

```bash
python3 xpl_toolkit.py --help
```

El script principal muestra los modos interactivo, batch, CVE-only, verificación de herramientas, descarga de SecLists y estadísticas de caché.

## 2. Revisar la caché local

```bash
python3 xpl_toolkit.py --cache-stats
```

Esta operación crea o consulta la caché local del proyecto y no necesita un objetivo de red.

## 3. Consultar herramientas sin instalar

```bash
python3 xpl_toolkit.py --check-tools < /dev/null
```

Con entrada cerrada, el script informa las herramientas faltantes y no solicita ni ejecuta instalaciones. La opción interactiva puede usar `apt-get` o `go install` después de confirmación.

## 4. Ejecutar una consulta CVE

```bash
python3 xpl_toolkit.py --cve-only "apache httpd 2.4" --min-severity HIGH
```

Esta operación consulta NVD si hay conectividad. Configura `NVD_API_KEY` sólo mediante un mecanismo de secretos aprobado. Una coincidencia CVE es una pista de priorización, no una confirmación de vulnerabilidad.

## 5. Ejecutar el modo batch de verificación

Usa únicamente un activo autorizado:

```bash
python3 xpl_toolkit.py --batch AUTHORIZED_TARGET SERVICE --batch-auth verify
```

El modo `verify` debe revisar el alcance y la salida antes de considerar cualquier acción adicional. Sustituye `AUTHORIZED_TARGET` sólo por un objetivo cubierto por autorización escrita.

## 6. Manejar resultados

Las sesiones pueden contener hosts, puertos, tecnologías, CVEs, credenciales, reportes y salida de herramientas. Conserva la sesión fuera de Git, restringe sus permisos y aplica el procedimiento de cleanup del engagement. Consulta [`SECURITY.md`](../SECURITY.md) antes de compartir información.
