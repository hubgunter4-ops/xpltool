# Changelog

## [Unreleased]

- Preparación de documentación, tutorial, feed y materiales de promoción para el punto de entrada consolidado.

## [2.1.2] — 2026-09-09

- Corregido el registro de sesiones canceladas para conservar exactamente el estado `CANCELLED`.
- Verificada en vivo la ruta completa del menú guiado hasta la confirmación de autorización, sin tráfico de red.

## [2.1.1] — 2026-09-09

- Añadido un menú principal interactivo y conciso para ejecutar las operaciones existentes mediante opciones numeradas.
- Añadidas rutas seguras de cancelación, validación de opción y manejo de EOF.
- Corregidos los ejemplos internos para mostrar `xpl_toolkit.py` como punto de entrada principal.
- Añadidas pruebas smoke para selección válida, selección inválida, cancelación y EOF.

## [2.1.0] — 2026-09-09

- Añadido flujo batch con modos `verify`, `full` y `cancel`.
- Añadida consulta CVE con filtros de severidad, caché SQLite y exportación JSON/CSV.
- Añadidos reportes HTML y Markdown con escape de valores externos.
- Añadida validación de objetivos y puertos antes de ejecutar herramientas.
- Añadida verificación interactiva de herramientas externas.
- Añadidas pruebas unitarias para validación, caché, reportes y wordlists.
