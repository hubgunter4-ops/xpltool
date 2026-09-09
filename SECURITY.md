# Security Policy

## Alcance

Esta política cubre `xpl_toolkit.py`, el archivo de compatibilidad `xpl_toolkit_v2.py`, `exploitdb_30.sh`, sus pruebas y la documentación del repositorio. Los datos producidos contra objetivos externos son material sensible de cada evaluación y no deben publicarse en issues.

## Reporte responsable

Reporta problemas del código mediante un canal privado del propietario del repositorio. No incluyas API keys, contraseñas, objetivos reales, capturas de tráfico, reportes de sesión ni salidas de explotación. Usa un fixture local, `localhost` o un laboratorio aislado para reproducir.

Un reporte útil incluye versión o commit, archivo afectado, pasos de reproducción, impacto, comportamiento esperado, comportamiento observado y una propuesta de mitigación. Redacta todos los datos sensibles antes de enviarlo.

## Uso operacional

El toolkit puede ejecutar reconocimiento, consultas de vulnerabilidad, fuerza bruta, herramientas de explotación y acciones de post-explotación según el modo elegido. Utiliza únicamente activos autorizados y registra el alcance, ventana, herramientas permitidas, retención y procedimiento de cleanup.

El modo `verify` no concede autorización. La selección `full` requiere permiso independiente y explícito. La instalación de herramientas puede ejecutar `sudo apt-get` o `go install`; revisa cada comando antes de confirmarlo.

## Datos y secretos

Configura `NVD_API_KEY` mediante el entorno o un gestor de secretos aprobado. No guardes la clave en el repositorio ni la incluyas en argumentos que puedan quedar en el historial. Mantén sesiones, cachés, informes y wordlists fuera del árbol versionado.
