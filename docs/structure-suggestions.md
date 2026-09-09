# Sugerencias estructurales

## Estado actual

`xpl_toolkit.py` es ahora el punto de entrada principal consolidado. `xpl_toolkit_v2.py` permanece como compatibilidad temporal para invocaciones existentes. No se añadió un segundo script base.

## Sugerencias futuras

La siguiente reorganización podría mejorar el mantenimiento sin cambiar el objetivo funcional: separar presentación CLI, validación, caché NVD, adaptadores de herramientas, generación de reportes y flujo de sesión en módulos internos. Esa separación debe conservar las interfaces públicas actuales y contar con pruebas de regresión antes de eliminar el archivo de compatibilidad.

`exploitdb_30.sh` concentra muchos ejemplos independientes. Una futura división por módulos podría facilitar pruebas y mantenimiento, pero no se aplica en esta actualización porque el alcance aprobado conserva ese script sin cambios.

El repositorio no declara una licencia. El propietario debería añadir una licencia explícita antes de redistribuirlo o describirlo como open source.
