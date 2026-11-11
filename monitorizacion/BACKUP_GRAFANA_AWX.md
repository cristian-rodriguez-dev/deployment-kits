# AWX — Job 13: backup integral de Grafana

## Estado y alcance

- **Estado:** preparado; validado únicamente mediante pruebas locales. Pendiente de ejecución real en AWX.
- **Playbook:** `monitorizacion/playbooks/backup_grafana.yml`.
- **Inventario:** `grafana-servers`.
- **Credenciales:** Machine SSH + `become`; no utiliza la credencial de administrador de Grafana.
- **Variables:** `var_grafana_install_dir`, `var_grafana_project_name`, `var_grafana_port`. Opcionales: `var_grafana_backup_root` y `var_grafana_backup_reserve_bytes`.
- **Dependencias:** Python 3 con `sqlite3`, Docker Compose, Grafana activo y SQLite local en `data/grafana.db`.

## Protección y almacenamiento

- Lee únicamente la configuración de Grafana, sus bind mounts y SQLite; no modifica dashboards ni reinicia servicios.
- Genera `grafana-full-*.tar.gz` y `*.tar.gz.sha256` en `var_grafana_backup_root` (por defecto `<var_grafana_install_dir>/backups/full`).
- Directorio `0700`, archivos `0600`, propietario `root`; **incluye secretos y datos internos en claro**, por lo que no debe subirse a Git ni enviarse a sitios externos sin cifrar.
- Valida SHA256 del archivo y de cada entrada del tar, así como la integridad de la copia SQLite.
- Se aborta con poco espacio libre, montajes adicionales no cubiertos o archivos simbólicos.
- No realiza limpieza automática ni backups de otras aplicaciones.

## Operación

1. Sincronizar el repositorio del laboratorio en AWX.
2. Crear Job Template `13 - Backup integral Grafana`, mismo grupo SSH que Job 10, con escalada sudo.
3. Ejecutar y confirmar `failed=0`, `unreachable=0`, que el snapshot se ha verificado y que Grafana sigue respondiendo `database=ok`.
4. Guardar la ruta y el SHA256 reportados en AWX, sin publicar el archivo de backup.
5. Definir traslado **cifrado** a otro soporte y política de retención; aún no están automatizados.
6. Ensayar recuperación **solo en una VM aislada** con la misma versión y sin tocar el Grafana principal.

## Política de recuperación

La recuperación consiste en verificar el archivo, restaurar archivos y permisos de Grafana en una VM aislada y poner en marcha Docker Compose **en esa VM**. Comprobar salud de la base, los 15 dashboards, 351 paneles, usuarios, alertas y cinco datasources. Los servicios externos no forman parte de esta copia. No autorizar restauración en producción ni escrituras del Job 11 hasta documentar una prueba satisfactoria.

Consultar `README.md` del paquete v5 para instrucciones completas y fundamentos de SQLite.
