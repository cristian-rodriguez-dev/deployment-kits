# Bloque 01 — Grafana AWX v5: backup integral de Grafana

**Alcance:** laboratorio antiguo `deployment-kits`, AWX/K3s, Grafana 13.2.3 sobre Docker Compose con SQLite y bind mounts. Este paquete añade archivos; **no modifica** los Jobs 10, 11 y 12 ni el instalador de Grafana. No ejecuta despliegues desde aquí.

## 1. Qué respaldamos

Este Job 13 incluye:

| Contenido | Fuente en servidor | Método |
|---|---|---|
| Estado de Grafana (dashboards, usuarios, alertas, datasources, etc.) | `{{ var_grafana_install_dir }}/data/grafana.db` | API de copia online de SQLite, verificada con `PRAGMA quick_check` |
| Plugins y demás datos locales | `.../data/` | Copia de archivos con SHA256 (sin copiar `grafana.db-wal`, `-shm` ni journals) |
| Provisioning | `.../provisioning/` | Árbol completo |
| Secreto de administrador | `.../secrets/` | Árbol completo; archivo sensible |
| Definición del servicio | `.../docker-compose.yml` | Archivo completo |
| Huella de inicialización de AWX | `.../.awx-initialized`, si existe | Archivo completo |

El playbook comprueba que los **tres bind mounts** esperados (`/var/lib/grafana`, `/etc/grafana/provisioning`, `/run/secrets/grafana_admin_password`) corresponden a esas rutas. Si detecta otros montajes, para con un error: hay que revisar su alcance, no ignorarlos.

**Límites:** no respalda Prometheus, Loki, Wazuh, redes Docker, hosts remotos ni volúmenes de otros contenedores. La copia online de SQLite es consistente para la base de datos, pero no es una transacción atómica conjunta con archivos de plugins/provisioning que se modifiquen al mismo tiempo. No sustituye a un ensayo de restauración.

Grafana recomienda una copia de sus archivos y base de datos, y para una copia *directa* de SQLite indica detener el servicio. Aquí **no copiamos el archivo SQLite en caliente**: usamos la API de backup online de SQLite, sin apagar Grafana. Aun así, el nivel de garantía que buscamos solo se alcanzará tras probar una restauración aislada.

Referencias: [Grafana — Back up Grafana](https://grafana.com/docs/grafana/latest/administration/back-up-grafana/) · [SQLite — Online Backup API](https://www.sqlite.org/backup.html)

## 2. Qué archivos añade

```
monitorizacion/
├── playbooks/
│   └── backup_grafana.yml
├── files/
│   ├── grafana_full_backup.py
│   └── verificar_backup_grafana.py
└── examples/
    └── variables_backup_grafana.yml

tools/
└── verificar_backup_grafana.py

tests/
└── test_backup_grafana.py
```

## 3. Preparación segura

1. Descomprimir **solo sobre la raíz** de `deployment-kits`, conservando carpetas. No sobrescribe los Jobs previos.
2. Revisar `git diff`, **no incluir** archivos de backup ni credenciales en Git.
3. Commit, push y sincronización del proyecto antiguo en AWX.
4. Crear Job Template: **`13 - Backup integral Grafana`**.
5. Playbook: `monitorizacion/playbooks/backup_grafana.yml`.
6. Inventario/grupo: el mismo utilizado por `10 - Auditar Grafana`, `grafana-servers`.
7. Credencial: Machine/SSH con `become` (sudo). **No precisa credencial de Grafana**, ya que no consulta rutas autenticadas de la API ni envía contraseñas.
8. Variables existentes del grupo: `var_grafana_install_dir`, `var_grafana_project_name`, `var_grafana_port`.
9. Opcionales (por defecto no necesarias):

```yaml
# Defecto: <var_grafana_install_dir>/backups/full
# var_grafana_backup_root: /ruta/externa/privada/grafana-full

# Conserva como mínimo 512 MiB de reserva al estimar espacio de copia:
# var_grafana_backup_reserve_bytes: 536870912
```

**Antes de ejecutar:** comprobar espacio libre de disco; si no hay suficiente, se aborta sin eliminar nada. La copia queda por defecto en el mismo servidor: **no es un backup externo**. Idealmente establecer un destino en otro disco, montado y protegido.

## 4. Comportamiento del Job 13

- GET de `/api/health` y `database=ok` antes y después del backup.
- Comprobación del servicio Grafana en el proyecto Docker Compose y de los bind mounts montados.
- Generación de un `grafana-full-YYYYMMDDTHHMMSSZ-xxxxxxxx.tar.gz` con manifiesto SHA256 de **cada archivo** y datos de UID/GID/permisos.
- Generación de `.tar.gz.sha256` con checksum externo.
- Archivo protegido con permisos `0600`, directorio de backups `0700`, propietario root.
- Verificación del SHA256 y de **todos los archivos**, además de `PRAGMA quick_check` del snapshot SQLite.
- No elimina backups antiguos, no rota, no reinicia Grafana, no escribe en Grafana ni ejecuta `docker compose up/down/restart`.
- **Es normal que el Job muestre `changed > 0`**: ha creado backups locales, no ha modificado el servicio.
- Si hay archivos cambiando durante la copia, symlinks o montajes inesperados, aborta: no debe maquillarse como correcto.

**Resultado esperado:**

```
TASK [Mostrar resumen sin imprimir datos sensibles]
ok: [ansible_server] => {
    "msg": [
        "Backup integral generado: /.../grafana-full-...tar.gz",
        "SHA256: ...",
        "Archivos: ...; tamano comprimido: ... bytes",
        "SQLite: copia online con comprobacion de integridad",
        "Grafana no se ha reiniciado ni modificado. Este respaldo contiene secretos: no subir a Git."
    ]
}
PLAY RECAP: failed=0; unreachable=0
```

## 5. Verificación adicional sin descargar secretos

El propio Job 13 verifica en el servidor todo el contenido, incluido SQLite. Si necesitas repetir la comprobación, ejecuta en Ubuntu con la ruta del ZIP (realmente es `.tar.gz`) que indique AWX:

```bash
sudo python3 /RUTA/DE/BACKUP/.verificar_backup_grafana.py \
  --archive /RUTA/DE/BACKUP/grafana-full-YYYYMMDDTHHMMSSZ-xxxxxxxx.tar.gz \
  --sha256 SHA256_DEL_JOB_13
```

No compartas aquí el archivo `.tar.gz`: incluye la base de datos y credenciales.

Para comprobación local opcional en Windows (solo si estás autorizado a copiar ese respaldo, **cifrado y protegido**), ejecuta desde el repo:

```powershell
uv run --python 3.15 --no-project .\tools\verificar_backup_grafana.py `
  --archive "C:\ruta\grafana-full-....tar.gz" `
  --sha256 "EL_SHA256_QUE_MOSTRÓ_AWX"
```

## 6. Restauración controlada: ensayo en una VM aislada

**No restaurar sobre el Grafana actual.** El Job 13 es solo de backup; no incluye ninguna operación de restauración automática.

En una VM *nueva y aislada* con Docker y la misma versión de Grafana:

1. Instala Docker/Compose y prepara una ruta *igual que* `var_grafana_install_dir`, pero en esa VM, nunca en el servidor activo. Revisa conectividad y dependencias externas; la configuración puede hacer referencia a redes, URL y otros servicios del laboratorio original.
2. Copia el backup por un canal autorizado **cifrado**, restringe su acceso a root y valida checksum y manifiesto con el verificador antes de extraer.
3. Revisa el `docker-compose.yml` dentro del backup y evita exposición de puertos, conflicto de nombres y acceso accidental a producción.
4. Restaura **solo en esa VM** con `sudo tar -xzf ... -C /ruta/de/staging`, después mueve el contenido `grafana/` a la ruta aislada prevista preservando UID/GID/permisos. Hazlo sin un Grafana en ejecución en esa VM.
5. Asegura la red externa requerida por Compose, revisa mounts y levanta el servicio **en la VM aislada**. No cambies la imagen ni la DB en la prueba de primera restauración.
6. Comprueba `GET /api/health` (base de datos `ok`), entrada a Grafana, inventario de dashboards (**15**) y sus **351 paneles**, usuarios, reglas de alertas, plugins y 5 datasources. Los datasources pueden no estar saludables si no se restauran sus servicios externos.
7. Documenta fecha, tiempo de restauración, incidencias y resultado en un acta. Solo entonces se considerará *restauración verificada*.

El backup es **portable bajo condiciones**, no un clon automático de todos los servicios ni un reemplazo de copias externas. La gestión de claves de cifrado debe ser independiente del servidor.

## 7. Seguridad y documentación

- **No introducir el `.tar.gz` ni `.sha256` en Git** (el `.sha256` identifica un respaldo sensible, aunque no sea secreto).
- No trasladar una copia sin cifrar a un portátil personal o servicios cloud. Para transporte externo, cifrar primero con una clave pública gestionada por la organización (por ejemplo, `age`) y controlar quién puede descifrar.
- Mantener `.md` del laboratorio actualizado al añadir el Job 13 a AWX: listado de Job Templates, ubicación/reten­ción de backups, permisos, pasos de recuperación, dependencia de Docker y SQLite.
- No hacer limpiezas automáticas de respaldos sin política de retención aprobada. Vigilar consumo de disco; una copia con raíz en el mismo host no protege de pérdida del host.
- **No activar todavía escrituras del Job 11**. El siguiente trabajo, una vez que el 13 pase, es practicar restauración aislada y definir la política de copias externas.

## 8. Pruebas locales del paquete

Con `uv` en Windows o Python del sistema:

```powershell
uv run --python 3.15 --no-project -m unittest discover -s .\tests -v
```

Los tests no hablan con Docker ni Grafana reales: prueban archivado, SQLite online, integridad, permisos, rechazo de symlinks y validación de montajes.
