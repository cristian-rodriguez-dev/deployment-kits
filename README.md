# Bloque 01 — Grafana AWX v6: Job 14 (ensayo offline de restauración)

**Proyecto antiguo:** `deployment-kits` (Ansible/AWX). Añade un playbook nuevo y scripts de validación; NO modifica los Jobs 10–13 ni la instalación de Grafana.

**Estado:** código y pruebas locales preparados. **No ejecutado en AWX ni probado con el TAR real**, porque el respaldo contiene secretos y permanece en el servidor. No representa todavía una restauración funcional completa.

## Alcance y garantías

- **AUDITORÍA (predeterminado):** valida destino aislado, marca manual, ausencia de Grafana existente, presencia y SHA256 del archivo. No crea carpetas ni extrae datos.
- **ENSAYO OFFLINE (`var_grafana_restore_apply: true`):** revalida **todo** el archivo del Job 13 (SHA256 global, manifiesto, hashes por fichero y SQLite), reconstruye su estructura y permisos en una carpeta **privada de una VM dedicada**, ejecuta `PRAGMA integrity_check` y contrasta los 15 dashboards almacenados en SQLite. Opcionalmente informa del número de datasources y reglas de alertas en la base restaurada.
- No invoca `docker`, `docker compose`, `systemctl` para efectuar cambios; no publica puertos ni accede a los servicios de la instalación principal. Las únicas acciones Docker son lectura para comprobar que no esté ejecutándose Grafana en el destino.
- No sobrescribe ensayos existentes: repetir con el mismo TAR comprueba los ficheros y devuelve `YA_VALIDADO` y `changed=false` para la tarea de restauración.
- **No es todavía un ensayo E2E:** no se ha arrancado una segunda instancia, ni probado sus plugins/datasources/alertas. Eso requiere otro ensayo controlado y sin acceso a los servicios originales.

## Archivos (rutas relativas a la raíz de `deployment-kits`)

```text
monitorizacion/
├── playbooks/ensayar_restauracion_grafana.yml
├── files/ensayar_restauracion_grafana.py
├── files/verificar_backup_grafana.py  # copia IDENTICA de v5; no cambia su funcionamiento
├── examples/variables_restauracion_grafana.yml
└── RESTAURACION_GRAFANA_AWX.md
tests/test_restauracion_grafana.py
```

La copia del verificador de v5 está incluida solo para hacer autocontenido este ZIP; **es byte a byte idéntica al archivo usado por el Job 13**. No sustituir por una versión distinta.

## 1. Preparar una VM de restauración, NO el servidor Grafana

Se necesita una **VM Ubuntu separada** con SSH, Python 3 y acceso de AWX por una credencial Machine con `become`. Preferiblemente host-only o red de gestión restringida, sin acceso a producción. **No usar `ansible_server`, ni ninguna VM que ya tenga Grafana.** Si no existe esa VM, no ejecutes aún el Job 14.

En AWX, añadir la VM exclusivamente al grupo `grafana-restore-lab` (nombre con guiones, como las plantillas del proyecto antiguo). No añadir el servidor original a ese grupo. La VM de ensayo necesita espacio libre para descomprimir el TAR (además de una reserva mínima de 512 MiB); el script calcula el volumen necesario según el manifiesto.

En la **VM aislada**, después de verificar manualmente su identidad, crear el marcador de autorización:

```bash
printf 'GRAFANA_RESTORE_LAB_ONLY_v1\n' | sudo tee /etc/grafana-restore-lab.allow >/dev/null
sudo chown root:root /etc/grafana-restore-lab.allow
sudo chmod 0600 /etc/grafana-restore-lab.allow
```

El playbook **no crea el marcador**; si no existe, se detiene.

## 2. Trasladar el TAR de forma segura a la VM de ensayo

El respaldo generado el 11 de noviembre está en el **servidor original**:

```text
/home/servidor/instalacion/grafana/backups/full/grafana-full-20261111T083927Z-cfdddd9b.tar.gz
```

SHA256 registrado por el Job 13:

```text
56881e757a51df805a83f4c7d47efcc02e0ea879b111f5e11ec813bc92bc3b29
```

Transfiere el TAR directamente entre máquinas por un canal SSH aprobado, con acceso de lectura mediante `sudo` en el servidor y permisos privados en la VM nueva. **No lo subas a Git, a ChatGPT ni a almacenamiento externo sin cifrado.** El archivo contiene secretos y usuarios de Grafana.

Ejemplo ilustrativo **desde el servidor original**, suponiendo que SSH por clave ya funciona hacia la VM de ensayo; sustituye `RESTORE_USER` y `RESTORE_VM_IP` por los reales:

```bash
sudo -v
sudo cat /home/servidor/instalacion/grafana/backups/full/grafana-full-20261111T083927Z-cfdddd9b.tar.gz \
  | ssh -o BatchMode=yes RESTORE_USER@RESTORE_VM_IP \
    'umask 077; mkdir -p "$HOME/.grafana-restore-inbox"; cat > "$HOME/.grafana-restore-inbox/grafana-full-20261111T083927Z-cfdddd9b.tar.gz"'
```

Si SSH por clave no está configurado, utiliza vuestro procedimiento autorizado de copia entre VMs. No elimines el respaldo original. Confirma en la VM de ensayo:

```bash
ls -lh "$HOME/.grafana-restore-inbox/"
stat -c '%a %U %n' "$HOME/.grafana-restore-inbox/"*.tar.gz
```

El archivo debe tener modo `600`. Asegúrate de que la VM de ensayo es efectivamente distinta de la original.

## 3. Configurar AWX

- Proyecto: el mismo proyecto Git antiguo, tras commit/push/sync.
- Job Template: **`14 - Ensayar restauración Grafana (VM aislada)`**.
- Playbook: `monitorizacion/playbooks/ensayar_restauracion_grafana.yml`.
- Inventario: el que tenga el grupo **`grafana-restore-lab`**; el Job debe apuntar solo a esa VM.
- Credencial: SSH+sudo **de la VM aislada**, no hace falta credencial API de Grafana.
- Variables del Job/grupo (ejemplo con usuario ficticio `restore`; ajustar ruta e IP reales):

```yaml
var_grafana_restore_archive: /home/restore/.grafana-restore-inbox/grafana-full-20261111T083927Z-cfdddd9b.tar.gz
var_grafana_restore_sha256: 56881e757a51df805a83f4c7d47efcc02e0ea879b111f5e11ec813bc92bc3b29
var_grafana_restore_source_address: 192.168.56.20  # confirmar IP REAL del servidor original
var_grafana_restore_expected_dashboards: 15
var_grafana_restore_apply: false
```

`var_grafana_restore_source_address` es una barrera de seguridad y **debe ser la dirección actual real** del servidor Grafana. No uses una IP de ejemplo si ha cambiado.

### Ejecución A — solo lectura

Con `var_grafana_restore_apply: false`, ejecutar y confirmar:

```text
SHA256 del respaldo: OK
Modo: AUDITORIA; no se ha extraido ni restaurado ningun archivo
PLAY RECAP: changed=0 failed=0
```

### Ejecución B — reconstrucción OFFLINE, solo en VM aislada

Tras verificar la identidad del host y el resumen anterior, cambiar **solo allí**:

```yaml
var_grafana_restore_apply: true
```

Esperamos:

```text
Estado: RESTAURADO_OFFLINE
Dashboards en SQLite: 15
SQLite: integrity_check correcto (comprobado)
No se ha arrancado Grafana.
```

`changed>0` es normal por los archivos creados **en la VM aislada**. La carpeta queda en `/var/lib/grafana-restore-lab/ensayo-<SHA16>/`, restringida a root. No copiarla a servicios vivos ni ejecutar el Compose del backup, porque contiene rutas y conexiones del entorno original.

## 4. Qué falta después

Una restauración funcional E2E en **una segunda instancia aislada**: arrancar Grafana de la **misma imagen/version** con bind mounts sobre la copia, sin conexiones a la red original ni puertos públicos; validar `/api/health`, login, 15 dashboards, 351 paneles, 5 datasources y alertas. Esa fase todavía no está implementada ni probada. El backup externo cifrado también sigue pendiente.

Documentar cambios en los README y listado de Job Templates del laboratorio, política de almacenamiento y recuperación. Mantener **Job 11 bloqueado en modo auditoría**. No se ha modificado Docker Compose ni el Wazuh existente.

## 5. Tests

```bash
python3 -m unittest discover -s tests -p 'test_restauracion_grafana.py' -v
```

Los tests del ensayo se han ejecutado en Linux (requieren operaciones sobre propietarios y permisos, como el playbook de destino). No requieren Docker ni Grafana reales.
