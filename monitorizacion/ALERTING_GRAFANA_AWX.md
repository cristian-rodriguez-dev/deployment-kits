# Job 24 — Respaldo y comparación de alerting Grafana

## Objetivo

Conservar el alerting existente **sin tocar las reglas ni las notificaciones**. Un solo Job Template de AWX soporta dos operaciones:

- `capture`: recopila mediante `GET` las definiciones actuales y crea un snapshot privado verificable.
- `compare`: compara la configuración actual con una referencia protegida y comunica las categorías que han cambiado.

No instala, actualiza, borra ni reinicia Grafana; tampoco crea contact points ni altera el bot.

**Importante:** este job no constituye todavía gestión declarativa con escritura. Primero necesitamos observar la configuración real, revisar los secretos y determinar cómo versionarla. La copia completa de Grafana del Job 13 continúa siendo el respaldo para recuperación.

## Archivos nuevos

- `monitorizacion/playbooks/gestionar_alerting_grafana.yml`
- `monitorizacion/files/grafana_alerting_snapshot.py`
- `monitorizacion/examples/variables_alerting_grafana.yml`
- `monitorizacion/ALERTING_GRAFANA_AWX.md`
- `tests/test_grafana_alerting.py`

No modifica los Jobs 10–21 ni `instalar_grafana.yml`.

## Job Template en AWX

- **Nombre:** `24 - Respaldar y comparar alerting Grafana`
- **Playbook:** `monitorizacion/playbooks/gestionar_alerting_grafana.yml`
- **Inventario:** mismo que Jobs 10 y 13, con el grupo `grafana-servers`.
- **Credencial de máquina:** SSH con sudo, la ya utilizada en el laboratorio.
- **Credencial de Grafana:** la ya utilizada en Job 10, que inyecta `VAR_GRAFANA_ADMIN_PASSWORD` en el Execution Environment.
- **Variables AWX existentes:** `var_grafana_install_dir`, `var_grafana_port`, `var_grafana_admin_user`.
- **Variables para la primera ejecución:**

```yaml
var_grafana_alerting_mode: capture
```

### Primera ejecución

El Job leerá estas API clásicas de Grafana 13 (aún disponibles):

- `/api/v1/provisioning/alert-rules`
- `/api/v1/provisioning/contact-points`
- `/api/v1/provisioning/policies`
- `/api/v1/provisioning/mute-timings`
- `/api/v1/provisioning/templates`
- Las variantes `/export?format=json` para reglas, contact points, policies y mute timings.

Las primeras tres son obligatorias; las restantes pueden devolver 404/405 y entonces aparecen como `unsupported`. Otros errores abortan el Job; **no se guarda una captura incompleta como correcta**.

El resultado contiene recuentos, estados, ruta y SHA256. La captura se almacena en:

`{{ var_grafana_install_dir }}/backups/alerting/alerting-<fecha>-<id>.json`

Propietario `root`, directorio `0700`, archivos `0600`. Se crea un archivo nuevo, nunca se sobrescribe otro existente. No guardes su contenido en el repositorio.

Es normal observar tareas `changed` por crear directorios, copiar el script o guardar el snapshot. Ninguna de ellas modifica la API de Grafana.

### Comparación posterior

Recupera la ruta y el SHA256 devueltos por la primera captura, y cambia las variables:

```yaml
var_grafana_alerting_mode: compare
var_grafana_alerting_reference_file: "/ruta/real/backups/alerting/alerting-YYYYMMDDTHHMMSSZ-abcdef123456.json"
var_grafana_alerting_reference_sha256: "<sha256-real-publicado-en-el-job>"
var_grafana_alerting_fail_on_drift: false
```

`compare` no crea snapshot. Comprueba primero integridad, permisos y propiedad del archivo de referencia y luego compara los JSON recogidos con los antiguos, sin exponer sus cuerpos. Devuelve `SIN CAMBIOS` o `DERIVA DETECTADA` y las categorías afectadas. Para que AWX marque el Job como fallido si detecta diferencias, usa `var_grafana_alerting_fail_on_drift: true`.

**Matiz:** las diferencias pueden ser legítimas, y campos de metadatos generados por Grafana podrían ocasionar deriva técnica sin cambio funcional. No se revierte nada de forma automática.

## Seguridad y limitaciones

- Todos los accesos al servidor Grafana utilizan `GET` sobre `127.0.0.1` y no siguen redirecciones externas ni usan proxies del entorno.
- Las credenciales se inyectan como entorno de una tarea `no_log`, **nunca** como argumento de un proceso.
- El snapshot bruto puede incluir datos de routing, destinatarios, consultas, URLs privadas y valores sensibles. **No subirlo a Git, no compartirlo por chat, no adjuntarlo a tickets.**
- Algunos secretos de contact points llegan ocultos o no son exportables mediante la API: **no considerar el snapshot una restauración autónoma completa**.
- El método usa las rutas de provisioning clásicas, disponibles en Grafana 13, aunque algunas están deprecadas. No incluye recursos de una configuración staged de Alertmanager ni reglas gestionadas únicamente por otro datasource.
- No se modifica provenance, política por defecto ni selección de contact points: esas acciones pueden alterar el comportamiento o bloquear la edición manual.
- En una fase posterior, una vez obtenida la captura y revisadas las dependencias, se prepararán archivos versionables con referencias a secretos y una operación de aplicación explícita con backup, preflight, plan y rollback.

## Validaciones recomendadas

1. `python -m unittest discover -s tests -p test_grafana_alerting.py -v` (o `uv run --python 3.15 --no-project -m unittest discover -s tests -p test_grafana_alerting.py -v`).
2. Comprobar que el Job `capture` termina con `failed=0`.
3. Ejecutar `compare` con la ruta y hash devueltos; inicialmente debe indicar `SIN CAMBIOS` salvo que el alerting haya cambiado entre ejecuciones.
4. No ejecutar un plan de escritura a partir de estos datos sin revisión adicional.

## Documentación y control de cambios

Mantener este documento y las variables de ejemplo junto al playbook. Si más adelante se incorporan alertas como código, actualizar también el README de instalación del laboratorio, los flujos **Grafana → bot → SMTP/Telegram**, el inventario AWX de credenciales y las instrucciones de recuperación antes del commit.
