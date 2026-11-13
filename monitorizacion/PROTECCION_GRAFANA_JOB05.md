# Job 05 — Instalación protegida de Grafana (laboratorio antiguo)

## Alcance y estado

El Job Template real de AWX es **`05 - Instalar Grafana`** y ejecuta
`monitorizacion/playbooks/instalar_grafana.yml` en `grafana-servers`.

En el laboratorio operativo existe Grafana con SMTP, datos persistentes,
dashboards y reglas de alerting. **Este Job NO adopta, no reconfigura, no
actualiza ni repara una instalación existente.** Para esa finalidad se requiere
otro procedimiento con auditoría, respaldo y autorización.

La validación local del parche es estática/unitaria: no supone haberlo probado
todavía con `ansible-playbook --syntax-check` ni en AWX.

## Contrato de seguridad

| Modo | Sin especificar confirmación | Instalación existente | Resultado |
| --- | --- | --- | --- |
| Sin variable / `inspect` | Permitido | Cualquiera | Solo lectura; `meta: end_play` antes de tareas de escritura |
| `install` | **Rechazado** | Cualquiera | Exige `INSTALL_NEW_GRAFANA` |
| `install` + confirmación | Permitido | Ruta nueva vacía | Instalación inicial, sujeta a demás prechecks |
| `install` + confirmación + SMTP | Permitido | Ruta con **solo** `.env` privado | Instalación inicial si `.env` es regular, root y 0600 |
| `install` + confirmación | Permitido | Compose, `data`, secretos, provisioning, marca de AWX, ficheros extra o proyecto Compose preexistentes | **Rechazado antes de escribir** |

El guard examina la ruta completa, incluidos archivos ocultos, y comprueba
contenedores detenidos o activos bajo el proyecto `var_grafana_project_name`.
La inspección no ejecuta Docker ni requiere contraseñas del administrador.

### Variables de Extra Variables de AWX

**Servidor actual — usar siempre:**

```yaml
---
var_grafana_job05_mode: inspect   # Solo lee huellas y presencia de SMTP
```

El `var_grafana_install_dir` se hereda de `grafana-servers` (en el laboratorio
histórico era `/home/servidor/instalacion/grafana`; comprobar el valor real).
No incluir `var_grafana_job05_confirm` en la plantilla habitual de auditoría.

**Solo instalación en VM nueva y con aprobación explícita:**

```yaml
---
var_grafana_job05_mode: install
var_grafana_job05_confirm: INSTALL_NEW_GRAFANA
var_grafana_smtp_enabled: false  # true SOLO si ya existe .env privado root:root 0600
```

El modo `install` **no es idempotente sobre un despliegue existente**: una segunda
ejecución debe rechazarse y no cambiar contenedores/DB. No encadenar
`install` por defecto en un workflow que pueda alcanzar el laboratorio actual.

### Variables de inventario/credenciales

El modo `inspect` solo necesita una ruta `var_grafana_install_dir` válida,
el host en `grafana-servers` y credencial Machine para conexión/`become`.

El modo `install` exige además las variables del instalador:
`var_grafana_access_group`, `var_grafana_project_name`, `var_grafana_image`,
`var_grafana_port`, `var_grafana_admin_user`, `var_grafana_admin_email`,
`var_monitorizacion_network` y `var_grafana_prometheus_url`.
La contraseña llega exclusivamente desde la credencial personalizada que
inyecta `VAR_GRAFANA_ADMIN_PASSWORD` en el Execution Environment.

Con `var_grafana_smtp_enabled: true`, provisionar en la VM **antes** de instalar
el único archivo `<var_grafana_install_dir>/.env` como archivo regular propiedad
de root, modo `0600`, y con estas claves no vacías:

```dotenv
GRAFANA_SMTP_HOST=servidor.smtp.example:587
GRAFANA_SMTP_USER=cuenta@example.com
GRAFANA_SMTP_PASSWORD=SECRETO_FUERA_DE_GIT
GRAFANA_SMTP_FROM_ADDRESS=cuenta@example.com
```

No se admite un `.env` symlink. Ni el contenido de `.env` ni las credenciales
SMTP deben almacenarse en Git ni aparecer en logs. `slurp`/validaciones
confidenciales están marcadas con `no_log: true`.

## Comprobaciones y límites

- El guard y las comprobaciones Docker del proyecto se ejecutan **antes** de
  cualquier `apt`, template, copia, red, arranque o handler.
- El instalador conserva la lógica de Compose, volúmenes persistentes,
  provisioning y health checks del proyecto anterior.
- No hay `prune`, actualización de imágenes forzada ni adopción automática.
- Este control no demuestra que los puertos estén libres, ni cubre otros
  proyectos Compose con nombres diferentes o despliegues externos.
- El modo `inspect` informa de presencia de configuraciones, pero no valida la
  salud de Grafana, SMTP ni la correspondencia de sus dashboards.
- La creación inicial con SMTP requiere que el `.env` se provisione **fuera**
  de este Job; no mover una instalación activa para superar el guard.

## Validación antes de utilizar AWX

Desde la raíz de `deployment-kits`:

```powershell
uv run --no-project --python 3.12 --with pytest --with pyyaml --with jinja2 python -X utf8 -m pytest tests/test_grafana_job05_guard.py -q -p no:cacheprovider

git diff --check
```

Después, en un entorno Ubuntu con Ansible y `community.docker`, ejecutar
`ansible-playbook --syntax-check` con inventario adecuado, y probar el Job 05
**en modo inspect** sobre el laboratorio antiguo (`changed=0`, `failed=0`).
Instalación nueva solo en VM aislada. No se ha desplegado ni hecho commit
como parte de esta entrega.

Actualizar la guía de variables AWX y el README general al incorporar este
cambio. No confundir este Job 05 con Jobs 10–13 ni 24–28.
