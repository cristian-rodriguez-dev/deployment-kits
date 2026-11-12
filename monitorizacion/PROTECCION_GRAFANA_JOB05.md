# Job 05 — Protección de instalación y SMTP (laboratorio anterior)

## Contexto verificado (12/11/2026)

- Grafana mediante Docker Compose, carpeta `/home/servidor/instalacion/grafana`.
- Volúmenes bind persistentes: `data/`, `provisioning/`, `secrets/admin_password`.
- SMTP añadido al Compose vivo y `.env` privado. Envía alertas directamente por Telegram y correo sin depender del bot de triaje.
- Alerting respaldado: 10 reglas, 3 contact points. Job 27 verificó 5 reglas nuevas sin deriva.

## Riesgo que resuelve

El antiguo Job 05 reescribe `docker-compose.yml` por una plantilla sin SMTP y ejecuta `docker_compose_v2`; esa secuencia podría borrar las variables SMTP de Compose al recrear el servicio. Un backup no sustituye la prevención.

## Reglas operativas del Job 05 protegido

| Modo | Instalación existente | Acción |
| --- | --- | --- |
| `inspect` | Sí | Lectura de metadatos, informa presencia de DB, Compose, `.env` y SMTP, termina antes de writes. |
| `install` (defecto) | Sí (Compose o `grafana.db`) | **Falla antes de crear/editar/redesplegar**. |
| `install` | Nueva VM vacía | Sigue los pasos del instalador original. |
| `install` + `var_grafana_smtp_enabled: true` | Nueva VM vacía con `.env` | Instala la plantilla con SMTP opcional; validación usa `--env-file` para no perder interpolación. |

### Para inspeccionar el servidor actual en AWX

```yaml
var_grafana_job05_mode: inspect
```

Resultado previsto:

```
Modo: INSPECT; solo lectura; no se instalara ni reiniciara Grafana
Compose existente: True
Base de datos existente: True
Archivo .env existente: True
SMTP declarado en Compose: True
Sin alteraciones de volumenes, alertas, secretos ni contenedores
```

Estas indicaciones son para **Job 05**, no para el Job 24, 25, 26 o 27.

### Instalación nueva con SMTP (no usar en Grafana actual)

```yaml
var_grafana_job05_mode: install
var_grafana_smtp_enabled: true
```

Variables solo en `.env` privado remoto (modo 0600; propietario adecuado para la ejecución Compose):

```dotenv
GRAFANA_SMTP_HOST=smtp.gmail.com:587
GRAFANA_SMTP_USER=cuenta@example.com
GRAFANA_SMTP_PASSWORD='CONTRASENA_DE_APLICACION'
GRAFANA_SMTP_FROM_ADDRESS=cuenta@example.com
```

Los valores mostrados son ejemplos; no introducir credenciales reales en Git. Para un nuevo despliegue también habrá que provisionar `.env` de manera segura; este Job **no crea** credenciales SMTP ni modifica el `.env` del Grafana actual.

## Pendiente de automatizar

- Adopción gestionada de Compose existente sin borrar configuraciones locales (comparación semántica y aprobación explícita).
- Versionado de reglas y contact points sin exponer secretos, con estrategias audit / apply separadas.
- Prueba aislada del flujo de restauración de Grafana.

No ejecutar el instalador legado desde el workflow de instalación sobre un host con Grafana operativo. Revisar y documentar este bloqueo en el README del workflow asociado antes del próximo commit de ese bloque.
