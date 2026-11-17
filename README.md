# Pilas Observabilidad — `deployment-kits` (laboratorio heredado)

Repositorio de automatización, configuración y verificación del **laboratorio antiguo** de seguridad y observabilidad. Es independiente de `infrastructure-platform` y sigue siendo la referencia operativa del entorno existente.

> **Estado:** laboratorio funcional con componentes instalados, auditorías y pilotos. **No** existe todavía un workflow único verificado que reconstruya toda la plataforma desde cero.

## Componentes y responsabilidades

| Área | Componentes | Función |
| --- | --- | --- |
| Automatización | Ansible / AWX sobre K3s | Despliegue de servicios, agentes, configuraciones, auditorías y tareas de mantenimiento. |
| Seguridad | Wazuh Manager, Indexer, Dashboard y agentes | Recopilación, análisis e indexación de eventos de seguridad. |
| Respuesta activa | Wazuh Active Response, Python, iptables y systemd | **Piloto SSH** validado en el agente `005`; no protege automáticamente a todos los equipos. |
| Métricas | Prometheus, Node Exporter, cAdvisor, kube-state-metrics | Recopilación de métricas de servidores, contenedores y K3s. |
| Logs | Loki, Grafana Alloy | Recopilación y consulta de logs, según colector y origen configurados. |
| Visualización y alertas | Grafana | Datasources, dashboards, reglas y canales de alerting. |
| Proxy y correlación | Traefik y puente Traefik–Loki–Wazuh | Exposición/routing y tratamiento de eventos del proxy para seguridad. |
| GeoIP | Pipeline Wazuh/OpenSearch y panel GeoIP | Enriquecimiento y visualización geográfica de IPs. |
| Bot de alerting | `security-triage-bot` (**repositorio/servicio separado**) | FastAPI, Smart Triage, Gemini, SQLite, enriquecimiento y notificadores Telegram/SMTP. En este repositorio hay **integraciones**, pero no su instalador completo. |

## Organización de este repositorio

```text
deployment-kits/
├── collections/                 # Requisitos de colecciones Ansible
├── monitorizacion/
│   ├── playbooks/              # Entradas de ejecución en AWX
│   ├── roles/                  # Roles de seguridad e integración
│   ├── templates/              # Plantillas de servicios
│   ├── files/                  # Herramientas transferidas por Ansible
│   ├── tasks/                  # Tareas reutilizables de Grafana
│   ├── integrations/           # Puente Traefik–Wazuh
│   ├── manifests/              # Manifiestos para K3s
│   ├── dashboards/             # Dashboards versionados
│   ├── examples/               # Variables de ejemplo SIN secretos
│   └── docs/                   # Guías técnicas específicas
├── tests/                       # Pruebas del código y contratos
└── tools/                       # Herramientas locales de verificación
```

## Workflows y playbooks existentes

La automatización inicial incluía:

1. **Despliegue instalación (01–05):** `instalar_docker.yml` → `instalar_wazuh.yml` → `configurar_wazuh.yml` → `instalar_prometheus.yml` → `instalar_grafana.yml`.
2. **Despliegue Agentes (06–07):** `instalar_agentes_monitorizacion.yml` → `configurar_agentes_prometheus.yml`.

Los archivos se encuentran en `monitorizacion/playbooks/`. Hay también playbooks independientes de observabilidad K3s, Alloy Host, dashboards, GeoIP, alertas de Grafana, backups/restauración, auditorías, Traefik y Active Response.

**Precaución:** estos workflows heredados **no** constituyen todavía una reconstrucción integral validada. `instalar_observabilidad_k3s.yml` prepara accesos Kubernetes que utiliza el Prometheus antiguo; esta dependencia debe revisarse en el orden de instalación.

## Modos de operación y seguridad

- **Instalación limpia:** ejecutar únicamente en hosts nuevos y después de validar variables, rutas, puertos y recursos.
- **Inspección / auditoría:** utilizar los modos de solo lectura de los playbooks protegidos, especialmente los de Grafana y Prometheus, sobre instalaciones existentes.
- **Adopción:** procedimiento distinto de instalación; seguir las guías y las comprobaciones previas.
- **Backups y restauración:** conservar los scripts/verificadores y ejecutar ensayos controlados antes de cualquier restauración real.
- **Active Response:** piloto sujeto a aprobación y pruebas; no habilitar bloqueos indiscriminados.
- **Credenciales:** usar AWX y ficheros privados según el contrato de cada componente; **nunca** guardar contraseñas, tokens, certificados privados, volúmenes o bases de datos reales en Git.

Nunca ejecutar `docker compose down -v` en una instalación con datos que deban conservarse. Un `git pull` o una sincronización de AWX **no** autorizan por sí solos un despliegue ni una actualización.

## Documentación de entrada

- [Instalación básica y configuración de AWX](monitorizacion/README_DESPLIEGUE_AWX.md)
- [Agentes y targets de Prometheus](monitorizacion/AGENTES.md)
- [Auditoría y gestión de Grafana Alerting](monitorizacion/ALERTING_GRAFANA_AWX.md)
- [Protección del instalador de Grafana](monitorizacion/PROTECCION_GRAFANA_JOB05.md)
- [Protección del instalador de Prometheus](monitorizacion/PROTECCION_PROMETHEUS_JOB04.md)
- [Copias de Grafana](monitorizacion/BACKUP_GRAFANA_AWX.md)
- [Restauración de Grafana](monitorizacion/RESTAURACION_GRAFANA_AWX.md)
- [Wazuh Active Response](monitorizacion/docs/WAZUH_ACTIVE_RESPONSE.md)
- [GeoIP de Wazuh](monitorizacion/GEOIP_WAZUH_AWX.md)
- [Traefik, Loki y Wazuh](monitorizacion/docs/TRAEFIK_LOKI_WAZUH.md)
- [Integración de métricas del bot](monitorizacion/TRIAGE_METRICS_AWX.md)

## Fase actual: instalación limpia antes que adopción

Objetivo de la fase: automatizar **instalaciones desde cero en Ubuntu Server 24.04**, probar un workflow maestro reproducible en VMs nuevas, y después preparar compatibilidad 26.04. La adopción y los cambios en instalaciones existentes quedan para más adelante.

**Job 01 Docker:** se ha adaptado `monitorizacion/playbooks/instalar_docker.yml` para exigir confirmación explícita, rechazar hosts ajenos y evitar reinicios sobre configuraciones existentes. Ver [guía de instalación limpia Docker 24.04](monitorizacion/docs/DOCKER_INSTALACION_LIMPIA_2404.md) y [variables de ejemplo](monitorizacion/examples/variables_docker_clean_2404.yml). **Nunca probar el Job 01 en el laboratorio actual.**

## Pendiente para el workflow maestro

- Auditar preflight, inventarios, credenciales y dependencias antes de construir el workflow.
- Separar las rutas **instalación limpia**, **inspección/adopción**, **mantenimiento** y **recuperación**; nunca encadenarlas indiscriminadamente.
- Incorporar la instalación automatizada del bot desde su repositorio propio, creación/configuración inicial de GeoIP, alerting y verificaciones end-to-end cuando se implementen.
- Validar idempotencia, retención de datos, fuentes de logs, consultas de datasources, paneles, targets, notificación y recuperación.

**Regla de mantenimiento:** conservar aquí solo código reutilizable, pruebas y documentación vigente. Los artefactos de un solo uso, instrucciones de parches ya aplicados, cachés, secretos y datos locales deben quedar fuera del repositorio.
