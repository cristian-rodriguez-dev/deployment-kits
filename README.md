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