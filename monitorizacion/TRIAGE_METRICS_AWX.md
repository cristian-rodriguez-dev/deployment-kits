# Security Triage → Prometheus → Grafana (laboratorio antiguo)

## Alcance y estado de partida

Esta integración ya se configuró manualmente y dio `up{job="security-triage-bot"} = 1`.
**No instalar** el bot ni Prometheus otra vez para automatizar este enlace.

- Bot: `/home/servidor/instalacion/security-triage-bot`; Compose `compose.yml`, `compose.indexer.yml`, `compose.metrics.yml`.
- Prometheus: `/home/servidor/instalacion/prometheus_server`; Compose `docker-compose.yml`, `compose.metrics.yml`.
- Red: `triage-metrics-private` (Docker `bridge`, `internal: true`). Alias del bot: `triage-metrics`.
- Scrape: `security-triage-bot`, `http://triage-metrics:8080/internal/metrics`, cada 30 s.
- Credencial: `/home/servidor/instalacion/prometheus_server/prometheus/triage_metrics_token`, legible por UID 65534; no imprimir ni versionar.
- Dashboard: **Security Triage — Observabilidad del Bot**, importado manualmente en Grafana.

## Job Template de AWX

- Playbook: `monitorizacion/playbooks/integrar_security_triage_metrics.yml`.
- Inventario: host que ejecuta ambos contenedores en el grupo **prometheus-servers**.
- Credencial de máquina: acceso SSH con sudo ya utilizado para Prometheus.
- Variables de grupo:

```yaml
var_prometheus_install_dir: /home/servidor/instalacion/prometheus_server
var_triage_bot_install_dir: /home/servidor/instalacion/security-triage-bot
var_prometheus_port: 9090
var_triage_integration_mode: audit
```

**Primera ejecución:** `audit`; no crea red, no toca archivos y falla si el job, token
 o target `up=1` no son compatibles. `apply` crea únicamente la red privada si
falta, crea overlays **solo si no existen** y conecta contenedores si están
separados; no reconstruye ni reinicia contenedores. Se niega a sobrescribir
un overlay diferente y no altera el YAML de scrape existente. La segunda
aplicación debe reportar `changed=0`.

**Limitación de gestión:** el playbook adopta un job ya existente; no gestiona
su primera creación ni un token ausente. Ambos requieren procedimiento
separado y autorizado. Si `up=0`, primero recuperar conectividad; no forzar
recreación de servicios.

## Persistencia si AWX reinstala Prometheus

`instalar_prometheus.yml` usa plantillas y puede sobrescribir modificaciones
manuales. Se ha incorporado a ambas plantillas Jinja2 un bloque **opcional**.
**Antes de volver a ejecutar ese instalador**, indicar en el grupo de AWX:

```yaml
var_prometheus_triage_enabled: true
var_triage_metrics_network: triage-metrics-private
```

El instalador ahora requiere una red y un token **preexistentes**, y renderiza
job + red adicional sin eliminar los jobs declarados en la plantilla.
No ejecutar el instalador solo para aplicar esta integración; puede generar
otros cambios no relacionados en servicios existentes. Validar con
`promtool` y `up` tras cualquier despliegue.

Para futuros despliegues manuales del bot y de Prometheus, incluir
`compose.metrics.yml` junto con los Compose que se empleen normalmente.
No dejar que otro workflow use solo los Compose base si puede recrear los servicios.

## Grafana — dashboard como código (16/16 V2)

La exportación del **12/11/2026** confirmó 16 recursos
`dashboard.grafana.app/v2`, sin V1 ni clásicos. El dashboard
**Security Triage — Observabilidad del Bot** se conserva en
`monitorizacion/dashboards/security-triage-observabilidad.json` con UID de
Grafana `security-triage-observabilidad`, **25 paneles** y datasource
`prometheus`. Los 15 dashboards anteriores mantienen sus especificaciones.

Fuente verificada: ZIP exportado por AWX
`grafana-dashboards-20261112T104736Z-d7vdtx.zip`;
SHA256: `2869f92a27f9cc8c294619581207d3c2d997b8bb96c60781300071766c6e1fa3`.
No versionar el ZIP completo: únicamente el JSON del nuevo dashboard.

Comprobaciones locales desde la raíz de `deployment-kits`:

```powershell
uv run --python 3.13 --with pytest --with pyyaml --no-project python -X utf8 -m pytest -v tests/test_contract.py tests/test_verificacion.py
uv run --python 3.13 --no-project python tools/verificar_cobertura_dashboards.py --repo .
# Con el ZIP original disponible, añadir --export RUTA_AL_ZIP
```

En AWX utilizar `monitorizacion/playbooks/configurar_dashboards_grafana.yml`
con `var_grafana_dashboards_apply: false`. Auditar los **16 UIDs** y verificar
**16/16 SIN CAMBIOS** antes de considerar el bloque incorporado. Este playbook
**bloquea cualquier escritura** por diseño; agregar el JSON a Git no importa
ni modifica dashboards en el servidor. No habilitar `apply` ni cambiar la
protección del playbook para este bloque.

El exportador puede trabajar con `var_grafana_export_expected_count: 16`.
Los tests que generan snapshots históricos de 15 dashboards siguen siendo
fixtures de pruebas y no representan el inventario actual. Los ensayos de
restauración deben usar la cantidad del backup concreto, no asumir que todas
las copias históricas contienen los 16.

## Seguridad e idempotencia

- Nunca publicar `.env`, token, claves, certificados ni credenciales AWX en Git.
- No modificar el rol genérico de Docker ni dar permisos de escritura al bot.
- No reiniciar Wazuh, Prometheus, SMTP, Telegram ni Grafana en la adopción.
- Revisar `.md` de inventario, flujos de red, seguridad y operación antes del commit.
- Los campos de las métricas son agregados: no contienen logs originales.
