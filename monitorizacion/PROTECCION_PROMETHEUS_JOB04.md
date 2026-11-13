# Job 04 — Protección del Prometheus existente

## Riesgo identificado

`monitorizacion/playbooks/instalar_prometheus.yml` contiene tareas de plantilla de `prometheus.yml` y Docker Compose, seguidas de `docker_compose_v2` y recarga de la configuración. En el laboratorio operativo, una ejecución sobre la ruta actual podría sobrescribir targets y provocar pérdida de observabilidad. Este es el mismo tipo de incidencia que ocurrió con SMTP y el Job 05 de Grafana.

## Modos

- `inspect` (predeterminado): `stat` de la ruta, Compose, `prometheus.yml` y almacenamiento `data`. Presenta booleanos sin revelar configuración ni credenciales. Finaliza por `meta: end_play` antes de cualquier cambio.
- `install`: requiere `var_prometheus_job04_confirm: INSTALL_NEW_PROMETHEUS`, ruta nueva que no existe y ausencia de contenedores con la etiqueta del proyecto Compose. Si se detecta instalación, falla de forma explícita.

## Invariantes

1. Nunca actualizar ni recrear la instalación existente desde el Job 04.
2. Nunca reescribir `prometheus.yml` con la plantilla histórica de instalación.
3. No borrar datos TSDB, targets, métricas o credenciales.
4. Tratar cambios de scrapes/targets como un proceso aparte: plan -> diff -> validación `promtool` -> aprobación -> aplicación -> health checks -> rollback.
5. No relanzar el workflow de despliegue sin revisar las Extra Variables efectivas de sus nodos y la revisión SCM.

## Verificación funcional en AWX

Extra Variables seguras:

```yaml
var_prometheus_job04_mode: inspect
```

Resultado esperado (depende de las rutas en ese host):

```text
Modo: INSPECT; solo lectura; no se instalara ni reiniciara Prometheus
Directorio existente: True
Compose existente: True
Configuracion existente: True
Almacenamiento existente: True
Sin alteraciones de targets, TSDB, contenedores ni credenciales
```

`PLAY RECAP` esperado: `changed=0 failed=0`.

**Nota:** ninguna lectura de ficheros en este modo valida los 9 jobs en tiempo real. Para ello se consultan métricas `up` y targets por otros procedimientos ya operativos.
