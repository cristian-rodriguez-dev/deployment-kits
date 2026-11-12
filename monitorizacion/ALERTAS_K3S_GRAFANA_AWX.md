# Grafana Alerting — dos reglas K3s (pausadas)

Bloque incremental para el proyecto antiguo `deployment-kits`.

## Alcance

Añade **solo** dos reglas nuevas, sin modificar las cinco existentes, su contact point ni sus políticas. Reutiliza el datasource de Grafana con UID `prometheus` y la carpeta/grupo de la regla `Host Down - Sistemas y Devs`. No crea carpetas ni modifica grupos. Los UID están fijados para que repetir la ejecución no duplique reglas.

| UID | Alerta | Condición | Pending |
| --- | --- | --- | --- |
| `awx-k3s-deploy-unavail` | K3s - Deployment sin replicas disponibles | Réplicas deseadas > disponibles | 5m |
| `awx-k3s-crashloop` | K3s - Contenedor en CrashLoopBackOff | Waiting reason = CrashLoopBackOff | 5m |

La consulta de replicas utiliza `kube_deployment_spec_replicas` y `kube_deployment_status_replicas_available`. La segunda utiliza `kube_pod_container_status_waiting_reason`.

## Instrucciones

1. Descomprime el paquete dentro de la raíz de `deployment-kits`. Confirma con `git status --short` que solo introduces los archivos nuevos. No agregues archivos `.git`, backups ni variables con secretos.
2. `git add monitorizacion/playbooks/crear_alertas_k3s_grafana.yml monitorizacion/files/grafana_k3s_rules.py monitorizacion/examples/variables_k3s_alerting_grafana.yml`
3. Revisa, haz commit/push y sincroniza el proyecto en AWX.
4. Crea el Job Template `25 - Crear alertas K3s Grafana (seguro)` (ajusta el número si ya está ocupado) y selecciona `monitorizacion/playbooks/crear_alertas_k3s_grafana.yml`. Usa el inventario `grafana-servers` y la credencial `VAR_GRAFANA_ADMIN_PASSWORD` utilizada en el Job 24.
5. Ejecuta en modo `plan` (por defecto) y comprueba que las métricas están presentes, el anchor existe y hay dos reglas pendientes. No crea reglas, pero copia una herramienta auxiliar al servidor.
6. Para crear las dos reglas **PAUSADAS** ejecuta de nuevo con `var_grafana_k3s_mode: apply` y `var_grafana_k3s_confirm: CREATE_PAUSED_ONLY`. Revisar primero el respaldo del Job 24.
7. Comprueba las reglas en Grafana y sus consultas. **No reanudes ambas de golpe.** Habilita cada regla individualmente después de verificar expresiones, ausencia de falsos positivos, políticas de routing y recepción por el bot.
8. Ejecuta el Job 24 con `compare` respecto a la referencia inicial, y una nueva captura para la versión aprobada.

## Comportamiento seguro

- No se ejecutan `PUT`, `PATCH` ni `DELETE`. Tampoco se actualizan contact points o rutas.
- Cualquier UID o título preexistente con contenido inesperado cancela la ejecución sin sobrescribirlo.
- Las dos reglas se crean inicialmente con `isPaused: true`.
- `noDataState: OK` evita que una ausencia de datos dispare la regla, pero **no detecta la pérdida de kube-state-metrics**: eso debe vigilarse por separado con la alerta `up{job="kube-state-metrics"}` o una comprobación externa.
- El script verifica mediante el proxy de Grafana que Prometheus contiene métricas de Deployments y Pods. Si no las encuentra, no crea reglas.
- Crear alertas mediante la API de provisioning puede cambiar su modo de gestión frente a alertas creadas desde UI. El header `X-Disable-Provenance` se utiliza para intentar conservar la edición por UI; comprobar en Grafana.
- Una creación parcial por fallo HTTP se puede reejecutar; el UID fijo previene duplicados.
- La copia del script al servidor puede contar como `changed` en AWX aunque no exista ninguna modificación de Grafana.

## Requisitos conocidos

- Grafana 13.2.3, Prometheus con datasource UID `prometheus`.
- `kube-state-metrics` configurado como target en el laboratorio antiguo.
- Python 3 en el servidor, con acceso local a Grafana, y credenciales AWX del Job 24.

No desplegar un segundo Prometheus ni modificar los playbooks existentes.
