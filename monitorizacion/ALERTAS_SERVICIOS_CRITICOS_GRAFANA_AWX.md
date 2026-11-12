# Grafana Alerting — servicios críticos mediante AWX (laboratorio antiguo)

Este bloque añade **solo tres reglas nuevas**, inicialmente **pausadas**. No configura destinos, no modifica las 7 reglas existentes, no cambia el árbol de notificaciones y no toca servicios Docker/K3s.

## Qué reglas se crean

| UID | Título | Consulta resumida | Pending | Estado inicial |
| --- | --- | --- | --- | --- |
| `awx-critical-triage-down` | Critico - Bot de triaje IA no disponible | `1 - (min(up{job="security-triage-bot"}) or vector(0))` | 2m | Pausada |
| `awx-critical-wazuh-containers` | Critico - Wazuh con contenedores ausentes | 3 menos los servicios Compose observados recientemente (`manager`, `indexer`, `dashboard`) | 3m | Pausada |
| `awx-critical-loki-notready` | Critico - Loki no disponible | `1 - (max(kube_pod_container_status_ready{namespace="logging",pod="loki-0",container="loki",...}) or vector(0))` | 5m | Pausada |

- Los valores esperados de **las tres consultas** cuando la plataforma está sana son `0`.
- Las expresiones `or vector(0)` cubren la desaparición de una serie, **pero no equivalen a una comprobación funcional de la aplicación**.
- Una pérdida de cAdvisor o kube-state-metrics puede parecer una caída de Wazuh/Loki. La regla del bot comprueba el endpoint de métricas, no que Gemini procese tareas.
- Solo Wazuh **Compose project `wazuh`** y **sus tres servicios** cuenta para Wazuh. Loki mira únicamente `logging/loki-0`, evitando el pod temporal `helm-install-loki`.
- La expresión de Wazuh devuelve *número de servicios ausentes*; no identifica cuál. El triaje debe consultar las series cAdvisor para enriquecer el incidente.
- Si cambian el nombre del pod/namespace de Loki o la topología de Wazuh, habrá que versionar las consultas; son definiciones basadas en la topología actual.
- Se usa `noDataState: OK` según el patrón previo; esto **puede ocultar fallos del propio datasource**. Antes de activarlas, configurar vigilancia separada de `up{job="docker-cadvisor"}`, `up{job="kube-state-metrics"}` y salud de Prometheus, idealmente desde un observador externo.

## Dependencias existentes

- Grafana 13.2.3 accesible localmente por `127.0.0.1:var_grafana_port`.
- Datasource Grafana UID `prometheus`, de tipo Prometheus.
- Regla de referencia `Host Down - Sistemas y Devs` para reutilizar carpeta/grupo (sin crear nueva carpeta).
- Jobs de Prometheus `security-triage-bot`, `docker-cadvisor`, `kube-state-metrics` con `up=1`.
- La contraseña se inyecta en AWX desde la credencial que aporta la variable de entorno `VAR_GRAFANA_ADMIN_PASSWORD`, como en Jobs 24/25. Nunca subirla a Git.

## Integración y ejecución

1. Descomprimir el ZIP **en la raíz de `deployment-kits`**. Revisar los cuatro tipos de cambios: dos scripts (`grafana_critical_services_rules.py` nuevo; `grafana_k3s_rules.py` actualización), un playbook y documentación/tests/ejemplo.
2. Para el Job 25 existente, el único cambio es sincronizar la consulta `CrashLoopBackOff` con Grafana: se añade `or vector(0)` conservando `namespace,pod,container`. **No ejecutar en `apply` para forzar una actualización**: el Job 25 no modifica reglas existentes; puede comprobarse en `plan` que aparecen como existentes si coinciden.
3. `python3 -m unittest discover -s tests -p 'test_critical_service_alerts.py' -v` desde la raíz del repositorio. Revisar cambios `git diff --check`, `git status --short`. Añadir solo ficheros funcionales y docs, no `.git`, `.venv`, cachés ni backups.
4. Commit y push. **Sincronizar el proyecto en AWX** (falló en un bloque previo por olvidar el sync).
5. Crear el Job Template **`26 - Alertas servicios críticos Grafana`** (o el siguiente número libre), playbook `monitorizacion/playbooks/crear_alertas_servicios_criticos_grafana.yml`, mismo Project/Inventory/Credentials que el Job 25. Las variables `var_grafana_install_dir`, `var_grafana_port` y `var_grafana_admin_user` deben heredarse del inventario existente.
6. Ejecutar únicamente:

   ```yaml
   var_grafana_critical_mode: plan
   ```

   Esperado: `Datasource Prometheus: OK`, `Targets de origen UP: 3/3`, `Incidencias actuales: ZERO`, `Reglas pendientes de crear: 3`, `Reglas nuevas creadas y pausadas: 0`.

7. Solo si el plan es correcto y ya existe el respaldo del Job 24, autorizar explícitamente:

   ```yaml
   var_grafana_critical_mode: apply
   var_grafana_critical_confirm: CREATE_PAUSED_ONLY
   ```

   El script únicamente usa `POST /api/v1/provisioning/alert-rules` para crear reglas **pausadas**; no usa `PUT`, `PATCH`, `DELETE` ni toca destinatarios. Al repetir, detecta reglas equivalentes, aunque hayan sido activadas manualmente. Cambios inesperados provocan rechazo por deriva.

8. Comprobar en Grafana que existen 10 reglas en total y las 3 nuevas están pausadas; verificar Preview y estados No Data/Error. No activarlas todas a la vez.
9. **Antes de activar la alerta del propio bot**, garantizar que el contacto recibe el aviso directamente desde Grafana (email/Telegram independiente de la lógica del bot). Comprobar el enrutamiento y ejecutar prueba de notificación controlada. Las reglas Wazuh/Loki también deben verificar su ruta.
10. Validar una transición controlada a Firing y a Normal cuando exista un entorno de pruebas seguro. No derribar Wazuh/Loki/bot en el servidor real solo para probar alertas.
11. Ejecutar el Job 24 en modo `capture` **tras** aprobar las reglas, manteniendo el respaldo anterior de 7 reglas.

## Garantías y límites

- Modo `plan`: solo GET a Grafana/Prometheus; Ansible puede registrar `changed` por copiar el script auxiliar al servidor, sin modificar Grafana.
- Modo `apply`: rechaza escrituras si cualquier fuente de métricas está DOWN o si alguna expresión inicial tiene un valor diferente de cero/No Data. Revisa todas las colisiones antes del primer POST.
- UID fijo para idempotencia; una creación interrumpida puede dejar parte de las reglas **pausadas**, se puede reejecutar para completar.
- Las credenciales viajan por variables de entorno de un proceso local y las tareas sensibles usan `no_log`. No se imprime la configuración de los contact points.
- Se mantiene deliberadamente el API clásico de Grafana ya usado con éxito en el Job 25. La documentación oficial marca esa API como obsoleta para futuras versiones; migrar a App Platform APIs cuando toque refactorizar, sin cambiar ahora la integración estable.
- No alterar el proyecto `infrastructure-platform` al integrar este bloque para el laboratorio antiguo.
