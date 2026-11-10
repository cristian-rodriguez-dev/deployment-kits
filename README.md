# Bloque 01 — Grafana: auditoría y dashboards V2 en AWX (laboratorio antiguo)

## Alcance

Este bloque añade dos playbooks al repositorio `deployment-kits` sin sustituir
`instalar_grafana.yml`, editar `docker-compose.yml`, cambiar el datasource
Prometheus, reinstalar Grafana ni actualizar versiones.

- `auditar_grafana.yml`: **solo lectura**. Consulta `/api/health`, datasources y dashboards.
- `configurar_dashboards_grafana.yml`: **solo auditoría por defecto**. Compara
  exportaciones de Git con Grafana y, cuando se autorice, crea o actualiza
  recursos por la API V2. **Nunca elimina dashboards**.
- `tasks/grafana/auditar_dashboard_v2.yml` y `tasks/grafana/aplicar_dashboard_v2.yml`: tareas reutilizadas por el segundo playbook.
- `dashboards/`: directorio para los JSON exportados, inicialmente vacío.
- `examples/variables_dashboards_grafana.yml`: flags de control de AWX.

## Antes de empezar: faltan las exportaciones

El ZIP `deployment-kits.zip` aportado **no incluía los 7 dashboards JSON**.
Por ello no se incluyen dashboards inventados ni se asume que ya estén
versionados. Exporta desde Grafana 13 los siete dashboards existentes en
formato **V2 Resource JSON** y coloca exactamente un JSON por dashboard en:

```text
monitorizacion/dashboards/
  fleet-infrastructure-overview.json
  platform-overview.json
  host-detail.json
  security-overview.json
  traefik-overview.json
  loki-overview.json
  k3s-overview.json
```

Los nombres son orientativos; el UID operativo es `metadata.name` dentro de cada JSON.
No renombres UIDs, ni modifiques el bloque `spec`, ni reemplaces los archivos
existentes por JSON de otro laboratorio sin antes revisar la correspondencia.

**Nota de compatibilidad:** los formatos dashboard V2 (`apiVersion:
"dashboard.grafana.app/v2"`) no deben copiarse como si fueran JSON Classic.
Este bloque emplea la API `/apis/dashboard.grafana.app/v2/namespaces/default/dashboards`.
Requiere Grafana 13 compatible con esta API; se contrastó documentación oficial,
pero debe probarse con la instancia concreta antes de habilitar escrituras.

## Configuración AWX

Se mantiene el proyecto Git, el inventario y el grupo `grafana-servers` actuales.
No crear duplicados de host. Utilizar la misma credencial Machine SSH con sudo
que utiliza `instalar_grafana.yml` y la credencial que expone
`VAR_GRAFANA_ADMIN_PASSWORD` al entorno de ejecución.

Crear dos nuevas plantillas de trabajo, fuera del workflow actual:

| Nombre sugerido | Playbook (ruta relativa a Git) | Ejecución |
| --- | --- | --- |
| `10 - Auditar Grafana` | `monitorizacion/playbooks/auditar_grafana.yml` | Solo lectura |
| `11 - Gestionar Dashboards Grafana` | `monitorizacion/playbooks/configurar_dashboards_grafana.yml` | Solo lectura inicialmente |

Variables del grupo `grafana-servers` ya usadas por el instalador:
`var_grafana_install_dir`, `var_grafana_port`, `var_grafana_admin_user`.
Inyectar `VAR_GRAFANA_ADMIN_PASSWORD` mediante credencial de AWX: **nunca Git**.

Añadir únicamente estos flags como variables de grupo o extra vars de la plantilla:

```yaml
var_grafana_dashboards_apply: false
var_grafana_dashboards_allow_updates: false
```

Los flags deben ser booleanos reales (`true`/`false`, sin comillas).

## Procedimiento de adopción en el laboratorio

1. Guarda el nuevo contenido en la estructura indicada. Commit y push del
   bloque independiente; sincroniza el proyecto Git de AWX.
2. Ejecuta `10 - Auditar Grafana`. Comprueba salud, nombres de datasources y
   total de dashboards (se esperan los 7 indicados, sujetos a auditoría real).
3. Coloca los siete JSON originales del mismo Grafana en
   `monitorizacion/dashboards/`, commitea y sincroniza el proyecto.
4. Ejecuta `11 - Gestionar Dashboards Grafana` con
   `var_grafana_dashboards_apply: false`. Comprueba **SIN CAMBIOS**, CREAR o
   ACTUALIZAR para cada UID. Este modo no escribe nada.
5. Si se muestran como **SIN CAMBIOS**, el estado de Git y la API coincide;
   no es necesario activar la escritura.
6. Solo para dashboards ausentes y tras verificar los UIDs, usa
   `var_grafana_dashboards_apply: true` y
   `var_grafana_dashboards_allow_updates: false`. Permite crear dashboards
   nuevos pero protege los existentes.
7. Si necesitas sustituir un dashboard existente, revisa manualmente el
   diff de JSON y la copia de seguridad de Grafana/SQLite antes de autorizar
   una ejecución específica con los dos flags en `true`. El playbook realiza
   un **respaldo JSON por UID** en `<var_grafana_install_dir>/backups/dashboards/`.
8. Tras cualquier aplicación, vuelve a ejecutar en modo auditoría y confirma
   que los dashboards y paneles siguen visibles. No reemplaza pruebas UI.

## Contrato de seguridad

- Predeterminado = solo lectura.
- Rechaza formatos no V2, UIDs inválidos y duplicados antes de escribir.
- Audita los siete UIDs y rechaza conflictos **antes de iniciar las escrituras**.
- No hay `DELETE`, ni `prune`, ni importación masiva por carpetas.
- No se cambian contenedores, puertos, permisos de la BD ni secretos.
- No modifica los datasources y no convierte dashboards automáticamente.
- Las credenciales API se mantienen fuera de Git y ocultas en el log AWX.
- Actualización de UID existente solo con opt-in explícito y respaldo JSON.
- Si hay un error 409 de concurrencia u otro HTTP, **detener y revisar**;
  no sobreescribir a la fuerza. Si hay modificaciones parciales entre varios
  dashboards, comprobar qué UIDs se aplicaron antes de reintentar.
- Si una exportación contiene una carpeta que no existe en el Grafana destino,
  la API puede rechazar la creación: crear/verificar la carpeta por separado.
- No se garantiza idempotencia semántica ante normalizaciones del `spec`
  efectuadas por Grafana; comparar en modo auditoría después de cada ejecución.

## Validación realizada en este paquete

- Sintaxis YAML y estructura del repositorio verificadas sin ejecutar tareas
  sobre servidores reales.
- **Pendiente en el AWX del laboratorio:** comprobar permisos API, formato V2
  exacto de las exportaciones, cambios reportados y repetición idempotente.

## Rollback

- Auditoría: no aplica, ya que no modifica datos.
- Creación: **no borrar automáticamente** el dashboard; evaluar la eliminación
  manual tras confirmar que el UID es nuevo y que no hay trabajo posterior.
- Actualización: recuperar la copia JSON previa a través de la API V2,
  tras verificar manualmente UID, carpeta y `resourceVersion` actual.
- Este paquete no sustituye un backup real de la base de datos de Grafana.

## Próximos bloques independientes

1. **Grafana (este paquete):** auditoría y gestión controlada de dashboards.
   Datasources Prometheus ya están provisionados por el instalador; Loki y
   OpenSearch/Wazuh deben evaluarse contra lo que existe antes de automatizarlos.
2. **Wazuh GeoIP:** conservar pipeline y mappings, comprobar IPs públicas.
3. **Wazuh Active Response:** reglas, scripts, listas de exclusión y pruebas.
4. **Bot de triaje:** Compose, variables, almacenamiento, healthchecks.
5. **Alerting:** reglas, contact points, SMTP y pruebas de entrega.
6. **Traefik:** auditoría de configuración existente antes de gestionarla.
7. **Healthchecks, copias de seguridad y recuperación.**

No se han añadido estos otros bloques al ZIP para mantener cada entrega independiente.
