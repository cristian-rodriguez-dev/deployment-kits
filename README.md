# Bloque 01 v2 — Corrección de auditoría Grafana AWX y exportaciones verificadas

## Diagnóstico del error aportado (10-11-2026)

El Job Template se detuvo en `Comprobar variables de Grafana en AWX`, **antes** de ejecutar cualquier llamada HTTP. El `no_log: true` del `assert` antiguo censuró cuál de los requisitos falló. No implica que se haya eliminado o modificado un dashboard.

El nuevo `auditar_grafana.yml` diferencia errores en variables, formato del puerto, disponibilidad de Grafana y autenticación. **Solo muestra nombres de variables ausentes, jamás contraseñas**. Evita `become` porque consulta la API local mediante GET sin necesidad de sudo.

`SSH password` y `BECOME password` son solicitudes de credenciales de la plantilla AWX; no indican una ejecución fallida. El aviso `ANSIBLE_COLLECTIONS_PATHS` y los guiones de nombres de grupos no son la causa de este error.

## Qué incluye

- `monitorizacion/playbooks/auditar_grafana.yml`: GET health/datasources/dashboard search (auditoría sin cambios).
- `monitorizacion/playbooks/configurar_dashboards_grafana.yml`: comparación por API V2. **ESCRITURAS BLOQUEADAS en este paquete incluso si el operador establece `var_grafana_dashboards_apply: true`**.
- `monitorizacion/tasks/grafana/*.yml`: helpers mantenidos como referencia; no se ejecuta la rama de escrituras en este paquete.
- `monitorizacion/dashboards/*.json`: 7 exportaciones V2 originales, con 187 paneles, conservadas sin modificar sus contenidos.
- `monitorizacion/examples/variables_dashboards_grafana.yml`: los dos switches permanecen en `false`.
- `tests/test_contract.py`: contratos estáticos de YAML, modos, identificadores y número de paneles.

## Grafana: exports incluidos

| Título | UID | Paneles |
|---|---|---:|
| Fleet - Infrastructure Overview | `adnk6jm` | 25 |
| Platform Overview | `adqmqdw` | 8 |
| Host Detail | `adcfhnb` | 37 |
| Security Overview | `adgsl8t` | 40 |
| Traefik Overview | `ad4fsvl` | 22 |
| Loki Overview | `adghvhn` | 21 |
| K3s Overview | `adrxc42` | 34 |
| **Total** | **7** | **187** |

Los JSON son fotografías de la configuración exportada: **pueden diferir de los dashboards vivos si han cambiado desde la exportación**. No habilites escritura basándote únicamente en estos archivos.

## Instalación

1. Descomprime las rutas `monitorizacion/...` sobre tu repo `deployment-kits` **sin reemplazar** `instalar_grafana.yml`, Compose, volumen o datasource.
2. Commit, push y sincronización de proyecto en AWX.
3. En el Job Template `10 - Auditar Grafana` selecciona playbook `monitorizacion/playbooks/auditar_grafana.yml`, inventario y credencial SSH de siempre. Revisa que esté vinculado al grupo `grafana-servers`.
4. Verifica que `var_grafana_port` (ejemplo `3000`) y `var_grafana_admin_user` estén en las variables de grupo `grafana-servers` de AWX. Usa los **valores existentes**, sin recrear el grupo.
5. Adjunta al **mismo Job Template** la credencial de AWX que expone la variable de entorno `VAR_GRAFANA_ADMIN_PASSWORD`. No es la contraseña SSH; si la credencial es `Custom Credential Type` debe inyectar ese nombre exacto. No añadas la contraseña a Git, extra vars ni capturas/logs.
6. Ejecuta el Job Template 10. Ahora debería identificar la variable que falta, si la hay; si llega a HTTP 401/403, comprueba credencial/privilegios en lugar de reinstalar Grafana.
7. Con resultado correcto, ejecuta `11 - Gestionar Dashboards Grafana` con `var_grafana_dashboards_apply: false`, para obtener `SIN CAMBIOS`, `CREAR` o `ACTUALIZAR` por UID. Si marca `CREAR` para todos, revisa conexión/org/UID antes de hacer nada más.

## Garantía de seguridad de esta revisión

Las ejecuciones de ambos playbooks están limitadas a consultas de lectura. El `10` solo invoca GET. El `11` rechaza el modo `apply` **antes de cualquier tarea remota**. Ningún dashboard se crea, sustituye ni elimina; ningún contenedor se reinicia; ninguna base de datos o datasource se cambia.

La aplicación real de dashboards se habilitará en una entrega independiente, tras verificar las diferencias y disponer de copia de seguridad real de Grafana. No se ha probado conexión a tu entorno AWX ni la API de Grafana desde este entorno.

## Qué hacer si sigue fallando

- Si aparece `Faltan en el Job Template o inventario AWX: ...`, añade únicamente las variables indicadas y vuelve a lanzar.
- Si falla `/api/health`, verifica puerto y accesibilidad **desde el host `ansible_server`**.
- Si health pasa pero falla una consulta autenticada, verifica usuario/contraseña actual y permisos de lectura.
- Si el paso 11 no reconoce `/apis/dashboard.grafana.app/v2/`, conserva el modo solo lectura y revisa compatibilidad de versión/API antes de cambios.

## Compatibilidad y alcance

Respeta `monitorizacion/...`, grupo `grafana-servers`, variables `var_grafana_*` y el instalador vigente del proyecto antiguo. No toca `infrastructure-platform` ni crea nuevos inventarios. Si hay modificaciones respecto a las exportaciones, se comunicarán en la auditoría, no se aplicarán automáticamente. Mantén este README junto al bloque en Git.
