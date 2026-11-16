# Bloque 19H — Recuperación segura de Alloy Host mediante AWX

Proyecto: **Pilas Observabilidad**. Repositorio: **`deployment-kits`** (Windows).

## Alcance

Piloto **manual** para iniciar exclusivamente el servicio Linux `alloy.service` del host `ansible_server`. La operación solo se ejecuta si el servicio está **inactive** y se han superado todas las comprobaciones. **No reinicia servicios activos** ni repara automáticamente los servicios `failed`, directorios, permisos o configuraciones incorrectas. No modifica Alloy K3s, Loki, Wazuh, Grafana ni Security Triage.

El playbook `monitorizacion/playbooks/recuperar_alloy_host_post_aprobacion.yml` admite:

- `var_alloy_recovery_mode: audit` (predeterminado), solo lectura; `ready_for_manual_approval` significa únicamente que las precondiciones actuales pasaron.
- `var_alloy_recovery_mode: apply` con `var_alloy_recovery_confirmation: START_ALLOY_ONLY_AFTER_AWX_APPROVAL`, para el Job Template restringido del workflow. La cadena **no** demuestra aprobación: AWX debe garantizarla con su DAG y RBAC.

### Precondiciones

1. Inventario `prometheus-servers`, limitado a exactamente `ansible_server`.
2. `systemctl show` acredita un servicio instalado con `User=alloy`, `Group=alloy`, posibilidad de inicio y sin `daemon-reload` pendiente.
3. Si está `active` no hace nada. Si está `failed` o en transición, aborta: investigar primero.
4. Si está `inactive`: configuración `/etc/alloy/config.alloy` no vacía, `alloy validate` correcto; `/var/lib/alloy` propiedad de `alloy` y escribible por ese usuario. Si existe `positions.yml` del journal o su directorio, son propiedad de `alloy` y escribibles por él. No cambia sus permisos.
5. La consulta de K3s debe confirmar que el Deployment `logging/alloy` utiliza el hostPath separado `/var/lib/alloy-k3s` y no monta `/var/lib/alloy` ni sus subdirectorios.
6. Antes de iniciar reconsulta que el servicio sigue inactivo; después comprueba `ActiveState=active`.

**No implica recuperación integral de logs:** para eso habría que comprobar posteriormente la ingestión en Loki/Grafana.

## Instalación en Windows

Descomprimir el ZIP de entrega dentro de `C:\deployment-kits`, **solo si los archivos no existen**. Ejecutar las pruebas con:

```powershell
uv run --no-project --python 3.12 --with pyyaml --with jinja2 python -B -m unittest discover -s monitorizacion/tests -p "test_alloy_host_awx_recovery.py" -v
```

Revisar y versionar únicamente los tres archivos del bloque, sincronizar el proyecto AWX. No subir credenciales ni datos del servidor.

## Configuración en AWX

Crear dos **Job Templates independientes** sobre el mismo playbook y el proyecto `deployment-kits`:

| Job Template | Extra variables fijas | Uso |
| --- | --- | --- |
| `19H - Alloy Host - AUDIT` | `var_alloy_recovery_mode: audit` | Diagnóstico de solo lectura. Ejecutable manualmente. |
| `19H - Alloy Host - APPLY protegido` | `var_alloy_recovery_mode: apply` + `var_alloy_recovery_confirmation: START_ALLOY_ONLY_AFTER_AWX_APPROVAL` | **Solo** nodo del workflow aprobado. |

En ambos: inventario con `ansible_server` en `prometheus-servers`, **Limit: `ansible_server`**, credencial de máquina existente, permisos `become` para systemd y consultas de K3s. Desactivar **Prompt on launch**, Survey, programación y cualquier paso que permita modificar variables, límite, credenciales o playbook durante el lanzamiento.

**Seguridad operativa:** la cadena `START_ALLOY_ONLY_AFTER_AWX_APPROVAL` no prueba aprobación y no es un secreto. Un usuario con permisos para ejecutar directamente el Job Template `APPLY` podría omitir el workflow; restringir mediante RBAC los permisos `Execute`, `Admin` y modificación del proyecto/credenciales/plantillas. AWX puede permitir a administradores saltarse el flujo: mantener el Job Template reservado a operadores autorizados. No utilizar el usuario de Security Triage para lanzar Jobs.

Crear workflow manual: 

1. Nodo Job Template `19H - Alloy Host - AUDIT`.
2. **On Success** → Approval Node `19H - Autorizar inicio Alloy Host`, timeout de 15 minutos.
3. **On Success** → Job Template `19H - Alloy Host - APPLY protegido`.
4. **Sin ramas `Always` o `Failure` hacia APPLY.** Sin horarios ni webhook. El operador debe comprobar el informe AUDIT antes de aprobar.

Si AUDIT devuelve `no_action`, no es necesario aprobar. Si devuelve `ready_for_manual_approval`, valorar manualmente si la detención fue intencionada y si es seguro intervenir. El estado actual se verifica de nuevo en APPLY.

**Primera prueba segura:** con Alloy actualmente activo, lanzar el workflow. AUDIT devolverá `no_action`; no aprobar si no hace falta. Para comprobar exclusivamente la rama de aprobación, un operador puede aprobarla con Alloy activo: APPLY seguirá sin cambios; **no detener Alloy artificialmente**.

## Validaciones y límites

- Pruebas offline: contrato YAML, lista cerrada, controles de estado, hostPath, permisos, validación de configuración y ausencia de comandos de parada o reinicio.
- Prueba AWX: `PLAY RECAP changed=0` si el servicio ya está activo. Nunca ejecutar una caída simulada en el laboratorio de uso habitual.
- No conectar al bot ni activar remediación autónoma. El informe `approval_verified: false` exige comprobación del workflow en AWX.
- Si se produce `failed`, K3s inaccesible o permisos incorrectos, el job debe **fallar sin cambios**. La aprobación humana no exime de estas comprobaciones.

## Reversión

Eliminar/inhabilitar primero el workflow y el Job Template APPLY. Después retirar los tres archivos del repositorio mediante un commit revisado y sincronizar AWX. El playbook no crea archivos persistentes en Ubuntu. Si un operador autorizó e inició Alloy, retirar el playbook **no detiene ese servicio**; no detenerlo como parte de rollback sin decisión explícita.
