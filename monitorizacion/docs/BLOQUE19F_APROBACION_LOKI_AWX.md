# Pilas Observabilidad — Bloque 19F: aprobación humana y revalidación de Loki (piloto sin ejecución)

## Alcance y fronteras

**Repositorio:** `deployment-kits`. No usar `infrastructure-platform` ni modificar Security Triage, Docker, SQLite, K3s, reglas Grafana o los notificadores. Se añaden un playbook que importa el diagnóstico 19C, sus pruebas offline y esta guía.

El 19F **no es una recuperación de Loki**. Implementa la parte segura del workflow de AWX: aprobación explícita, relectura del estado *después* de aprobar, y resultado informativo (`no_action` o `investigate`). No contiene un paso de reinicio, borrado, escala ni acción correctiva. **Aprobar 19F NO autoriza ninguna remediación futura.**

El 19D verifica exclusivamente jobs 19C con `launch_type=manual`; un trabajo disparado por workflow usa otro tipo de lanzamiento y otro playbook. **No presentar el 19F como un job verificado por 19D.** Para conectar este flujo a Security Triage en otro bloque habrá que validar el Workflow Job, la aprobación y los eventos por la API autenticada de AWX; no basta con el JSON impreso.

### Dependencia

Debe existir `monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml` (19C) en la misma carpeta del repositorio que sincroniza AWX. El 19F **importa ese playbook**, evita duplicar lógica y obtiene una observación fresca en el mismo trabajo. Reutiliza el grupo `prometheus-servers` y limita internamente a `ansible_server`.

## Instalación en Windows (PowerShell)

1. Descargar `deployment-kits-bloque19F-aprobacion-loki.zip` en `Descargas`.
2. Verificar que `C:\deployment-kits` contiene 19C.
3. Descomprimir en una carpeta temporal y copiar solo tres archivos; detenerse si algún destino ya existe.
4. Ejecutar con `uv` y Python 3.12 (NO usar `py`, que no está disponible en este Windows):

```powershell
cd C:\deployment-kits
uv run --no-project --python 3.12 --with pyyaml --with jinja2 python -B -m unittest discover -s monitorizacion/tests -p "test_loki_awx_approval_gate.py" -v
if ($LASTEXITCODE -ne 0) { throw 'Tests 19F fallidos: no publicar' }
```

5. Preparar **solo** los tres archivos nuevos con `git add -- ...` y revisar `git diff --cached --check` y `git diff --cached --stat`. Hacer commit/push **solo al remoto autorizado** si la política del entorno lo permite; después, en AWX, sincronizar el Proyecto vinculado a `deployment-kits`.

## Configuración AWX (manual, no ejecutarla hasta revisar los permisos)

### A. Job Template fijo de revalidación (19F)

- Nombre: `19F - Revalidar Loki post-aprobacion - AUDIT`.
- Proyecto: el que obtiene `deployment-kits`.
- Playbook: `monitorizacion/playbooks/revalidar_loki_k3s_post_aprobacion.yml`.
- Inventario/credencial: los mismos usados para `19C - Diagnosticar Loki K3s - AUDIT`; host único `ansible_server`.
- Deshabilitar **todos** los `Prompt on launch`, **Surveys** y schedules; limitar acceso a los administradores responsables del workflow. **No conceder Execute directo a usuarios del bot ni a operadores generales**: si se lanzara el Job Template fuera del workflow, saltaría el nodo de aprobación.
- El playbook es solo lectura; el 19C importado aún emplea `become: true` como las auditorías K3s existentes. Para automatización futura, separar un kubeconfig con RBAC `get pods` mínimo. No dar credenciales de AWX ni kubeconfig admin al bot.

### B. Workflow Job Template (piloto manual)

Nombre recomendado: `19F - Aprobacion y revalidacion Loki - PILOTO`.

DAG EXACTO (sin ramas `Always` ni `Failure`):

```text
[Inicio manual]
      |
      v
[APPROVAL: Autorizar SOLO revalidacion Loki | timeout 900s]
      | (ON SUCCESS, aprobacion humana)
      v
[JT 19F - Revalidar Loki post-aprobacion - AUDIT]
      |
      v
[Fin: no_action / investigate, NUNCA remediar]
```

- El primer nodo es un **Approval** de AWX, creado en el visualizador del Workflow; **no** usar una variable `approved=true`, un Survey ni aprobación en el propio webhook.
- El siguiente nodo tiene enlace **On Success exclusivamente**. `Failure`/`Always` permanecen vacíos. Denegación/caducidad no deben continuar el flujo.
- Timeout recomendado de Approval: **900 segundos**, para evitar aprobaciones indefinidas. Se trata de una recomendación operativa, no de una propiedad ya configurada.
- Conceder aprobación solo al rol de **Approver** o a los roles de administración autorizados. Para separación real de funciones, usar operador iniciador y aprobador diferentes. Usuarios con permisos administrativos pueden disponer de capacidades superiores, por lo que la segregación debe verificarse en la configuración real.
- **Sin schedules, inventarios solicitados, `extra_vars` editables ni encuestas**. No conceder a Security Triage los permisos `Execute`/`Approve`.
- No incorporar jobs de reinicio, reparación, `kubectl delete/rollout/scale/patch`, Docker o systemd. Este workflow termina tras el informe.

AWX admite nodos de aprobación con rutas de éxito/fallo y roles específicos de aprobación. Referencia: https://github.com/ansible/awx/blob/devel/docs/workflow.md

### C. Una única prueba controlada en AWX

1. Con Loki operando normalmente, lanzar el workflow **manualmente**.
2. Comprobar que se queda **a la espera de aprobación** y que todavía no arrancó el Job Template 19F.
3. Un usuario con rol de aprobación autoriza el paso.
4. Verificar que el Job 19F ejecuta el diagnóstico de solo lectura e informa `status=no_action`, `reason_code=loki_ready`, `execution_allowed=false`, `action_executed=false`, `changes_kubernetes=false` y recap `changed=0`. Si el estado real cambió, se espera `investigate`, **sin corrección automática**.
5. Si el workflow no espera aprobación o alguien puede arrancar directamente el JT 19F sin permisos adecuados, **deshabilitar el workflow y corregir RBAC**.
6. No simular una caída real de Loki para probar las rutas. La rama `ready=false` queda cubierta por tests offline.

## Qué acredita y qué no

- AWX aplica la aprobación **solo si su DAG y permisos están bien configurados**. El playbook por sí solo **no puede verificar una aprobación**; por eso devuelve `approval_verified=false`, `requires_external_workflow_validation=true`.
- `ready=true` ⇒ `no_action`; `ready=false` ⇒ `investigate` (posible causa diversa); `ready=null` ⇒ `investigate` (estado desconocido). No inferir que un pod no preparado se repara reiniciándolo.
- Este flujo **no** verifica todavía el vínculo `19E` entre incidente y workflow/approval, ni lo convierte en una orden de ejecución.

## Reversión

- En AWX: deshabilitar/eliminar el Workflow 19F y su Job Template, revocar roles asignados específicamente a ambos y sincronizar el Proyecto.
- En Windows: si estos tres archivos siguen sin otros cambios ni se han utilizado en otro trabajo, eliminarlos de `deployment-kits`. Si estaban staged, ejecutar `git restore --staged -- <rutas>` antes de eliminar; si estaban publicados, gestionar su retirada mediante un commit revisado (no reescribir el historial remoto).
- No hay rollback en Ubuntu ni contenedores: este bloque no los altera.

## Siguiente trabajo, solo si se confirma necesidad real

Vincular el Workflow 19F a una revisión de incidente 19E mediante verificaciones autenticadas de origen y aprobación. Diseñar por separado una recuperación **con operación explícita, preflight específico, mínimo privilegio, aprobación independiente, rollback y comprobación posterior**. No añadirla silenciosamente al presente workflow.
