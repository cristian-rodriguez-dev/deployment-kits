# Pilas Observabilidad — Bloque 19C: diagnóstico manual de Loki mediante AWX

## Alcance

Pertenece al repositorio **`deployment-kits`**. Se basa en la pauta de
`monitorizacion/playbooks/auditar_traefik_k3s.yml`: grupo `prometheus-servers`,
`kubectl` en el servidor K3s y consultas de solo lectura.

Nuevos archivos:

- `monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml`
- `monitorizacion/tests/test_loki_awx_diagnostic.py`
- `monitorizacion/docs/BLOQUE19C_LOKI_AWX.md`

No se modifica ningún archivo existente, `main.py`, bases de datos,
notificadores, alertas Grafana, reglas pausadas, contenedores ni recursos K3s.
**No hay integración automática con Security Triage**, ni llamadas a AWX desde el bot.

## Operación

1. AWX lanza **manualmente** el Job Template sobre el único host `ansible_server`,
   que debe pertenecer a `prometheus-servers`.
2. En ese host se consulta la salud de la API K3s con el mismo mecanismo que el
   playbook de auditoría de Traefik.
3. Si la API está disponible, se consulta **solo** el pod `logging/loki-0`,
   mediante `kubectl get pod` sin lecturas de secretos ni logs.
4. Se comprueba que la respuesta corresponde al pod exacto y que el contenedor
   `loki` aparece en la especificación. El estado `ready` procede **únicamente**
   del booleano de `status.containerStatuses`, cuando existe.
5. Se publica una observación restringida con `pod_found`, `container_found`,
   `ready` (true/false/null) y tiempo UTC de la comprobación.

Un error de API/permisos/parseo hace **fallar** el trabajo; no se transforma en
`ready=false`. Si falta pod o estado del contenedor, se publica `ready=null`,
no una caída confirmada. No se consulta el contenido de los logs.

La salida emplea `source=kubernetes_api`, `namespace=logging`, `pod=loki-0`,
`container=loki` y `observed_at_utc`, compatibles con el *esquema* de 19B.
Sin embargo, `verified_provenance=false`: **una salida AWX no acredita por sí sola**
que una observación pertenezca a un incidente concreto. La futura capa 19D
necesitará comprobar, como mínimo, identidad del Job Template, ID y estado del job,
inventario/host, tiempo UTC, alcance, autenticación del API de AWX, correlación
con el incidente y autenticidad de los datos antes de marcar
`observation_trusted=True`. Nunca aceptar ese booleano de webhooks, Gemini o
variables proporcionadas por usuarios.

## Seguridad y permisos

- El Job Template debe fijar **proyecto, inventario, credencial de máquina y
  playbook**. No permitir `Prompt on launch` para inventario, credenciales,
  límite, etiquetas o variables adicionales. No crear Survey.
- Dar `Execute` solo a los operadores que deban lanzarlo; nadie del bot recibe
  credenciales de AWX ni permiso para lanzar el job.
- Se conserva `become: true` por compatibilidad con las auditorías K3s
  existentes. Puede implicar utilizar privilegios amplios de Kubernetes.
  **Esto solo es aceptable como piloto manual**. Antes de una integración
  automática, provisionar un acceso K8s de solo lectura con RBAC limitado a
  `get pods` del pod `loki-0` en el namespace `logging`, más lo imprescindible
  para consultar salud de API, y retirar la dependencia de un kubeconfig admin.
- El playbook no ejecuta `apply`, `delete`, `patch`, `rollout`, `restart`,
  `scale` ni modifica archivos. Los resultados crudos de Kubernetes se ocultan
  con `no_log: true`.
- AWX debe tener un proyecto sincronizado con el repositorio `deployment-kits`.
  El archivo local de Windows **no aparece automáticamente en AWX**.
- El objetivo es fijo. Nunca convertir namespace, pod o contenedor en
  campos editables desde webhook, IA o encuesta AWX.

## Instalación en Windows

Descargar `deployment-kits-bloque19C-loki-awx.zip` en Descargas y ejecutar
PowerShell desde una terminal normal (no requiere administrador):

```powershell
$ErrorActionPreference = 'Stop'
$repo  = 'C:\deployment-kits'
$zip   = Join-Path $env:USERPROFILE 'Downloads\deployment-kits-bloque19C-loki-awx.zip'
$stage = Join-Path $env:TEMP 'pilas-19C-stage'

if (-not (Test-Path -LiteralPath $repo)) { throw 'No existe deployment-kits' }
if (-not (Test-Path -LiteralPath $zip)) { throw 'No se encuentra el ZIP en Descargas' }
if (Test-Path -LiteralPath $stage) { throw 'El directorio temporal ya existe; usa otro nombre' }
Expand-Archive -LiteralPath $zip -DestinationPath $stage

$paths = @(
  'monitorizacion\playbooks\auditar_loki_k3s_remediacion.yml',
  'monitorizacion\tests\test_loki_awx_diagnostic.py',
  'monitorizacion\docs\BLOQUE19C_LOKI_AWX.md'
)

foreach ($relative in $paths) {
  $src = Join-Path $stage $relative
  $dst = Join-Path $repo $relative
  if (-not (Test-Path -LiteralPath $src)) { throw "Falta en el ZIP: $relative" }
  if (Test-Path -LiteralPath $dst) { throw "El archivo ya existe; no sobrescribir: $dst" }
}

foreach ($relative in $paths) {
  $dst = Join-Path $repo $relative
  New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $stage $relative) -Destination $dst
}

Set-Location $repo
py -B -m unittest discover -s monitorizacion\tests -p test_loki_awx_diagnostic.py -v
if ($LASTEXITCODE -ne 0) { throw 'Pruebas offline fallidas' }

git status --short
git diff --check
```

Se esperan **9 pruebas estáticas**, y otras **5 opcionales** si el entorno
Python dispone de `PyYAML` y `Jinja2`. Las 14 se ejecutaron correctamente en
el entorno de preparación. Estas pruebas **no sustituyen** la validación de
Ansible dentro de AWX.

Revisar el diff antes de añadir estos tres archivos al commit. En Git solo
introducir los tres archivos nuevos, nunca secretos, logs, bases de datos,
archivos de inventario privados ni copias completas del servidor.

## Alta y prueba en AWX (manual)

1. Confirmar que la copia de `deployment-kits` usada por el **Proyecto AWX**
   contiene el nuevo playbook. Si el Proyecto usa SCM Git, llevar solo los
   archivos revisados al remoto autorizado y ejecutar **Actualizar proyecto**.
   No asumir que editar `C:\deployment-kits` actualiza AWX.
2. Crear un **Job Template** independiente, por ejemplo
   `19C - Diagnosticar Loki K3s - AUDIT`, con el proyecto `deployment-kits`,
   el inventario ya usado por `auditar_traefik_k3s.yml`, el playbook
   `monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml` y las credenciales
   de máquina ya usadas para las auditorías K3s.
3. Desactivar los prompts del lanzamiento y las encuestas. Fijar los recursos.
   Conceder `Execute` solo a operadores autorizados; no añadirlo a workflows
   de despliegue o remediación.
4. Lanzarlo **una sola vez manualmente**, sin detener Loki ni simular caídas.
   Validar que el job termina `successful`, `changed=0` y que la observación
   muestra el estado real. Si `ready=true`, no hay propuesta de recuperación.
5. Si falla por kubeconfig, credenciales, API o inventario, **detenerse**.
   No resolverlo ampliando indiscriminadamente privilegios ni reiniciando K3s.

La primera ejecución remota es una prueba pendiente: el archivo no está
configurado actualmente como Job Template en AWX.

## Rollback

Si no se han modificado después, borrar **solo**:

- `monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml`
- `monitorizacion/tests/test_loki_awx_diagnostic.py`
- `monitorizacion/docs/BLOQUE19C_LOKI_AWX.md`

Si ya existe el Job Template, deshabilitar o eliminar primero su acceso
operativo y después quitar los archivos en la fuente del proyecto AWX y volver
a sincronizar. No hay rollback en Ubuntu, Kubernetes ni Docker: este bloque no
los modifica.

## Siguiente paso

Bloque 19D: definir y probar un adaptador **solo lectura** entre AWX y
Security Triage, que valide la autenticidad y vigencia del job antes de
establecer el parámetro interno `observation_trusted`. No integrar todavía
aprobaciones ni ejecución de remediaciones.
