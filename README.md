# Bloque 01 · Fase 3 — Exportación segura de los 15 dashboards Grafana (AWX)

**Fecha:** 10-11-2026. **Proyecto:** `deployment-kits` (laboratorio antiguo), NO `infrastructure-platform`.

## Resultado previo validado

- Job Template `10 - Auditar Grafana`: `ok=6 changed=0 failed=0`; 15 dashboards, 5 datasources; Grafana DB `ok`.
- Job Template `11 - Gestionar Dashboards`: `ok=41 changed=0 failed=0`; los 7 dashboards V2 exportados a Git coinciden exactamente (`SIN CAMBIOS`).
- **Este paquete es aditivo:** NO sustituye los playbooks 10 y 11 ni los JSON existentes.

## Qué hace / qué NO hace

El Job Template `12 - Exportar Dashboards Grafana` consulta por GET la API de Grafana, comprueba que devuelve **exactamente 15 dashboards con UID único**, los descarga por API V2 y usa `/api/dashboards/uid/<uid>` como alternativa si el recurso no existe en la API V2. Conserva los formatos **V2, V1 y clásico** sin convertirlos. Si hay un dashboard inaccesible o inconsistente, detiene el paquete en lugar de declarar un backup completo.

Escribe UN ZIP con `manifest.json` (UID, título, formato, ruta, checksum SHA256 por JSON) y 15 JSON individuales. Usa un nombre único en un **directorio persistente del host `grafana-servers`**, permisos privados (`0700` directorio, `0600` ZIP), sin sustituir exportaciones anteriores. El staging privado de ESTA ejecución se borra solo tras completar el ZIP.

**No modifica Grafana**: no ejecuta POST/PUT/DELETE, no reinicia servicios, no toca Docker Compose, datasource, paneles ni base de datos. **Sí escribe el ZIP y archivos temporales en el sistema de archivos del servidor**, por tanto el recap tendrá `changed` superior a cero. Esto es normal.

**No constituye una copia integral de Grafana**: faltan su DB, configuración, datasources, plugins, permisos, secretos, alertas e información de usuarios.

## Archivos añadidos al repositorio antiguo

```text
monitorizacion/
├── playbooks/exportar_dashboards_grafana.yml
├── tasks/grafana/exportar_dashboard.yml
├── files/grafana_export_bundle.py
└── examples/variables_exportacion_grafana.yml

tools/verificar_exportacion_grafana.py  # CLI en PC Windows/Linux, no se usa en AWX
```

## Configuración Job Template 12

1. Copia **solo los archivos nuevos**, manteniendo las rutas del ZIP, sobre `deployment-kits`.
2. Haz commit/push y sincroniza el proyecto de AWX.
3. Crea Job Template `12 - Exportar Dashboards Grafana`: proyecto `deployment-kits`, playbook `monitorizacion/playbooks/exportar_dashboards_grafana.yml`, mismo inventario y credencial SSH/BECOME que el Job 11, grupo `grafana-servers`.
4. Adjunta la credencial personalizada de Grafana que inyecta `VAR_GRAFANA_ADMIN_PASSWORD` (la misma que en 10 y 11). Se reutilizan `var_grafana_port`, `var_grafana_admin_user`, `var_grafana_install_dir` ya existentes en AWX. Nunca meter contraseñas en Extra Variables, código, ZIP adjuntos públicos o logs.
5. El valor esperado es **15** por defecto. Si se añade/quita un dashboard, revisar primero el inventario y ajustar deliberadamente `var_grafana_export_expected_count` en las variables de AWX; no ignorar la comprobación.
6. Lanza 12. Confirma `failed=0`, `unreachable=0`, `Exportación completada: 15 dashboards`; anota ruta ZIP y SHA256 impresos. No marcar como validado hasta que el ZIP esté descargado y el verificador confirme el contenido.

**Requisitos en servidor:** Python 3 y `zipfile` estándar (Ubuntu incluye ambos), espacio disponible para ZIP + staging (aproximadamente el doble de los JSON exportados), usuario AWX con sudo para escribir los archivos root-only, red local hacia Grafana API.

### Recuperar el ZIP en tu PC

AWX usa un entorno efímero (`/runner`); por eso el ZIP **no está en AWX**, sino en el servidor de Grafana, cuya ruta exacta aparece en el último `debug` (por defecto `{{ var_grafana_install_dir }}/backups/dashboard-exports/...zip`).

1. Entra por SSH al servidor de Grafana con el usuario habitual.
2. Copia la ruta EXACTA del ZIP que muestra AWX a tu directorio personal, creando una copia privada accesible por SSH (sustituye los marcadores):

```bash
sudo install -m 0600 -o "$(id -un)" -g "$(id -gn)" \
  '/ruta/impresa/por/AWX/grafana-dashboards-FECHA.zip' \
  "$HOME/grafana-dashboards-export.zip"
```

3. Descarga con PowerShell desde tu PC, utilizando la dirección/usuario del laboratorio (ejemplo ilustrativo):

```powershell
scp usuario@IP_DEL_SERVIDOR:~/grafana-dashboards-export.zip "$HOME\Downloads\grafana-dashboards-export.zip"
```

4. En el directorio local del repositorio, comprueba el backup y compáralo con los siete JSON originales:

```powershell
python .\tools\verificar_exportacion_grafana.py "$HOME\Downloads\grafana-dashboards-export.zip" --repositorio .
```

Opcionalmente, extrae en una **carpeta nueva** fuera de `monitorizacion/dashboards`, para revisión manual:

```powershell
python .\tools\verificar_exportacion_grafana.py "$HOME\Downloads\grafana-dashboards-export.zip" --repositorio . --extraer "$HOME\Downloads\grafana-candidatos"
```

**Mantén el ZIP y la carpeta de candidatos fuera del repositorio Git** hasta completar la revisión de seguridad y decidir qué archivos versionar.

Tras confirmar la copia en el PC, puedes borrar la copia de tu `HOME` del servidor; conserva el ZIP protegido en `backups/dashboard-exports` y verifica las políticas de retención/almacenamiento antes de cualquier limpieza.

## Interpretación y próximos pasos

- `15 dashboards` y `7 coincidencias`: exportación consistente respecto al Git anterior.
- Los **8 restantes** estarán en `dashboards/v2`, `/v1` o `/legacy` según el formato de API recibido. Si son V2, revisaremos si deben incorporarse como JSON al directorio gestionado; V1/legacy requerirán un tratamiento explícito de compatibilidad, no renombrarlos a V2.
- Los archivos exportados pueden contener rutas, URLs internas, consultas y otros datos sensibles. **No subir el ZIP ni su contenido a un repositorio público ni a tickets** antes de revisarlos; Git privado también requiere revisión de secretos.
- La automatización actual de los 7 dashboards permanece en modo AUDITORÍA. El Job 12 no habilita escrituras ni modifica esas decisiones.
- Tras validar la exportación: preparar backup de BD/configuración de Grafana, documentar restauración, después gestionar dashboards y datasources con rollback verificado.

## Si falla

- `Faltan variables`: añade a Job 12 el mismo conjunto usado por Jobs 10/11.
- Cantidad distinta de 15: no se crea ZIP; revisar permisos/organización y repetir auditoría 10.
- GET 401/403/404 no recuperable: revisar permisos y Dashboard UID; no crear backups incompletos.
- `No space left on device`: detener, comprobar disco; no limpiar ni eliminar el almacenamiento de Grafana.
- Si un error deja `.stage-*` o `.zip.partial`, **no borrar nada automáticamente fuera de la carpeta de esta ejecución**. Investigar y retirar manualmente solo los temporales de ese intento cuando estén identificados.
