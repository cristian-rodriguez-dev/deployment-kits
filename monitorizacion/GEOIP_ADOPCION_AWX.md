# Bloque 02 — Wazuh GeoIP / Job 16 — Adopción protegida

**Proyecto:** `deployment-kits` (laboratorio antiguo). Extensión incremental al Job 15. El ZIP **no** contiene pipelines exportados ni credenciales y no reemplaza archivos existentes.

## Evidencia previa

Job 15 auditó correctamente `filebeat-7.10.2-wazuh-alerts-pipeline`: HTTP OK, 10 procesadores GeoIP directos, uno de `data.srcip` hacia `GeoLocation`, 22 documentos con `GeoLocation.location`; `ok=13, changed=0, failed=0`. La simulación no se ejecutó todavía.

## Qué aporta el Job 16

- Lee la definición **completa y actual** del pipeline por API `GET /_ingest/pipeline/{id}`.
- Comprueba que conserva el procesador `data.srcip` → `GeoLocation`.
- Calcula SHA256 de una representación JSON estable de la definición, sin mostrar contenido ni credenciales.
- Opcionalmente simula la IP `8.8.8.8` mediante `POST .../_simulate`, sin indexar documentos.
- Si se autoriza, guarda **únicamente en el servidor** una copia privada `root:root 0600` dentro de `/var/backups/wazuh-geoip` (`0700`); el nombre lleva la huella SHA256 para no pisar un backup anterior.
- Si encuentra un archivo previo con ese nombre pero contenido distinto o es un enlace, aborta antes de sobrescribirlo.
- No incluye `PUT`, `DELETE`, `docker compose` ni cambios de configuración Wazuh.

**La copia del pipeline no equivale a un backup del Indexer completo.** Podría contener configuraciones internas; no copiarla a Git ni a un chat antes de revisarla y redactar secretos o metadatos sensibles.

## Incorporación al proyecto

Extraer en la raíz de `C:\deployment-kits` y verificar que se añaden exclusivamente:

```
monitorizacion/playbooks/adoptar_geoip_wazuh.yml
monitorizacion/examples/variables_geoip_adopcion.yml
monitorizacion/GEOIP_ADOPCION_AWX.md
tests/test_geoip_adopcion.py
```

No añadir el directorio `.git` de un ZIP antiguo ni respaldos privados. Confirmar `git status --short`, `git diff --cached --stat`; después commit, push y Project Sync en AWX.

Crear Job Template **`16 - Adoptar Wazuh GeoIP`** con:

- Proyecto `deployment-kits`, `monitorizacion/playbooks/adoptar_geoip_wazuh.yml`.
- Inventario con grupo `wazuh-servers` (`ansible_server`), Machine Credential para SSH/sudo y Custom Credential Wazuh con variable de entorno `VAR_WAZUH_ADMIN_PASSWORD`.
- Variable de grupo para ruta de respaldo si hace falta; por defecto `/var/backups/wazuh-geoip`.

## Secuencia

**Paso 1 — Auditoría y simulación, sin escribir archivos:**

```yaml
var_geoip_save_snapshot: false
var_geoip_simulate: true
```

Resultado esperado: `changed=0`, `failed=0`, `Simulacion: OK`, hash SHA256 visible. La simulación podría fallar si el pipeline no transforma este tipo de evento, en cuyo caso no modifica nada y revisaremos el resultado antes de continuar.

**Paso 2 — Adopción con backup privado (una vez validado el Paso 1):**

```yaml
var_geoip_save_snapshot: true
var_geoip_simulate: true
```

Resultado: `changed` normalmente 2 (directorio+archivo) o 0 en ejecuciones repetidas. **No es un cambio en Wazuh**. Confirmar ruta y SHA256, sin copiar el JSON en el log.

**Paso 3 — Repetición:** relanzar con las mismas variables; `changed=0` indica idempotencia. Si la definición remota cambia, se generará un nuevo nombre SHA; no se sobrescribe la versión anterior.

## Qué haremos después

Una vez capturada la definición real, el futuro Job 17 definirá el contrato deseado de manera explícita, comparará contra la instantánea y propondrá diferencias. **No autorizaremos todavía sustituciones del pipeline de Filebeat** porque hay 10 procesadores GeoIP y necesitamos preservar todos los bloques, no solo el de `data.srcip`.

### Seguridad

`validate_certs: false` está restringido a la conexión HTTPS local `127.0.0.1` existente en el laboratorio. Antes de producción, configurar confianza CA y validar certificados; no trasladar esta excepción indiscriminadamente.

No guardar valores de credenciales, JSON completos de pipelines ni logs sensibles en Git, chat o capturas.
