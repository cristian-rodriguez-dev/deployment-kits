# Bloque 02 · Wazuh GeoIP AWX — v4 (corrección de la verificación del snapshot)

**Objetivo:** reparar exclusivamente la verificación del respaldo del Job 16. No modificar el Indexer, sus pipelines ni el resto de playbooks.

## Problema corregido

El Job 16 con `var_geoip_save_snapshot: true` falló al comparar la huella de la representación JSON en memoria con la del archivo escrito por `ansible.builtin.copy(content=...)`. El fichero podía ser JSON equivalente aunque la serialización de bytes no coincidiera. **No se considera validado hasta leerlo de vuelta y comprobarlo.**

Esta revisión no asume que la diferencia sea inocua. Ahora:

1. Comprueba que el destino, si existe, es un fichero regular privado (`root:root`, modo `0600`, límite 512 KiB), nunca un enlace simbólico.
2. Conserva el archivo anterior; `force: false` y sin operaciones destructivas.
3. Lee el fichero real con `ansible.builtin.slurp` (con `no_log`).
4. Lo interpreta como JSON y exige equivalencia de toda la definición con la recibida del Indexer, no solo de la regla `data.srcip`.
5. Calcula un SHA256 SHA-256 **de los bytes reales del archivo** mediante `stat` y muestra ese valor y el identificador/hash lógico de la representación por separado.
6. Rechaza un JSON alterado, inválido o de otra definición. No oculta un desacuerdo de contenido bajo el argumento de que puede haber espacios distintos.

Si la lectura `from_json` falla por JSON inválido, la tarea fallará sin mostrar el contenido sensible y sin modificar el archivo.

## Uso

Extrae el paquete en la raíz de `C:\deployment-kits`, revisa `git diff`, haz commit/push y sincroniza el Project de AWX.

En el Job Template 16 utiliza:

```yaml
var_geoip_save_snapshot: true
var_geoip_simulate: true
```

### Resultados esperados

- `JSON del respaldo: IDENTICO al pipeline del Indexer`.
- Dos huellas SHA256 (representación y bytes reales). Pueden coincidir o no; no equipararlas.
- `failed=0`, con `changed=0` si el archivo ya existe y es válido.
- Wazuh sin cambios: el único archivo es el snapshot privado `/var/backups/wazuh-geoip/...`.

**Si la comparación estructural falla, no borres ni reescribas el fichero**: necesitaremos comprobar el resultado sin mostrar JSON ni credenciales.

No envíes el snapshot ni credenciales al chat o a Git. El respaldo no sustituye a copias externas ni incluye el resto de datos del Indexer.
