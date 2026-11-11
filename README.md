# Bloque 02 — Wazuh GeoIP AWX v5 · Auditoría de deriva (Job 17)

Se añade un **playbook nuevo** y reutilizable. No modifica los Jobs 15/16 que ya han sido probados; no introduce escrituras en el Indexer.

## Archivos nuevos

- `monitorizacion/playbooks/auditar_deriva_geoip_wazuh.yml`
- `monitorizacion/examples/variables_geoip_deriva.yml`
- `monitorizacion/GEOIP_DERIVA_AWX.md`
- `tests/test_geoip_deriva.py` (pruebas estáticas opcionales)

## Ejecución

1. Extraer en la raíz de `C:\deployment-kits`, conservando las rutas; revisar `git status` y `git diff`.
2. Revisar cuidadosamente la ruta del snapshot en `monitorizacion/examples/variables_geoip_deriva.yml`. El valor es la ruta **esperada por defecto**, no una ruta confirmada por acceso a tu servidor.
3. Hacer commit y push de los archivos del bloque, sincronizar el Project de AWX.
4. Crear Job Template `17 - Auditar deriva GeoIP` con el playbook nuevo, mismo inventario y credenciales del Job 16.
5. Pegar las 3 variables del ejemplo en Extra Variables, ajustando la ruta cuando proceda.
6. Ejecutar y enviar solo `Mostrar resultado de comparacion sin contenidos ni credenciales` y `PLAY RECAP`.

**Seguridad:** lee API y snapshot privado, compara JSON, no crea ni modifica ningún archivo, no ejecuta PUT/POST/DELETE, no cambia OpenSearch/Wazuh. En modo por defecto `var_geoip_fail_on_drift: false` informa sobre deriva sin marcar failed, para revisar manualmente.

**IMPORTANTE:** No subir el snapshot privado de GeoIP al repositorio. Su hash SHA256 del archivo es `f7adde...`, diferente del hash SHA256 de representación `8a24ed...`. Los dos son correctos pero no intercambiables.
