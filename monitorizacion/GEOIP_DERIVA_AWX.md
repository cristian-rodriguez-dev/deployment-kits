# GeoIP — auditoria de deriva (AWX, Job 17)

## Propósito

Detectar diferencias entre el pipeline GeoIP de Wazuh Indexer y el snapshot privado validado en el Job 16. **No escribe en OpenSearch, no cambia reglas, no reinicia servicios y no toca archivos del servidor.** Es un control de lectura reutilizable, no un instalador.

## Prerrequisitos

- Job 16 terminado con `JSON del respaldo: IDENTICO al pipeline del Indexer`.
- Snapshot remoto privado `root:root` modo `0600`, por defecto bajo `/var/backups/wazuh-geoip/`.
- Conocer el SHA256 **de los bytes en disco**, mostrado por el Job 16: `f7addeaade50b77ed2d13f9ca953cb5ce2f379ce1fc226c91dd666c42dfa3e8c` para la ejecución validada el 11-11-2026.
- Inventario con grupo `wazuh-servers`; SSH y sudo funcionando.
- Credencial personalizada de AWX que inyecta `VAR_WAZUH_ADMIN_PASSWORD`.

## Plantilla AWX

- Nombre: `17 - Auditar deriva GeoIP`.
- Playbook: `monitorizacion/playbooks/auditar_deriva_geoip_wazuh.yml`.
- Inventario y credenciales: los mismos que Job 16.
- Extra Variables: ver `monitorizacion/examples/variables_geoip_deriva.yml`. **Verifica la ruta real del snapshot**, puede variar si se configuró otro directorio.

```
var_geoip_reference_file: '/var/backups/wazuh-geoip/filebeat-7.10.2-wazuh-alerts-pipeline-8a24edf01dabfd0.json'
var_geoip_reference_sha256: 'f7addeaade50b77ed2d13f9ca953cb5ce2f379ce1fc226c91dd666c42dfa3e8c'
var_geoip_fail_on_drift: false
```

## Resultado

- `SIN CAMBIOS`: JSON estructuralmente idéntico al snapshot verificado.
- `DERIVA DETECTADA`: diferencias entre definiciones; con `var_geoip_fail_on_drift: false` deja el job en verde, pero imprime la diferencia. Para un job de vigilancia programada puede activarse `true` para que la ejecución falle ante deriva.
- Respaldo ausente, inseguro o con checksum alterado: falla antes de comparar.

No imprime configuraciones completas, documentos de alertas ni credenciales. No utiliza `diff` y los valores sensibles se procesan con `no_log`.

## Limitaciones y siguiente fase

Este Job 17 verifica **la copia ya creada en el mismo servidor**. No constituye por sí solo GitOps ni un backup fuera de host: si el servidor se pierde, también se pierde la referencia. La futura gestión declarativa requiere exportar una definición revisada sin secretos a un origen versionado seguro, definir política de cambios, backup externo y pruebas de restauración. **No automatizar PUT ni reescribir diez procesadores hasta completar esos pasos.**

Para el repositorio antiguo, conservar solamente el playbook reusable, la guía y el ejemplo de variables. No incorporar snapshots reales ni artefactos temporales.
