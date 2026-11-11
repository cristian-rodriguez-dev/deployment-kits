# Bloque 02 — Wazuh GeoIP / Job 15

**Entrega incremental para `deployment-kits`, proyecto antiguo.** No contiene comandos de despliegue, actualizaciones ni cambios de configuración en Wazuh.

## Qué contiene

- `monitorizacion/playbooks/auditar_geoip_wazuh.yml`: audita el Indexer, el pipeline y la presencia de `GeoLocation.location`.
- `monitorizacion/examples/variables_geoip_wazuh.yml`: valores opcionales de AWX.
- `monitorizacion/GEOIP_WAZUH_AWX.md`: instrucciones, requisitos, seguridad y siguientes fases.
- `tests/test_geoip_awx_static.py`: comprobaciones estáticas de solo lectura.

## Cómo instalarlo

1. Descomprimir en la **raíz de `C:\deployment-kits`**, conservando rutas; solo se añaden archivos.
2. Revisar `git status --short` y `git diff --stat`; añadir exclusivamente el playbook, las variables de ejemplo, la documentación y los tests.
3. Hacer commit/push y sincronizar el Project en AWX.
4. Crear el Job Template **`15 - Auditar Wazuh GeoIP`** con el playbook `monitorizacion/playbooks/auditar_geoip_wazuh.yml` y el inventario/grupo `wazuh-servers`.
5. Asignar credencial de Máquina y **credencial personalizada Wazuh** (inyector `VAR_WAZUH_ADMIN_PASSWORD`).
6. Lanzarlo primero sin simulación (`var_geoip_simulate: false`).

No necesitas instalar paquetes ni reiniciar el Indexer. No importes el ZIP de backup Grafana a Git.

## Evidencia que necesitamos

Copiar únicamente la tarea **Mostrar resumen de auditoria sin documentos ni credenciales** y el `PLAY RECAP`. Si falla antes, enviar el nombre de la tarea y el mensaje visible (sin credenciales).

**Esperado:** `changed=0`, `failed=0`, pipeline encontrado y procesador `data.srcip` → `GeoLocation` detectado.

La auditoría no verifica todavía que Filebeat aplique el pipeline a todos los eventos reales ni que Grafana muestre todas las alertas públicas. Esos puntos pertenecen a la fase de adopción controlada.
