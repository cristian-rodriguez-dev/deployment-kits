# Adopción segura de Traefik → Alloy → Loki → Wazuh desde Ansible/AWX

**Alcance:** instalación de laboratorio ya existente en `ansible_server` (Ubuntu). Validación manual previa: Traefik 3.7.13 → Alloy → Loki; `traefik-wazuh-bridge.service` activo, SQLite/JSONL persistentes; Wazuh Manager (`-p wazuh`) recibe el JSONL de solo lectura y generó una alerta real `100601` (nivel 7). No se han validado E2E las correlaciones `100603`/`100605`. No hay Active Response web; se mantiene el piloto SSH del agente `005`.

## Archivos nuevos

- `monitorizacion/roles/traefik_loki_wazuh/`: auditoría y adopción controlada; no despliega Manager ni borra datos.
- `monitorizacion/playbooks/auditar_traefik_loki_wazuh.yml`: lectura de estado, `changed=0`.
- `monitorizacion/playbooks/adoptar_traefik_loki_wazuh.yml`: adopción con permiso explícito, idempotente cuando no hay deriva.
- `tests/test_traefik_wazuh_ansible.py`: comprobaciones offline de salvaguardas y estructura.
- Los originales administrados siguen en `monitorizacion/integrations/traefik_wazuh_bridge/` y `monitorizacion/manifests/`; no se duplica `bridge.py` en el rol.

## Política de seguridad

1. Por defecto `var_tlw_mode: audit`, sin escrituras. El playbook de adopción exige además `var_tlw_apply: true`.
2. El rol acepta únicamente hosts autorizados (`ansible_server` por defecto). La selección es deliberadamente estrecha; nunca ejecutar contra `all`.
3. Se comprueba **el proyecto Docker `wazuh`**, su correspondencia con los tres volúmenes originales y la presencia de un bind mount `/var/ossec/traefik-bridge` en solo lectura. **No ejecuta `docker compose up/down` ni recrea el Manager.**
4. El rol verifica que el archivo del Manager contenga un `localfile` JSON exactamente para el destino activo, que esa configuración haya sido cargada, que el contenedor pueda leer el JSONL y que las reglas activas coincidan con Git. Los archivos originales pueden incluir dos bloques `<ossec_config>`.
5. No modifica SQLite, su cursor ni el contenido de JSONL. En modo adopción solo corrige permisos/propietarios de archivos existentes. Si falta una ruta o es enlace simbólico, se detiene.
6. No actualiza el script ni la unidad systemd si difieren de Git sin `var_tlw_allow_bridge_file_update: true` **y** `var_tlw_allow_service_restart: true`. Antes de ello, revisar el diff; las copias usan `backup: true`.
7. La URL del servicio `loki` se resuelve mediante `k3s kubectl` (ClusterIP), **no se almacena una IP fija en Git**. Un cambio de URL solo se aplica con `var_tlw_allow_loki_url_update: true` y `var_tlw_allow_service_restart: true`, conservando las demás claves del JSON y creando backup. Para producción, evaluar DNS estable desde el host y TLS.
8. El `HelmChartConfig` se compara semánticamente con el manifiesto versionado. Solo se escribe si difiere **y** se autoriza `var_tlw_allow_traefik_update: true` y `var_tlw_ack_traefik_rollout: true`; puede recrear el pod Traefik.
9. No hay código para borrar recursos duplicados del proyecto `single-node`, gestionar Compose/Manager o modificar reglas Wazuh: requieren una operación separada y explícita. Nunca usar `prune`, `down -v` ni editar `/var/lib/docker/volumes/*/_data`.
10. Los archivos sensibles y la salida completa de Docker inspect/Compose se ocultan en las tareas de auditoría, evitando publicar contraseñas en AWX. No introducir secretos en Extra Variables.

## Pruebas offline (Windows PowerShell)

```powershell
cd C:\deployment-kits
uv run --python 3.13 --no-project python -m unittest discover -s tests -p "test_traefik_wazuh_ansible.py" -v
uv run --python 3.13 --no-project python -m unittest discover -s tests -p "test_traefik_wazuh_bridge.py" -v
```

**Antes de ejecutar en AWX:** publicar el bloque versionado en Git, sincronizar el proyecto AWX y confirmar la credencial con `become` para `ansible_server`. No publicar `config.json`, certificados, logs, `state.sqlite` ni inventarios temporales.

## Plantillas AWX

| Campo | Plantilla A — auditoría | Plantilla B — adopción |
| --- | --- | --- |
| Nombre sugerido | `Traefik-Wazuh - Auditoria` | `Traefik-Wazuh - Adopcion segura` |
| Playbook | `monitorizacion/playbooks/auditar_traefik_loki_wazuh.yml` | `monitorizacion/playbooks/adoptar_traefik_loki_wazuh.yml` |
| Inventario | Inventario con `ansible_server` | El mismo |
| Limit | `ansible_server` | `ansible_server` |
| Credencial | SSH + become | SSH + become |
| Extra Variables | Ninguna | `var_tlw_apply: true` |
| Ejecución esperada | `changed=0` | `changed=0` en el laboratorio adoptado sin deriva |

**No añadir automáticamente al workflow principal** la plantilla de adopción. Si se integra, colocar una aprobación manual delante y conservar el límite de host. En entornos con más de un servidor, revisar `var_tlw_authorized_hosts` e inventario antes de ampliar alcance.

### Comandos desde consola Ubuntu, si se requiere validación aislada

```bash
cd /ruta/al/repositorio/deployment-kits/monitorizacion
ansible-playbook -i INVENTARIO playbooks/auditar_traefik_loki_wazuh.yml --limit ansible_server --ask-become-pass
ansible-playbook -i INVENTARIO playbooks/adoptar_traefik_loki_wazuh.yml --limit ansible_server --ask-become-pass -e 'var_tlw_apply=true'
```

Ambos playbooks usan `include_role`; cualquier fallo ante ausencia o discrepancia bloquea la adopción sin tocar Wazuh. **Los cambios de archivo aprobados no deben autorizarse en la plantilla estándar**: crear una ventana de mantenimiento independiente, evaluar diferencias y actualizar la documentación de seguridad, red y almacenamiento antes del commit.

## Operación y pendientes

- **Monitorización:** `systemctl status traefik-wazuh-bridge`, `journalctl -u traefik-wazuh-bridge`, estado Loki/Alloy y tamaño del JSONL. El límite de 50 MiB detiene la ingesta; no truncar ni rotar sin plan de conservación de cursor y líneas.
- **Loki:** ventana de retraso y deduplicación ofrecen al menos una vez; no prometer entrega exactamente una vez. Los tres `401` recientes de la prueba controlada aparecieron en Traefik; las correlaciones Wazuh por frecuencia necesitan verificación separada.
- **Reglas:** 100600–100605 se mantienen en el Manager existente; la prueba 100601 procede de un evento sintético escrito en el JSONL (alerta real, no prueba de tráfico hostil de extremo a extremo).
- **Rollback de una actualización autorizada del puente:** conservar backup de script, unidad y config; restaurar solo los archivos que se cambiaron; `systemctl daemon-reload` y reiniciar el puente tras aprobación. No borrar SQLite/JSONL.
- **Traefik:** si se modifica HelmChartConfig, usar copia de seguridad y revisión del rollout. Verificar el manifiesto controlado por K3s antes de restaurar; no reinstalar el chart por defecto.
- **Manager:** si alguna vez se modifica su Compose, exigir proyecto explícito `-p wazuh`, los tres archivos Compose, ventana de mantenimiento y backup privado; no hacerlo desde este rol de adopción.
- **Documentación previa al commit:** revisar `monitorizacion/docs/TRAEFIK_LOKI_WAZUH.md`, README/guías AWX y cualquier ADR/contrato del repositorio sobre red, seguridad, almacenamiento, mantenimiento y rollback. El commit debe abarcar la documentación afectada junto con el rol.
