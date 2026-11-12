# Wazuh Active Response — piloto SSH, automatización AWX y seguridad

**Proyecto antiguo `deployment-kits` · Actualizado el 12/11/2026 · Piloto validado en laboratorio; no validado en producción.**

## Estado real comprobado del piloto (12/11/2026)

- **Agente piloto:** Wazuh `005`, `PC_SISTEMAS_1`; en AWX figura como `cliente_1` (`192.168.56.21`). `wazuh-agent` activo.
- **Manager:** Wazuh 4.14.8 en Docker; se mantiene `location=defined-agent`, `agent_id=005`, `rules_id=5763`, `timeout=180`. No se ha aplicado la migración del rol del Manager.
- **Otros agentes registrados:** `003` (`PC_Sistemas_1`) y `004` (`PC_Marketing_1`) desconectados. No se han preparado ni autorizado para recibir esta respuesta.
- **Detección:** regla `5763` tras eventos SSH fallidos correlacionados (`5760`, frecuencia 8, ventana 120 s).
- **Mitigación:** cadena IPv4 `WAZUH_SSH_BLOCK`, salto desde `INPUT` para TCP/22; excepciones `127.0.0.0/8` y `192.168.56.0/24` antes de cualquier `DROP`.
- **Tiempos declarados:** bloqueo Wazuh de 180 s; respaldo systemd a 240 s. Son valores configurados, no garantía de ejecución exacta bajo cualquier condición.
- **Código instalado y comprobado:** `/var/ossec/active-response/bin/ssh-block-pilot.py`, SHA256 `64f6fa121b45d0b81a9595d8605b1e36bbc635f6c45b45ef41261dd8a56ab332`; JSON válido en `/etc/wazuh-ssh-ar/config.json`; unidad `wazuh-ssh-firewall-init.service` activa y habilitada; `wazuh-agent` activo.
- **Migración del agente con Ansible:** primera ejecución `ok=29 changed=7 failed=0`; segunda ejecución `ok=27 changed=0 failed=0`. Se conservaron backups del script y de la unidad systemd anterior.
- **AWX:** auditoría del host `cliente_1` `ok=11 changed=0 failed=0`; plantilla `Wazuh AR - Despliegue Agente` ejecutada satisfactoriamente y sin cambios tras corregir el cálculo SHA1 del archivo con `lookup('ansible.builtin.file', ..., rstrip=False)`.
- **Workflow de agentes configurado (no probado integralmente):** `06 - Instalar Agentes` → `07 - Configurar Agentes` → **aprobación manual** → `23 - Wazuh AR - Despliegue`. La plantilla 23 conserva `limit=cliente_1`, `var_wazuh_ar_migrate_existing=false` y las autorizaciones explícitas del agente.
- **Comportamiento demostrado:** alerta real de Wazuh `5763` del agente 005 y ejecución del script nuevo (`IGNORED invalid, protected or excluded IP`, ante IP reservada de prueba). Prueba controlada *directa de funciones* con `iptables`, persistencia, token antiguo y borrado correcto: superada. El piloto original también demostró bloqueo/desbloqueo temporizado, pero con el script anterior.
- **Pendiente:** prueba E2E con el **script nuevo** que abarque entrega real de Wazuh `ADD`, decisión `check_keys`, creación de `DROP`, posterior `DELETE` y ejecución del fallback systemd de 240 s. No se debe afirmar que ese ciclo completo esté validado.

## Alcance y origen de los scripts

El ZIP inicial de la automatización no incluía una extracción literal de todos los ficheros de configuración manual del cliente. El código nuevo se preparó y migró posteriormente mediante Ansible y se verificó su SHA256 contra el repositorio.

## Archivos

| Ruta relativa a `monitorizacion/` | Función |
| --- | --- |
| `playbooks/auditar_wazuh_active_response.yml` | Auditoría sin modificaciones de los grupos `monitoring-agents` y `wazuh-servers` |
| `playbooks/configurar_wazuh_active_response_agentes.yml` | Aplicación controlada a agentes Ubuntu, un host cada vez (`serial: 1`) |
| `playbooks/configurar_wazuh_active_response_manager.yml` | Preparar configuración del Manager, sin reiniciar contenedor |
| `roles/wazuh_active_response_agent/` | Scripts Python, configuración JSON, unidad systemd, controles y backups |
| `roles/wazuh_active_response_manager/` | Preparación XML conservadora y copias de seguridad en el host |
| `examples/variables_wazuh_active_response.yml` | Valores de ejemplo para grupos AWX |
| `tests/test_wazuh_active_response.py` | Pruebas simuladas sin tocar firewall ni Wazuh |

**No modifica** los playbooks existentes de Docker, Prometheus, Grafana, Loki, K3s, Suricata o instalación del agente.

## Guía de adopción o ampliación en AWX (no repetir sobre el piloto validado)

1. Descomprimir el paquete sobre la carpeta que contiene `deployment-kits/`. Revisar diferencias antes de guardar en Git.
2. Sincronizar el proyecto en AWX. Crear plantilla **Auditar Wazuh Active Response**, playbook `monitorizacion/playbooks/auditar_wazuh_active_response.yml`, inventario de siempre, credenciales SSH/SUDO de los grupos existentes. Necesita `var_wazuh_ar_manager_config_path` en el host Manager; por defecto usa `var_wazuh_install_dir/single-node/config/wazuh_cluster/wazuh_manager.conf`.
3. En un host nuevo, ejecutar SOLO auditoría. Verificar que `monitoring-agents` no contiene servidores centrales ni máquinas Windows. Para el primer piloto limitar a `PC_SISTEMAS_1`.
4. En grupo/host de **agentes**, ajustar `var_wazuh_ar_protected_networks` para incluir **todas** las redes administrativas; y `var_wazuh_ar_protected_ips` con las IPs públicas de AWX/VPN. Con `var_wazuh_ar_ipv6_enabled: false`, documentar el riesgo y, si se acepta para el laboratorio, activar `var_wazuh_ar_ack_ipv6_gap: true`. En sistemas que usan IPv6, preferir habilitar cobertura IPv6 y probarla aisladamente.
5. Para **migrar el piloto existente**, configurar temporalmente en el host de pruebas: `var_wazuh_ar_agent_apply: true`, `var_wazuh_ar_admin_networks_reviewed: true`, `var_wazuh_ar_migrate_existing: true`. Crear plantilla de `configurar_wazuh_active_response_agentes.yml`, con límite de un host. La primera ejecución guarda backups de los ficheros que sustituya. Ejecutar una segunda vez y exigir ausencia de cambios funcionales. **No reinicia el agente Wazuh**.
6. Auditar los demás agentes y aplicar solo en los aprobados; `var_wazuh_ar_migrate_existing: false` en instalaciones nuevas. No dar por válido el despliegue hasta comprobar los logs y que existe la cadena con protecciones por delante de cualquier `DROP`.
7. **Fase futura, no aplicada al piloto actual: solo cuando todos los agentes que pueden disparar la regla estén preparados**, configurar las variables en `wazuh-servers`: `var_wazuh_ar_manager_apply: true`, `var_wazuh_ar_manager_agents_ready: true` y, para sustituir `location=defined-agent`, `var_wazuh_ar_manager_allow_migration: true`. Ejecutar `configurar_wazuh_active_response_manager.yml` sobre el Manager autorizado. El helper actualiza **solo** los bloques `ssh-block-pilot`, valida que el XML parsea y guarda copia de seguridad de toda la configuración antes de escribir. No reinicia contenedores.
8. En esa eventual fase futura, revisar backup/diferencia del Manager. En ventana aprobada, reiniciar **solo Wazuh Manager** mediante el procedimiento Docker Compose que ya se usa en el entorno. Validar `agent_control`, regla 5763, logs de Active Response, y prueba controlada usando IP de laboratorio bajo nuestro control. **No modificar ni recrear los otros contenedores**.
9. Mantener la auditoría separada del apply; conservar `apply=false` en variables comunes y habilitarlo únicamente en ejecución autorizada.

### Por qué la configuración del Manager se cambia al final

`location=local` envía la respuesta al agente que generó la alerta. Es adecuado para múltiples agentes, pero **puede alcanzar otros agentes que generen la regla 5763 y aún no dispongan del ejecutable**. No habilitar hasta censar esos agentes. La alternativa `defined-agent` sigue operativa en el piloto anterior hasta aplicar y reiniciar el Manager.

## Comportamiento de los scripts

- El nuevo `ssh-block-pilot.py` acepta IPs públicas globales; rechaza IPs privadas, reservadas, loopback y listas protegidas; valida el `rule.id` y la ubicación del evento.
- La respuesta `add` valida el `agent.id` contra el ID local de `/var/ossec/etc/client.keys` sin leer ni registrar la clave compartida; así, mientras el Manager siga usando `defined-agent`, una alerta de otro agente no bloqueará el cliente piloto. Si falta ese archivo o contiene varias identidades, falla de forma conservadora.
- No se incluyen exclusiones públicas de laboratorio en las variables por defecto; cualquier IP administrativa externa debe añadirse tras revisión explícita.

- `add` consulta Wazuh con `check_keys`, y solo acepta `continue`; un `abort` no toca iptables.
- Antes de `DROP`, programa un temporizador systemd con **token único** y guarda el estado root-only bajo `/var/lib/wazuh-ssh-ar`.
- `delete` compara el `alert.id` de Wazuh con el ID del bloqueo en curso. Si no existe o no coincide, no quita una regla nueva; la recuperación independiente usa el token. Esto puede aplazar el desbloqueo a 240 s si la notificación Wazuh `delete` no incluye el mismo ID.
- `--cleanup IP TOKEN` retira la regla **solo** si el token coincide. Un temporizador antiguo no puede desbloquear una generación posterior.
- La cadena se inicializa al arrancar sin restaurar bloqueos temporales anteriores ni modificar las demás reglas. Las reglas `RETURN` de acceso administrativo preceden a las `DROP`.
- Si el firewall o la recuperación fallan, el script registra error; **no se promete eliminación infalible**: sigue siendo necesario alertar ante reglas antiguas, temporizadores fallidos y errores.

## Seguridad y limitaciones

1. **Solo SSH**: la cadena recibe tráfico TCP dirigido al puerto configurado, por defecto 22. No es un firewall general.
2. **IPv6**: desactivado inicialmente. Antes de la migración el SSH del piloto escuchaba en ambas familias; en el estado validado de `PC_SISTEMAS_1`, **sshd escucha solo en IPv4**. No implica desactivar IPv6 globalmente. La automatización admite `ip6tables` al activar `var_wazuh_ar_ipv6_enabled`, pero esa ruta no se ha validado sobre VMs reales. Aceptar explícitamente el hueco IPv6 solo en laboratorio temporal.
3. **UFW/firewalld**: la aplicación falla si alguno está activo para no interferir con otro propietario del firewall. Si se habilita posteriormente, debe revisarse la integración.
4. **Protección de IPs**: revisar redes AWX, VPN, accesos administrativos externos, rangos y exclusiones por host antes de aplicar. No confiar solo en `192.168.56.0/24` fuera del laboratorio.
5. **Sin reinstalaciones**: el rol requiere que Wazuh Agent ya exista; nunca instala, actualiza ni reconfigura Node Exporter o Wazuh Agent.
6. **Sin borrados masivos**: no usa `iptables -F`, `-X`, `iptables-save`, `prune`, `compose down`, ni `systemctl restart wazuh-agent`.
7. **Cadena compartida**: no adoptar instalaciones con `DROP` activo; se exige retirar o investigar los bloqueos antes de migrar para no dejar reglas huérfanas.
8. **Estado al reiniciar**: se reconstruye la cadena pero no se restauran bloqueos temporales anteriores. La permanencia del estado en disco no implica que las reglas sigan activas.
9. **Compatibilidad**: preparado para agentes Ubuntu con `python3`, `systemd`, `iptables` (nf_tables o legacy). Probado en el laboratorio sobre el agente 005 y ejecutado desde AWX; **no validado en producción**.
10. **Alertas artificiales**: NO permitir rangos de documentación como `203.0.113.0/24` en despliegue normal. No usar `logger` sintético sobre IPs reales externas.

## Plantilla AWX actual y protección contra cambios involuntarios

La plantilla `23 - Wazuh AR - Despliegue` usa `monitorizacion/playbooks/configurar_wazuh_active_response_agentes.yml`, el inventario existente y **limit `cliente_1`**. Variables validadas para el piloto:

```yaml
var_wazuh_ar_agent_apply: true
var_wazuh_ar_migrate_existing: false
var_wazuh_ar_admin_networks_reviewed: true
var_wazuh_ar_ipv6_enabled: false
var_wazuh_ar_ack_ipv6_gap: true
```

- `var_wazuh_ar_migrate_existing: false` es obligatorio en ejecución ordinaria: una versión distinta debe detenerse para revisión antes de sustituir el script.
- En el caso ya resuelto, el fallo de integridad era un **falso positivo**: `lookup('file')` recortaba el salto de línea final. Se corrigió con `lookup('ansible.builtin.file', role_path ~ '/files/ssh-block-pilot.py', rstrip=False) | hash('sha1')`. No cambiar a `migrate_existing=true` para evitar esa validación.
- El workflow incluye una aprobación manual y la rama de éxito desde el paso 07 al nodo de aprobación y de este al paso 23. La plantilla ya se ejecutó individualmente, pero el workflow completo no se ha ejecutado tras añadir el nodo.
- Al dar de alta nuevos agentes, el paso 23 **no los cubre** mientras conserve `limit=cliente_1`. Revisar identidad Wazuh, IP administrativa y autorizaciones antes de ampliar la lista. No convertir el Manager a `location=local` de forma automática.
- No guardar credenciales, claves de `client.keys`, IPs externas personales o tokens de ejecución en Git.

## Criterio de cierre y prueba E2E pendiente

**Cerrado:** despliegue del agente, protección de accesos administrativos, instalación systemd, rechazo de IP reservada, prueba directa de token/iptables, idempotencia Ansible, auditoría y plantilla de despliegue desde AWX, conexión al workflow con aprobación.

**Pendiente y separado del despliegue:** prueba completa a nivel Wazuh del nuevo script, usando una IP de origen que pertenezca al laboratorio y sea admisible según la política, en entorno aislado con acceso de consola. Registrar el `ADD`, `check_keys`, `BLOCKED`, estado/timer y `DELETE` o recuperación `systemd`; demostrar ausencia posterior de `DROP` y estado. No introducir excepciones permanentes para redes reservadas ni hacer pruebas contra IPs externas ajenas. Hasta ejecutarla, el **ciclo E2E nuevo no está certificado**.

## Diagnóstico en un agente

```bash
sudo systemctl status wazuh-ssh-firewall-init.service --no-pager
sudo iptables -S INPUT
sudo iptables -S WAZUH_SSH_BLOCK
sudo tail -n 40 /var/ossec/logs/ssh-block-pilot.log
sudo systemctl list-timers --all --no-pager | grep wazuh-ssh-recovery || true
sudo systemctl is-active wazuh-agent
```

Para IPv6 habilitado, consultar también `sudo ip6tables -S WAZUH_SSH_BLOCK`.

## Restauración y rollback

**Agente**: los módulos Ansible `copy` y `template` usan `backup: true` si sobrescriben un archivo. Anotar en el output de AWX la ruta `backup_file` de cada archivo que cambie (el rol muestra la copia del script principal). Guardar también copia previa del servicio, inicializador y configuración JSON antes de la primera migración. Para volver al piloto anterior, restaurar sus archivos desde esas copias **con ventana de mantenimiento y consola de recuperación**, revalidar sintaxis, configuración SSH, estado del firewall y reiniciar únicamente la unidad `wazuh-ssh-firewall-init.service` si es necesario. No vaciar reglas `DROP` ajenas ni reemplazar automáticamente `ossec.conf` del agente.

**Manager**: la herramienta del host `/usr/local/sbin/wazuh-ar-manager-config.py` guarda versiones originales en `.wazuh-active-response-backups` junto a `wazuh_manager.conf`. Restaurar una versión verificada con:

```bash
sudo python3 /usr/local/sbin/wazuh-ar-manager-config.py \
  --file /RUTA/REAL/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf \
  --mode rollback --backup /RUTA/REAL/wazuh-docker/single-node/config/wazuh_cluster/.wazuh-active-response-backups/NOMBRE.bak \
  --confirm-agents-ready
```

El rollback hace a su vez copia de la versión anterior. El Manager necesita un reinicio manual controlado para cargar el cambio. **No ejecutar el comando con rutas de ejemplo**; comprobar cada ruta con `ls -l`.

## Pruebas locales sin desplegar

Desde `deployment-kits` en Windows/Linux con Python + PyYAML + pytest:

```bash
python -m pytest -q tests/test_wazuh_active_response.py
```

Las pruebas unitarias simulan `iptables`, `ip6tables`, systemd-run y mensajes Wazuh. Verifican protección de IPs, `check_keys`, `abort`, bloqueo, borrado, temporizador obsoleto, interrupciones de recuperación, idempotencia del inicializador y edición conservadora del Manager. **No sustituyen** la prueba E2E real de `ADD → DELETE` del nuevo script. Los tests `tests/test_contract.py` existentes tienen cinco errores previos por YAML de ejemplo vacío; no se han corregido como parte de este bloque.

## Fuentes técnicas

- Wazuh: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- Wazuh: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html
- Wazuh Docker: https://documentation.wazuh.com/current/deployment-options/docker/container-usage.html
- Ansible roles: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/include_role_module.html
