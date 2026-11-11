# Wazuh Active Response — piloto SSH, automatización AWX y seguridad

**Proyecto antiguo `deployment-kits` · 10/11/2026 · Implementación preparada, NO desplegada por este paquete.**

## Alcance y estado conocido

- Piloto manual comprobado en `PC_SISTEMAS_1` (agente 005), Wazuh 4.14.8.
- Regla 5763: ocho eventos `5760` desde una IP en 120 s.
- Respuesta automática IPv4 `iptables` `DROP` en TCP/22, reversible por Wazuh tras ~180 s.
- Salvaguarda systemd a 240 s. En el piloto se comprobó que Wazuh desbloqueó primero y systemd no necesitó actuar.
- Cadena `WAZUH_SSH_BLOCK` y arranque persistente validados tras reiniciar una VM.
- **Esta entrega incluye código nuevo** con estado por generación. No se ha reemplazado el código del piloto en las máquinas.
- El ZIP original no incluía los tres ficheros de configuración manual del cliente. El código nuevo se ha construido a partir del script y del servicio compartidos en la conversación: **no es una copia byte a byte del sistema en vivo**.

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

## Orden recomendado en AWX (no ejecutar a ciegas)

1. Descomprimir el paquete sobre la carpeta que contiene `deployment-kits/`. Revisar diferencias antes de guardar en Git.
2. Sincronizar el proyecto en AWX. Crear plantilla **Auditar Wazuh Active Response**, playbook `monitorizacion/playbooks/auditar_wazuh_active_response.yml`, inventario de siempre, credenciales SSH/SUDO de los grupos existentes. Necesita `var_wazuh_ar_manager_config_path` en el host Manager; por defecto usa `var_wazuh_install_dir/single-node/config/wazuh_cluster/wazuh_manager.conf`.
3. Ejecutar SOLO auditoría. Verificar que `monitoring-agents` no contiene servidores centrales ni máquinas Windows. Para el primer piloto limitar a `PC_SISTEMAS_1`.
4. En grupo/host de **agentes**, ajustar `var_wazuh_ar_protected_networks` para incluir **todas** las redes administrativas; y `var_wazuh_ar_protected_ips` con las IPs públicas de AWX/VPN. Con `var_wazuh_ar_ipv6_enabled: false`, documentar el riesgo y, si se acepta para el laboratorio, activar `var_wazuh_ar_ack_ipv6_gap: true`. En sistemas que usan IPv6, preferir habilitar cobertura IPv6 y probarla aisladamente.
5. Para **migrar el piloto existente**, configurar temporalmente en el host de pruebas: `var_wazuh_ar_agent_apply: true`, `var_wazuh_ar_admin_networks_reviewed: true`, `var_wazuh_ar_migrate_existing: true`. Crear plantilla de `configurar_wazuh_active_response_agentes.yml`, con límite de un host. La primera ejecución guarda backups de los ficheros que sustituya. Ejecutar una segunda vez y exigir ausencia de cambios funcionales. **No reinicia el agente Wazuh**.
6. Auditar los demás agentes y aplicar solo en los aprobados; `var_wazuh_ar_migrate_existing: false` en instalaciones nuevas. No dar por válido el despliegue hasta comprobar los logs y que existe la cadena con protecciones por delante de cualquier `DROP`.
7. **Solo cuando todos los agentes que pueden disparar la regla están preparados**, configurar las variables en `wazuh-servers`: `var_wazuh_ar_manager_apply: true`, `var_wazuh_ar_manager_agents_ready: true` y, para sustituir `location=defined-agent`, `var_wazuh_ar_manager_allow_migration: true`. Ejecutar `configurar_wazuh_active_response_manager.yml` sobre el Manager autorizado. El helper actualiza **solo** los bloques `ssh-block-pilot`, valida que el XML parsea y guarda copia de seguridad de toda la configuración antes de escribir. No reinicia contenedores.
8. Revisar backup/diferencia del Manager. En ventana aprobada, reiniciar **solo Wazuh Manager** mediante el procedimiento Docker Compose que ya se usa en el entorno. Validar `agent_control`, regla 5763, logs de Active Response, y prueba controlada usando IP de laboratorio bajo nuestro control. **No modificar ni recrear los otros contenedores**.
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
2. **IPv6**: desactivado inicialmente. El piloto SSH escuchaba tanto IPv4 como IPv6. La automatización admite `ip6tables` al activar `var_wazuh_ar_ipv6_enabled`, pero esa ruta no se ha validado sobre VMs reales. Aceptar explícitamente el hueco IPv6 solo en laboratorio temporal.
3. **UFW/firewalld**: la aplicación falla si alguno está activo para no interferir con otro propietario del firewall. Si se habilita posteriormente, debe revisarse la integración.
4. **Protección de IPs**: revisar redes AWX, VPN, accesos administrativos externos, rangos y exclusiones por host antes de aplicar. No confiar solo en `192.168.56.0/24` fuera del laboratorio.
5. **Sin reinstalaciones**: el rol requiere que Wazuh Agent ya exista; nunca instala, actualiza ni reconfigura Node Exporter o Wazuh Agent.
6. **Sin borrados masivos**: no usa `iptables -F`, `-X`, `iptables-save`, `prune`, `compose down`, ni `systemctl restart wazuh-agent`.
7. **Cadena compartida**: no adoptar instalaciones con `DROP` activo; se exige retirar o investigar los bloqueos antes de migrar para no dejar reglas huérfanas.
8. **Estado al reiniciar**: se reconstruye la cadena pero no se restauran bloqueos temporales anteriores. La permanencia del estado en disco no implica que las reglas sigan activas.
9. **Compatibilidad**: preparado para agentes Ubuntu con `python3`, `systemd`, `iptables` (nf_tables o legacy). No está validado en producción ni ejecutado contra el AWX del usuario.
10. **Alertas artificiales**: NO permitir rangos de documentación como `203.0.113.0/24` en despliegue normal. No usar `logger` sintético sobre IPs reales externas.

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

Las pruebas simulan `iptables`, `ip6tables`, systemd-run y mensajes Wazuh. Verifican protección de IPs, `check_keys`, `abort`, bloqueo, borrado, temporizador obsoleto, interrupciones de recuperación, idempotencia del inicializador y edición conservadora del Manager. **No sustituyen** `ansible-playbook --syntax-check`, auditoría en AWX ni E2E real. Los tests `tests/test_contract.py` existentes tienen cinco errores previos por YAML de ejemplo vacío; no se han corregido como parte de este bloque.

## Fuentes técnicas

- Wazuh: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- Wazuh: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html
- Wazuh Docker: https://documentation.wazuh.com/current/deployment-options/docker/container-usage.html
- Ansible roles: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/include_role_module.html
