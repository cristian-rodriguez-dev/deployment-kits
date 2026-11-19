# Piloto SSH Active Response original · 24.04 → 26.04

Esta carpeta conserva íntegros los dos scripts Python recibidos del agente Wazuh de Ubuntu 24.04 y su unidad systemd. `config.original.sanitized.json` es el fichero de referencia saneado, **no** un secreto ni un fichero que se despliegue literalmente.

Confirmado en el origen:

- Regla `5763`, agente autorizado `005` mediante `defined-agent`, puerto SSH `22` y timeout del manager `180` segundos.
- `WAZUH_SSH_BLOCK` protegía `127.0.0.0/8` y `192.168.56.0/24`, y estaba enganchada a `INPUT` solo para SSH.
- Configuración local: `block_seconds=180`, `recovery_seconds=240`, IPv6 desactivado, exclusión del log `geoip-lab.log`.
- Script en `/var/ossec/active-response/bin/ssh-block-pilot.py`, inicializador en `/usr/local/sbin/wazuh-ssh-firewall-init.py`, servicio `wazuh-ssh-firewall-init.service`.

## Preparación en Ubuntu 26.04

El Job **17**, fuera del workflow central, es **solo para clientes remotos** del grupo AWX `monitoring-agents`. Exige autorización de instalación, un único nombre lógico de host y el ID local de agente confirmado. No se ejecuta sobre el servidor central, no instala agentes, no activa iptables, no arranca ni habilita la unidad systemd y no edita `ossec.conf` del manager. No copiar `005` a otro cliente: el nuevo ID se consulta en Wazuh después del registro.

Ejemplo de variables para el Job 17 (ajustar a los valores reales del cliente y del entorno):

```yaml
var_wazuh_ssh_pilot_install_authorized: true
var_wazuh_ssh_pilot_target_host: HOST_AGENTE_REAL
var_wazuh_ssh_pilot_agent_id: 'ID_REAL'
var_wazuh_ssh_pilot_admin_cidr: RED_ADMINISTRATIVA_REAL
```

`var_wazuh_ssh_pilot_admin_cidr` permite añadir a las protecciones originales la red administrativa del nuevo despliegue. Si aún no se conoce, puede omitirse en esta **fase de preparación** (sin modificar cortafuegos), pero debe comprobarse antes de cualquier activación futura. Opcionalmente: `var_wazuh_ssh_pilot_protected_networks`, `var_wazuh_ssh_pilot_protected_ips`, `var_wazuh_ssh_pilot_ssh_port`. Las redes originales se conservan por defecto. No incluir datos de empresa, redes privadas identificativas o secretos en Git; usar inventario y variables de AWX.

En AWX, la importación del workflow principal **no crea automáticamente esta plantilla opcional**. Si se autoriza la preparación de un cliente, crea un Job Template independiente llamado `26.04 - 17 Preparar piloto SSH remoto (manual)` con el playbook `ubuntu-26.04/playbooks/17_preparar_piloto_ssh.yml`, el inventario existente, la credencial SSH y el proyecto `deployment-kits`. Activa «Prompt on launch» para las variables de aprobación y destino, o asígnalas únicamente a la plantilla aprobada (sin claves). No conectarlo al workflow central.

Tras el Job 17, verificar mediante `ls -l` los archivos copiados, `systemctl is-enabled wazuh-ssh-firewall-init.service` (se espera `disabled`/`static`, si antes no existía) y que `iptables -S INPUT` **no haya cambiado**. El Job no hace pruebas de bloqueo reales. Los scripts originales **no implementan un interruptor general de `dry-run`**: las pruebas del paquete se ejecutan con funciones de firewall y temporizador simuladas en memoria.

Para activar el piloto en una fase posterior, hace falta revisar antes el fragmento real de `ossec.conf` del manager, identificar el nuevo agente, confirmar la red desde donde se administra SSH y aprobar explícitamente las modificaciones de firewall y el reinicio necesario. Nunca conectar el piloto a todos los agentes ni activar reglas sobre IPs reales como prueba automática. Si se decide no seguir, el Job 17 deja solo archivos inertes, sin cambiar las reglas de iptables existentes.

**Incidencia pendiente:** en el último diagnóstico el servicio local `wazuh-agent` aparecía activo, pero el manager mostraba el agente `005` desconectado. Un servicio activo local no confirma la conectividad con el manager.
