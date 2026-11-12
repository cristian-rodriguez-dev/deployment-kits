# Despliegue de agentes remotos con AWX

Guía para instalar Wazuh Agent y Node Exporter en equipos Ubuntu e incorporarlos al Prometheus central mediante AWX.

## Índice

1. [Archivos del repositorio](#1-archivos-del-repositorio)
2. [Requisitos](#2-requisitos)
3. [Proyecto y entorno de ejecución de AWX](#3-proyecto-y-entorno-de-ejecución-de-awx)
4. [Inventario y grupos](#4-inventario-y-grupos)
5. [Variables](#5-variables)
6. [Credenciales de AWX](#6-credenciales-de-awx)
7. [Crear las plantillas de trabajo](#7-crear-las-plantillas-de-trabajo)
8. [Crear el WorkFlow](#8-crear-el-workflow)
9. [Primera prueba](#9-primera-prueba)
10. [Añadir otro equipo después](#10-añadir-otro-equipo-después)
11. [Cambiar o retirar equipos](#11-cambiar-o-retirar-equipos)
12. [Diagnóstico](#12-diagnóstico)
13. [Permisos de operadores](#13-permisos-de-operadores)
14. [Referencias](#14-referencias)

## 1. Archivos del repositorio

| Ruta desde la raíz de Git | Función |
| --- | --- |
| `monitorizacion/playbooks/instalar_agentes_monitorizacion.yml` | Instalar ambos agentes en `monitoring-agents`. |
| `monitorizacion/playbooks/configurar_agentes_prometheus.yml` | Actualizar targets en `prometheus-servers`. |
| `monitorizacion/templates/prometheus/prometheus.yml.j2` | Plantilla común del instalador central y del configurador de agentes. |

El Compose de Prometheus debe montar el directorio de configuración, como en la instalación preparada:

```yaml
volumes:
  - "{{ var_prometheus_install_dir }}/prometheus:/etc/prometheus:ro"
  - "{{ var_prometheus_install_dir }}/data:/prometheus"
```

## 2. Requisitos

### Equipos remotos

- Ubuntu.
- Python 3.
- Servicio SSH.
- Usuario de automatización con permisos sudo.
- Ningún otro proceso ocupando el puerto elegido para Node Exporter.

### Conectividad

| Origen | Destino | Puerto habitual | Uso |
| --- | --- | --- | --- |
| Entorno de ejecución AWX | Agentes Ubuntu | TCP 22 | Instalación por SSH. |
| Entorno de ejecución AWX | Servidor central | TCP 22 | Actualizar Prometheus. |
| Agentes | Wazuh Manager | TCP 1514 | Comunicación del agente. |
| Agentes | Wazuh Manager | TCP 1515 | Inscripción inicial. |
| Prometheus central | Agentes | TCP 9100 | Lectura de métricas. |

## 3. Proyecto y entorno de ejecución de AWX

Seguir usando el Nombre_Organización que elegiste para la instalación del despliegue.

En **Proyectos** -> **Nombre_Proyecto**, comprobar la URL, rama y última sincronización del repositorio.

Las rutas de playbook se expresan desde la raíz de Git, usando `/`.

## 4. Inventario y grupos

Utilizar el mismo inventario para ambas plantillas. Debe incluir estos grupos exactos:

| Grupo | Miembros |
| --- | --- |
| `prometheus-servers` | Servidor central Prometheus. |
| `monitoring-agents` | Únicamente los Ubuntu remotos. |

Los nombres deben coincidir con `hosts:` en los playbooks.

En **Inventarios → Nombre_Inventario → Grupos** -> **Añadir** -> **Crear**: `monitoring-agents` si no existe. Después asociar los hosts remotos.

## 5. Variables

### Grupo `monitoring-agents`

En **Inventarios → Nombre_Inventario → Grupos → monitoring-agents → Variables**:

```yaml
---
# Dirección del manager accesible desde los agentes.
var_wazuh_manager_ip: "10.10.3.100"

# Versión exacta del paquete: ejemplo para manager 4.14.8.
# Comprobar disponibilidad en el repositorio y versión real del manager.
var_wazuh_agent_version: "4.14.8-1"

# Puerto real que configurará el instalador de Node Exporter.
var_node_exporter_port: 9100

# Departamento heredado cuando un host no define uno propio.
var_prometheus_department: "Sin-departamento"
```

La versión del agente no debe ser posterior a la del manager. El playbook fija la versión solicitada y deja el paquete en `hold` para evitar actualizaciones automáticas.

### Cada host remoto

Ejemplo:

En **Inventarios → Nombre_Inventario → Servidores → Añadir**:  Crear `ubuntu-contabilidad-01`. En sus variables copiar esto:

```yaml
---
# Sustituir por la IP real de un Ubuntu remoto.
ansible_host: "10.10.200.180"

# Nombre único para la inscripción inicial en Wazuh.
var_wazuh_agent_name: "ubuntu-contabilidad-01"

# Nombre utilizado en la etiqueta nodename de Prometheus.
var_prometheus_agent_name: "Contabilidad-01"

# Agrupación de los targets.
var_prometheus_department: "Contabilidad"

# Opcional: sobrescribir el puerto heredado.
# var_node_exporter_port: Número_Puerto

# Opcional: dirección diferente para que Prometheus acceda al equipo.
# var_prometheus_target_address: "equipo01.ejemplo.local"
```

Asociar el host a `monitoring-agents`.

Cambiar el nombre de un agente Wazuh ya inscrito no modifica automáticamente su registro. **El nombre de instalación debe elegirse antes del primer despliegue**.

### Grupo `prometheus-servers`

Conservar las variables actuales del servidor. El configurador necesita:

```yaml
# Conservar los valores reales de la instalación existente:
# var_prometheus_install_dir (Ruta absoluta de instalación)
# var_prometheus_project_name 
# var_prometheus_image
# var_prometheus_port (Puerto para el panel de control Prometheus)
# var_prometheus_scrape_interval (Tiempo entre consultas)
# var_prometheus_local_name
# var_node_exporter_port (Puerto usado para Node Exporter)

# Si todos los remotos se gestionan desde monitoring-agents:
var_prometheus_departamentos: []
```

**No copiar ese bloque como reemplazo completo del grupo.**

*(Recomiendo gestionar todos los agentes remotos desde monitoring-agents, para tener todo más separado y fácil de identificar)*.

### Nombres y precedencia

Las variables propias llevan `var_`. Las variables de Ansible, como `ansible_host` o `ansible_become`, conservan sus nombres oficiales. *(Si no, no las detectaria)*.

Definir valores comunes en grupos y excepciones por host. Evitar repetir estas variables en las variables adicionales de la plantilla o del workflow, porque pueden imponerse a los valores del inventario (La misma variable en Plantilla machaca a la variable en Inventario).

## 6. Credenciales de AWX

### Credencial de los agentes

Ir a **Credenciales → Añadir**:

| Campo | Valor |
| --- | --- |
| Nombre | `SSH - Agentes Ubuntu` |
| Organización | `Nombre_Organización`, o la organización correspondiente. |
| Tipo de credencial | Máquina. |
| Usuario | Usuario SSH real de los agentes. |
| Contraseña | Contraseña SSH, si se usa autenticación por contraseña. |
| Método de escalado | `sudo`. |
| Usuario de escalado | `root`. |
| Contraseña de escalado | Contraseña de sudo del usuario SSH. |

Una credencial común sirve si todos los agentes aceptan esa misma cuenta y autenticación. Si tienen accesos diferentes, organizar grupos y plantillas con sus credenciales correspondientes antes de ejecutar sobre todos ellos.

### Credencial del servidor central

Reutilizar la credencial Máquina que ya funciona con `Ip_Servidor`.

Si este host necesita el ejecutable alternativo de sudo que se comprobó durante la instalación, conservar exclusivamente en sus variables:

```yaml
ansible_become: true
ansible_become_method: sudo
ansible_become_user: root
ansible_become_exe: /usr/bin/sudo.ws
```

No copiar `ansible_become_exe` a los agentes sin comprobar que existe y que lo necesitan.

## 7. Crear las plantillas de trabajo

Ir a **Plantillas → Añadir → Agregar plantilla de trabajo**. Los nombres visibles pueden variar según la versión de AWX.

| Campo | Primera plantilla | Segunda plantilla |
| --- | --- | --- |
| Nombre | `Instalar agentes de monitorización` | `Configurar agentes Prometheus` |
| Tipo de trabajo | Ejecutar / Run | Ejecutar / Run |
| Inventario | Inventario común | El mismo inventario |
| Proyecto | Proyecto Git de monitorización | El mismo proyecto |
| Playbook | `monitorizacion/playbooks/instalar_agentes_monitorizacion.yml` | `monitorizacion/playbooks/configurar_agentes_prometheus.yml` |
| Credencial Máquina | `SSH - Agentes Ubuntu` | Credencial del servidor central |
| Entorno de ejecución | Entorno AWX EE Latest | Entorno AWX EE Latest |
| Escalado de privilegios | Activado; el playbook también lleva `become: true` | Activado; el playbook también lleva `become: true` |
| Límite | Vacío | Vacío |
| Variables adicionales | Vacías, salvo necesidad concreta | Vacías, salvo necesidad concreta |

Si el playbook no aparece en el desplegable, revisar proyecto, rama, sincronización y contenido del archivo en Git, o probar escribiéndola a mano.

## 8. Crear el WorkFlow

Ir a **Plantillas → Añadir → Plantilla de flujo de trabajo**.

- Nombre: `Desplegar agentes de monitorización`.
- Organización: la misma que el proyecto.
- Inventario: el común, si se configura en el workflow, mantener ambas plantillas con ese inventario.
- Límite: vacío.
- Variables adicionales: vacías.
- Ejecuciones simultáneas: desactivadas para evitar escrituras concurrentes en Prometheus.

En el visualizador:

1. Añadir desde Inicio la plantilla **Instalar agentes de monitorización**.
2. Añadir como siguiente nodo **Configurar agentes Prometheus** con condición **Si tiene éxito / On Success**.
3. Guardar el workflow.

Cada nodo utiliza su credencial Máquina. No se configura una contraseña compartida en el workflow.

No aplicar un límite global con el nombre del agente nuevo: excluiría al servidor central del segundo trabajo. El inventario completo es también necesario para generar todos los targets.

## 9. Primera prueba

1. Tener la plataforma central funcionando.
2. Añadir un único Ubuntu remoto real a `monitoring-agents`.
3. Revisar variables, IP y credencial SSH/sudo.
4. Sincronizar el proyecto de AWX.
5. Ejecutar `Desplegar agentes de monitorización`.
6. Abrir cada trabajo hijo y comprobar que haya ejecutado tareas sobre los hosts correctos.
7. Comprobar en Wazuh Dashboard que el agente aparece **Active**.
8. Abrir `http://IP_CENTRAL:PUERTO_PROMETHEUS/targets` *(http:prometheus:9090/targets)* y comprobar el target **UP**.
9. En Grafana, actualizar las variables del dashboard y seleccionar el job y equipo nuevos.

## 10. Añadir otro equipo después

1. Crear el host en AWX con su `ansible_host`.
2. Añadirlo a `monitoring-agents`.
3. Definir su nombre Wazuh, nombre visible y departamento.
4. Comprobar que la credencial de agentes sirve para ese equipo.
5. Ejecutar el workflow de agentes.
6. Verificar Wazuh Active y Prometheus UP.

El workflow actual revisa todos los miembros de `monitoring-agents`, no solo el nuevo. Las tareas que ya estén en el estado esperado deberían quedar sin cambios. Después se genera la lista completa de targets; Prometheus se reinicia solo si cambia su archivo.

Si un agente anterior está inaccesible, el primer trabajo puede fallar y el segundo no se ejecutará. No cambiar la condición a «Siempre» como solución automática. Revisar el equipo o diseñar una selección exclusiva para el primer trabajo manteniendo la lista completa para el segundo.

## 11. Cambiar o retirar equipos

- **Departamento o etiqueta de Prometheus:** editar variables del host y ejecutar `Configurar agentes Prometheus`.
- **Puerto Node Exporter:** editar la variable del host y ejecutar el workflow completo para cambiar servicio y target.
- **Retirar un target:** quitar el host de `monitoring-agents` y ejecutar directamente `Configurar agentes Prometheus`, incluso si el grupo queda vacío.
- **Desinstalar agentes o retirar su registro Wazuh:** no lo realizan estos playbooks. Quitar un host del inventario no desinstala software ni elimina su registro en Wazuh.
- **Cambiar el manager o renombrar un agente ya inscrito:** requiere revisar el registro y las claves existentes; no se considera una simple alta nueva.

## 12. Diagnóstico

En un Ubuntu remoto, consultas útiles:

```bash
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 60 /var/ossec/logs/ossec.log
sudo systemctl status prometheus-node-exporter --no-pager
sudo journalctl -u prometheus-node-exporter -n 60 --no-pager
curl --noproxy '*' http://127.0.0.1:9100/metrics
```

Si se necesitan logs más detallados, aumentar temporalmente la verbosidad de la plantilla a 3 *(debug)* y volver al nivel habitual después (0 - normal).

## 13. Permisos de operadores

El administrador configura proyecto, inventario, credenciales y plantillas. Para ejecutar un workflow ya preparado, otorgar al equipo operador el rol Execute sobre ese workflow *(Si se le dan permisos sobre la organización también tendría permisos en las plantillas individualmente y en todo lo relacionado a la organización)*. No es necesario hacerlo administrador global.

Si además debe añadir hosts o editar sus variables, necesita los permisos de administración correspondientes sobre ese inventario.

## 14. Referencias

- [AWX: credenciales](https://docs.ansible.com/projects/awx/en/24.6.1/userguide/credentials.html)
- [AWX: workflows](https://docs.ansible.com/projects/awx/en/24.6.1/userguide/workflow_templates.html)
- [Wazuh: instalación del agente Linux y compatibilidad](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)
- [Wazuh: variables de despliegue Linux](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-linux.html)

## Protección SSH mediante Wazuh Active Response (bloque independiente)

**Estado del piloto el 12/11/2026:** el agente Wazuh `005` (`PC_SISTEMAS_1`; host AWX `cliente_1`) está migrado al nuevo script, con firewall IPv4 y servicio systemd activos; Ansible y la plantilla individual de AWX son idempotentes (`changed=0`). El Manager continúa con `location=defined-agent`, `agent_id=005` y regla `5763`.

El workflow de agentes está configurado así:

```text
06 - Instalar Agentes
        ↓ éxito
07 - Configurar Agentes
        ↓ éxito
Aprobación manual de Active Response
        ↓ aprobación
23 - Wazuh AR - Despliegue (limit=cliente_1)
```

En la plantilla 23 se utiliza `configurar_wazuh_active_response_agentes.yml` con `var_wazuh_ar_agent_apply=true`, `var_wazuh_ar_migrate_existing=false`, `var_wazuh_ar_admin_networks_reviewed=true`, `var_wazuh_ar_ipv6_enabled=false` y `var_wazuh_ar_ack_ipv6_gap=true`. La ejecución individual de la plantilla funcionó; **no se ha realizado una ejecución integral del workflow modificado**.

El ciclo automático completo `ADD → DELETE` del nuevo script y el fallback temporal aún no se han validado de extremo a extremo; las funciones de bloqueo, desbloqueo y token sí se probaron directamente. No ampliar la plantilla a otros agentes ni el Manager a `location=local` hasta preparar y autorizar esos equipos.

No integrar esta función dentro de los instaladores de agentes: conservar los playbooks `auditar_wazuh_active_response.yml` y `configurar_wazuh_active_response_agentes.yml` separados.

Para detalles técnicos, pruebas, salvaguardas y rollback consultar [`docs/WAZUH_ACTIVE_RESPONSE.md`](docs/WAZUH_ACTIVE_RESPONSE.md).
