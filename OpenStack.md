# Guía de OpenStack con Sunbeam, AWX, Wazuh, Prometheus y Grafana

***(No testeado)***

## Índice

1. [Qué hace cada herramienta](#1-qué-hace-cada-herramienta)
2. [Arquitectura prevista](#2-arquitectura-prevista)
3. [Requisitos y preparación de la red](#3-requisitos-y-preparación-de-la-red)
4. [Actualizar Ubuntu](#4-actualizar-ubuntu)
5. [Instalar OpenStack mediante Snap](#5-instalar-openstack-mediante-snap)
6. [Preparar el nodo](#6-preparar-el-nodo)
7. [Inicializar el clúster](#7-inicializar-el-clúster)
8. [Configurar la nube con acceso remoto](#8-configurar-la-nube-con-acceso-remoto)
9. [Horizon y credenciales](#9-horizon-y-credenciales)
10. [Comprobar la nube](#10-comprobar-la-nube)
11. [Crear una instancia de prueba](#11-crear-una-instancia-de-prueba)
12. [Proyecto y tamaños de VM](#12-proyecto-y-tamaños-de-vm)
13. [Preparar la clave SSH para AWX](#13-preparar-la-clave-ssh-para-awx)
14. [Grupos de seguridad](#14-grupos-de-seguridad)
15. [Crear las VM definitivas](#15-crear-las-vm-definitivas)
16. [Asignar IP flotantes](#16-asignar-ip-flotantes)
17. [Probar SSH y preparar el sistema invitado](#17-probar-ssh-y-preparar-el-sistema-invitado)
18. [Registrar las VM en AWX](#18-registrar-las-vm-en-awx)
19. [Verificar AWX antes del despliegue](#19-verificar-awx-antes-del-despliegue)
20. [Preparar Docker y desplegar servicios](#20-preparar-docker-y-desplegar-servicios)

## 1. Qué hace cada herramienta

- **OpenStack:** Crea y administra las VM, sus redes y sus discos.
- **Sunbeam:** Instala y administra el despliegue de OpenStack sobre Ubuntu.
- **Kubernetes:** Aloja el plano de control de OpenStack.
- **AWX:** Ejecuta Ansible por SSH para preparar las VM e instalar servicios y agentes.
- **Docker dentro de las VM:** Ejecuta Wazuh, Prometheus y Grafana usando playbooks.
- **Wazuh:** Recibe eventos de los agentes y muestra información de seguridad.
- **Prometheus:** Consulta métricas de los exportadores.
- **Grafana:** Consulta Prometheus y representa esas métricas.

Las actualizaciones se realizan mediante los procedimientos de Sunbeam.

## 2. Arquitectura prevista

| Equipo | Función |
| --- | --- |
| Servidor físico Ubuntu | Nodo OpenStack con control, cómputo y almacenamiento |
| AWX existente | Automatización y acceso SSH a las VM |
| vm-wazuh | Manager, indexer y dashboard Wazuh en Docker |
| vm-prometheus | Prometheus y Node Exporter |
| vm-grafana | Grafana |
| Equipos monitorizados | Agente Wazuh y/o exportador de métricas |

OpenStack crea las máquinas. AWX configura sus sistemas. Los agentes se conectan después a los servicios correspondientes.

Un único nodo no proporciona alta disponibilidad: si falla el servidor físico, las tres VM quedan afectadas.

## 3. Requisitos y preparación de la red

Utilizar un servidor dedicado con Ubuntu Server 24.04 LTS recién instalado y virtualización por hardware disponible. La guía manual de Canonical utiliza redes físicas diferenciadas para gestión y tráfico externo. Reserva también un disco adicional sin particionar para MicroCeph si vas a asignar el rol storage.

El tutorial de aprendizaje de Canonical parte de 4 núcleos, 16 GiB de RAM y 100 GiB SSD de sistema, además del disco de Ceph. Esos mínimos no garantizan capacidad para ejecutar las tres VM de esta guía: hay que sumar sus recursos y el margen que requiere OpenStack.

Recursos iniciales orientativos para pocos equipos:

| VM | vCPU | RAM | Disco raíz |
| --- | ---: | ---: | ---: |
| vm_wazuh | 4 | 8 GiB | 100 GiB |
| vm_prometheus | 2 | 4 GiB | 40 GiB |
| vm_grafana | 2 | 2 GiB | 20 GiB |

Ajustar según agentes, retención y carga. En especial, vigilar el consumo de RAM y almacenamiento del indexer Wazuh.

### Ejemplo de direccionamiento

| Concepto | Ejemplo |
| --- | --- |
| Red de gestión | Una subred dedicada accesible a los administradores |
| Rango de API de OpenStack | IP libres y reservadas en la red de gestión |
| Red externa de las VM | x.x.x.x/24 |
| Gateway externo | x.x.x.1 |
| Rango reservado de IP flotantes | x.x.x.x–x.x.x.y |
| Red privada del proyecto | 192.168.x.x/24 |
| DNS | DNS accesible desde las VM |

Las IP flotantes deben estar fuera del DHCP y libres. La red privada no debe solaparse con redes que las VM necesiten alcanzar.

Identificar interfaces y rutas en el nodo:

```bash
ip -br address
ip route
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS
```

## 4. Actualizar Ubuntu

**Dónde:** servidor físico OpenStack.

```bash
sudo apt update
sudo apt upgrade -y
```

Si se requiere reinicio, hacerlo antes de iniciar el despliegue.

`apt update` actualiza el índice de paquetes; `apt upgrade` instala las actualizaciones.

## 5. Instalar OpenStack mediante Snap

```bash
snap info openstack
sudo snap install openstack
snap list openstack
```

## 6. Preparar el nodo

Ver primero el script generado:

```bash
sunbeam prepare-node-script --bootstrap
```

Ejecutarlo:

```bash
sunbeam prepare-node-script --bootstrap | bash -x
newgrp snap_daemon
```

Prepara dependencias y permisos, incluido sudo sin contraseña para el usuario actual. `newgrp` abre una shell con el grupo actualizado.

## 7. Inicializar el clúster

```bash
sunbeam cluster bootstrap --role control,compute,storage
```

Roles:

- control: funciones de control y API de la nube.
- compute: ejecución de VM.
- storage: almacenamiento mediante Ceph.

Responder al asistente con la red de gestión, rango reservado para API y disco dedicado a Ceph. Según la versión, pregunta también por proxy, región y topología de base de datos. Registrar las respuestas.

Se omite `--accept-defaults` para revisar la configuración de red y almacenamiento. Esa opción solo acepta valores predeterminados.

## 8. Configurar la nube con acceso remoto

```bash
sunbeam configure --openrc "$HOME/demo-openrc"
```

Seleccionar acceso **remote** para que AWX y otros equipos puedan alcanzar las VM.

| Pregunta | Respuesta de ejemplo |
| --- | --- |
| Local or remote access to VMs | remote |
| External network | x.x.x.x/24 |
| External network gateway | x.x.x.1 |
| External allocation range | x.x.x.x–x.x.x.y |
| External network type | flat, si no hay etiquetado VLAN |
| Populate demo user, images, flavors | y |
| Username | demo |
| Password | Mi_Contraseña |
| Project network | 192.168.x.x/24 |
| Project nameservers | DNS accesible |
| Enable ping and SSH | y |
| External network interface | Interfaz física correspondiente |

## 9. Horizon y credenciales

Obtener la URL:

```bash
sunbeam dashboard url
```

Abrir la URL completa que devuelve el comando.

Consultar las credenciales del usuario de demostración:

```bash
cat "$HOME/demo-openrc"
```

En Horizon utilizar los valores del archivo:

- Usuario: OS_USERNAME.
- Contraseña: OS_PASSWORD.
- Dominio: OS_USER_DOMAIN_NAME.

Generar credenciales administrativas:

```bash
sunbeam openrc > "$HOME/admin-openrc"
chmod 600 "$HOME/admin-openrc" "$HOME/demo-openrc"
```

## 10. Comprobar la nube

Con credenciales administrativas:

```bash
source "$HOME/admin-openrc"
openstack token issue
openstack service list
openstack compute service list
openstack network agent list
```

Con credenciales del proyecto demo:

```bash
source "$HOME/demo-openrc"
openstack server list
openstack image list
openstack flavor list
openstack network list
openstack subnet list
openstack router list
```

## 11. Crear una instancia de prueba

```bash
sunbeam launch ubuntu --name Nombre_Servidor
```

Utilizar el comando SSH que muestre al terminar. Verificar que la VM arranca y tiene conectividad.

## 12. Proyecto y tamaños de VM

Crear flavors como administrador:

```bash
source "$HOME/admin-openrc"
openstack flavor create monitor_wazuh --vcpus 4 --ram 8192 --disk 100
openstack flavor create monitor_prometheus --vcpus 2 --ram 4096 --disk 40
openstack flavor create monitor_grafana --vcpus 2 --ram 2048 --disk 20
openstack flavor list
```

Comprobar las cuotas del proyecto en Horizon antes de lanzar las instancias.

## 13. Preparar la clave SSH para AWX

**Dónde:** Equipo de administración que tendrá la clave.

```bash
ssh-keygen -t ed25519 -f "$HOME/.ssh/awx_openstack"
```

- awx_openstack: Clave privada para la credencial de máquina de AWX.

- awx_openstack.pub: Clave pública para OpenStack.

En Horizon, dentro del proyecto que alojará las VM:

**Proyecto -> Cómputo -> Pares de claves -> Importar clave pública**.

Nombre: `awx_openstack`.

Pegar el contenido de awx_openstack.pub. La clave privada no se importa en OpenStack.

Seleccionar ese par de claves al crear cada VM. Importarlo después no modifica automáticamente las VM existentes.

## 14. Grupos de seguridad

En **Proyecto -> Red -> Grupos de seguridad**, crear:

- seguridad_wazuh.
- seguridad_prometheus.
- seguridad_grafana.

Configurar reglas de entrada:

| Destino | Puerto/protocolo | Origen |
| --- | --- | --- |
| Las tres VM | ICMP | Red de administración |
| Wazuh | TCP 1514 | Redes de los agentes |
| Wazuh | TCP 1515 | Redes de los agentes |
| Wazuh dashboard | TCP 5601 (Por defecto 443) | Equipos administradores |
| Wazuh API | TCP 55000 | Equipos autorizados |
| Prometheus | TCP 9090 | VM Grafana y equipos administradores |
| Grafana | TCP 3000 | Usuarios autorizados |
| VM con Node Exporter | TCP 9100 | VM Prometheus |

## 15. Crear las VM definitivas

En **Proyecto -> Cómputo -> Instancias -> Lanzar instancia**:

| Nombre | Imagen | Flavor | Clave | Grupo |
| --- | --- | --- | --- | --- |
| vm_wazuh | Ubuntu Server cloud compatible | monitor_wazuh | awx_openstack | seguridad_wazuh |
| vm_prometheus | Ubuntu Server cloud compatible | monitor_prometheus | awx_openstack | seguridad_prometheus |
| vm_grafana | Ubuntu Server cloud compatible | monitor_grafana | awx_openstack | seguridad_grafana |

Esperar al estado ACTIVE y a que finalice cloud-init. Consultar la consola de instancia si no arranca.

## 16. Asignar IP flotantes

En **Proyecto -> Red -> IP flotantes**, reservar tres IP y asociar cada una al puerto de su VM.

| VM | IP privada | IP flotante |
| --- | --- | --- |
| vm_wazuh | 192.168.x.x | x.x.x.x |
| vm_prometheus | 192.168.x.y | x.x.x.y |
| vm_grafana | 192.168.x.z | x.x.x.z |

Anotar las IP realmente asignadas *(las flotantes)*.

Comprobar en la topología de la red, que el router del proyecto conecta la subred privada con la red externa.
***Nota: (Si Sunbeam ya lo creó, reutilizarlo)***.

Las IP flotantes deben mantenerse asociadas de forma estable para no tener que estar cambiando las direcciones configuradas en AWX y los agentes.

## 17. Probar SSH y preparar el sistema invitado

Desde el equipo que tenga la clave:

```bash
ssh -i "$HOME/.ssh/awx_openstack" ubuntu@x.x.x.x
```

Dentro de cada VM:

```bash
cloud-init status --wait
hostname
ip route
getent hosts archive.ubuntu.com
sudo apt update
sudo -n true
python3 --version
```

## 18. Registrar las VM en AWX

Añadir los hosts al inventario existente.

Host vm_wazuh:

```yaml
ansible_host: x.x.x.x
ansible_user: ubuntu
```

Host vm_prometheus:

```yaml
ansible_host: x.x.x.y
ansible_user: ubuntu
```

Host vm_grafana:

```yaml
ansible_host: x.x.x.z
ansible_user: ubuntu
```

Asignar a cada host al grupo usar por los playbooks a usar:

Ejemplo (Los usados en Readme_Despliegue):

| Grupo | Host |
| --- | --- |
| wazuh-servers | vm_wazuh |
| prometheus-servers | vm_prometheus |
| grafana-servers | vm_grafana |

Crear una credencial de tipo Máquina:

- Nombre: SSH OpenStack.
- Usuario SSH: ubuntu.
- Clave privada: Contenido de awx_openstack.
- Contraseña de la clave: Si se configuró al generarla.
- Método de escalado: sudo.
- Usuario de escalado: root.

Activar el check de escalado de privilegios en las plantillas que lo necesiten o utilizar become: true en el playbook.
*Nota: (Recomiendo usar ambos métodos por asegurar)*.

Las contraseñas de Wazuh y Grafana siguen en sus credenciales de aplicación.
*Nota: (Revisar Readme_Despliegue)*.

## 19. Verificar AWX antes del despliegue

Ejecutar una tarea ad hoc con módulo ping sobre los tres hosts y la credencial SSH OpenStack. Resultado esperado: pong.

Con los privilegios de escalado activados, ejecutar el módulo command con argumento:

```text
id
```

Tiene que aparecer uid=0(root).

## 20. Preparar Docker y desplegar servicios

