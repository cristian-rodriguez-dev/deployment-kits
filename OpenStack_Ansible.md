# OpenStack-Ansible 2026.1 en Ubuntu 26.04 LTS

## 1. Objetivo

Instalar OpenStack sobre un servidor con **Ubuntu Server 26.04 LTS (Resolute Raccoon)** utilizando **OpenStack-Ansible 2026.1 (Gazpacho)**.

Se utilizará una instalación **AIO (All-in-One)**, de forma que el mismo servidor actúe como:

- Host de despliegue Ansible.
- Host de infraestructura.
- Nodo de cómputo.
- Nodo de red.
- Nodo de almacenamiento.
- Host de los contenedores LXC utilizados por OpenStack.

Este tipo de instalación está pensada principalmente para:

- Laboratorios.
- Pruebas.
- Desarrollo.
- Demostraciones.
- Pruebas de concepto.

No está pensada como arquitectura de producción definitiva.

---

# 2. Arquitectura inicial

La arquitectura será aproximadamente:

```text
Ubuntu Server 26.04
        │
        ▼
OpenStack-Ansible
        │
        ├── Ansible
        ├── LXC
        ├── MariaDB / Galera
        ├── RabbitMQ
        ├── HAProxy
        │
        └── OpenStack
             │
             ├── Keystone
             │    Identidad y autenticación
             │
             ├── Nova
             │    Máquinas virtuales
             │
             ├── Neutron
             │    Redes
             │
             ├── Glance
             │    Imágenes
             │
             ├── Cinder
             │    Almacenamiento
             │
             └── Horizon
                  Interfaz web
```

Posteriormente las máquinas virtuales creadas en OpenStack podrán utilizarse para servicios como:

```text
OpenStack
   │
   ├── VM Wazuh
   ├── VM Prometheus
   ├── VM Grafana
   └── otras VM
```

---

# 3. Requisitos

## Sistema operativo

```text
Ubuntu Server 26.04 LTS
Codename: resolute
Arquitectura: amd64 / x86_64
```

OpenStack-Ansible 2026.1 soporta Ubuntu 26.04 tanto como nodo de despliegue como nodo destino.

---

## Recursos

### Mínimos

- 8 vCPU.
- 8 GB RAM.
- 50 GB libres en `/`.

### Recomendados

- 8 cores.
- 16 GB RAM.
- 80 GB libres en `/`.
- Virtualización por hardware.
- SSD.

Cuantos más recursos tenga el servidor, mejor funcionarán posteriormente las VM creadas dentro de OpenStack.

---

# 4. PASO 0 — Comprobar el servidor

Antes de instalar nada:

```bash
lsb_release -a
```

Debe aparecer algo similar a:

```text
Description: Ubuntu 26.04.1 LTS
Codename:    resolute
```

---

## Comprobar CPU

```bash
lscpu
```

Podemos comprobar específicamente los cores:

```bash
nproc
```

Y virtualización:

```bash
lscpu | grep Virtualization
```

Por ejemplo:

```text
Virtualization: VT-x
```

o:

```text
Virtualization: AMD-V
```

---

## Comprobar RAM

```bash
free -h
```

---

## Comprobar almacenamiento

```bash
df -h /
```

---

## Comprobar interfaces de red

```bash
ip -br addr
```

También:

```bash
ip route
```

Es importante saber cuál es la interfaz que proporciona conectividad al servidor.

Por ejemplo:

```text
ens18
ens160
eth0
```

---

## Comprobar hostname

```bash
hostname
hostname -f
```

Por ejemplo:

```text
wizard-00
```

---

# 5. PASO 1 — Entrar como root

La documentación de OpenStack-Ansible realiza la instalación como `root`.

Entramos en una shell de root:

```bash
sudo -i
```

Comprobar:

```bash
whoami
```

Debe devolver:

```text
root
```

A partir de aquí los comandos de instalación se ejecutarán desde esta shell.

---

# 6. PASO 2 — Actualizar Ubuntu

Actualizar repositorios:

```bash
apt update
```

Actualizar completamente los paquetes:

```bash
apt dist-upgrade -y
```

Instalar herramientas básicas:

```bash
apt install -y git ca-certificates curl
```

---

## Reiniciar

Después de la actualización:

```bash
reboot
```

Cuando el servidor vuelva:

```bash
sudo -i
```

Comprobar:

```bash
uname -r
```

Y:

```bash
lsb_release -a
```

---

# 7. PASO 3 — Revisar `/etc/hosts`

Consultar:

```bash
cat /etc/hosts
```

Hay que prestar especial atención a líneas como:

```text
127.0.1.1 wizard-00
```

OpenStack-Ansible advierte de que resolver el hostname real contra `127.0.1.1` puede provocar problemas.

La entrada:

```text
127.0.0.1 localhost
```

NO debe eliminarse.

Antes de modificar este archivo conviene comprobar la IP real:

```bash
hostname -I
```

y:

```bash
ip -br addr
```

---

# 8. PASO 4 — Descargar OpenStack-Ansible

Nos situamos en:

```bash
cd /opt
```

Clonamos el repositorio oficial:

```bash
git clone https://opendev.org/openstack/openstack-ansible /opt/openstack-ansible
```

Entramos:

```bash
cd /opt/openstack-ansible
```

---

# 9. PASO 5 — Seleccionar OpenStack 2026.1

No interesa utilizar directamente la rama de desarrollo.

Primero cambiamos a la rama estable:

```bash
git checkout stable/2026.1
```

Comprobamos:

```bash
git branch
```

Debería aparecer:

```text
* stable/2026.1
```

---

## Buscar última versión etiquetada

```bash
git describe --abbrev=0 --tags
```

Podemos guardarla automáticamente:

```bash
LATEST_TAG=$(git describe --abbrev=0 --tags)
```

Mostrar:

```bash
echo "$LATEST_TAG"
```

Y cambiar a esa versión:

```bash
git checkout "$LATEST_TAG"
```

Esto evita depender de una versión escrita manualmente en esta guía y permite utilizar la última versión etiquetada disponible dentro de 2026.1.

Comprobar:

```bash
git describe --tags
```

---

# 10. PASO 6 — Bootstrap de Ansible

Desde:

```text
/opt/openstack-ansible
```

ejecutamos:

```bash
scripts/bootstrap-ansible.sh
```

Este script prepara:

- Ansible.
- Dependencias Python.
- Colecciones.
- Roles necesarios.
- Entorno utilizado por OpenStack-Ansible.

---

## Comprobar Ansible

Cuando termine:

```bash
ansible --version
```

Y:

```bash
openstack-ansible --version
```

---

## Posible problema con `/tmp`

Si durante el bootstrap aparece un error similar a:

```text
configure: error: cannot run C compiled programs
```

comprobar:

```bash
mount | grep $(df /tmp | tail -n +2 | awk '{print $1}') | grep noexec
```

Si `/tmp` está montado con `noexec`, se puede utilizar:

```bash
TMPDIR=/var/tmp scripts/bootstrap-ansible.sh
```

---

# 11. PASO 7 — Preparar el AIO

Una vez instalado Ansible:

```bash
cd /opt/openstack-ansible
```

Ejecutamos:

```bash
scripts/bootstrap-aio.sh
```

Este es uno de los pasos más importantes.

El script prepara el servidor para funcionar como instalación OpenStack **All-in-One**.

Entre otras cosas prepara:

- Redes.
- Bridges.
- LXC.
- Almacenamiento.
- Configuración de OpenStack-Ansible.
- Inventario.
- Variables.
- Estructura de `/etc/openstack_deploy`.

---

# 12. Configuración generada

Cuando finalice deberían existir:

```bash
ls -la /etc/openstack_deploy
```

Entre los archivos importantes estarán:

```text
/etc/openstack_deploy/
├── openstack_user_config.yml
├── user_variables.yml
├── user_secrets.yml
├── conf.d/
└── env.d/
```

---

## `openstack_user_config.yml`

Define principalmente:

- Hosts.
- Redes.
- Infraestructura.
- Servicios.
- Grupos.

Consultar:

```bash
less /etc/openstack_deploy/openstack_user_config.yml
```

---

## `user_variables.yml`

Se utiliza para modificar variables globales del despliegue.

```bash
less /etc/openstack_deploy/user_variables.yml
```

Es uno de los archivos que utilizaremos posteriormente para personalizar OpenStack.

---

## `user_secrets.yml`

Contiene contraseñas y secretos generados automáticamente:

```bash
less /etc/openstack_deploy/user_secrets.yml
```

⚠️ Este archivo no debe publicarse ni subirse a Git.

---

# 13. PASO 8 — Preparar los hosts

Ahora empieza realmente el despliegue.

Primero:

```bash
cd /opt/openstack-ansible
```

Ejecutamos:

```bash
openstack-ansible openstack.osa.setup_hosts
```

Este playbook prepara:

- Host físico.
- Contenedores.
- Redes.
- Paquetes.
- Dependencias.
- Configuración base.

---

# 14. PASO 9 — Desplegar infraestructura

Cuando el paso anterior termine correctamente:

```bash
openstack-ansible openstack.osa.setup_infrastructure
```

Aquí se despliegan componentes de infraestructura utilizados posteriormente por OpenStack.

Por ejemplo:

```text
MariaDB / Galera
RabbitMQ
Memcached
HAProxy
repositorios internos
otros componentes
```

---

# 15. PASO 10 — Instalar OpenStack

Cuando infraestructura termine correctamente:

```bash
openstack-ansible openstack.osa.setup_openstack
```

Este playbook despliega los servicios OpenStack.

Entre los servicios básicos estarán:

```text
Keystone
Nova
Neutron
Glance
Cinder
Horizon
```

Este es el paso principal de la instalación.

---

# 16. Orden completo de los tres playbooks

El orden debe ser:

```bash
openstack-ansible openstack.osa.setup_hosts
```

después:

```bash
openstack-ansible openstack.osa.setup_infrastructure
```

y finalmente:

```bash
openstack-ansible openstack.osa.setup_openstack
```

Representado:

```text
setup_hosts
     │
     ▼
setup_infrastructure
     │
     ▼
setup_openstack
```

No conviene continuar al siguiente si el anterior ha terminado con errores.

---

# 17. PASO 11 — Ver los contenedores

El despliegue AIO utiliza normalmente contenedores LXC para aislar servicios.

Podemos consultar:

```bash
lxc-ls -f
```

También:

```bash
lxc-ls -1
```

Deberían aparecer diferentes contenedores relacionados con componentes de OpenStack.

---

# 18. PASO 12 — Acceder a Horizon

Horizon es la interfaz gráfica web de OpenStack.

Consultar primero la IP:

```bash
hostname -I
```

Por defecto Horizon puede estar disponible mediante HTTPS:

```text
https://IP_SERVIDOR
```

Por ejemplo:

```text
https://10.10.x.x
```

El AIO utiliza certificados propios por defecto, por lo que el navegador puede mostrar una advertencia de certificado.

---

# 19. Usuario administrador

El usuario administrativo creado por defecto es:

```text
admin
```

La contraseña está almacenada en:

```text
/etc/openstack_deploy/user_secrets.yml
```

Podemos buscarla:

```bash
grep keystone_auth_admin_password /etc/openstack_deploy/user_secrets.yml
```

Obtendremos algo similar a:

```text
keystone_auth_admin_password: CONTRASEÑA
```

Por tanto:

```text
Usuario: admin
Contraseña: valor de keystone_auth_admin_password
```

---

# 20. PASO 13 — Acceso por línea de comandos

En el escenario LXC existe normalmente un contenedor `utility`.

Buscarlo:

```bash
lxc-ls -1 | grep utility
```

Entrar:

```bash
lxc-attach -n "$(lxc-ls -1 | grep utility | head -1)"
```

Dentro podemos comprobar:

```bash
ls /root/openrc
```

Y:

```bash
ls /root/.config/openstack/clouds.yaml
```

---

## Utilizar OpenStack CLI

Podemos cargar:

```bash
export OS_CLOUD=default
```

Por ejemplo:

```bash
openstack project list
```

También:

```bash
openstack user list
```

```bash
openstack service list
```

```bash
openstack endpoint list
```

---

# 21. PASO 14 — Comprobaciones básicas

## Servicios

```bash
openstack service list
```

---

## Proyectos

```bash
openstack project list
```

---

## Usuarios

```bash
openstack user list
```

---

## Redes

```bash
openstack network list
```

---

## Imágenes

```bash
openstack image list
```

---

## Flavors

```bash
openstack flavor list
```

---

## Máquinas virtuales

```bash
openstack server list
```

Al principio probablemente estará vacío.

---

# 22. Funcionamiento conceptual

OpenStack no funciona como Docker.

Una VM OpenStack es una máquina virtual completa:

```text
Servidor físico
      │
      ▼
Ubuntu 26.04
      │
      ▼
OpenStack
      │
      ├── VM 1
      │    └── Ubuntu
      │         └── Wazuh
      │
      ├── VM 2
      │    └── Ubuntu
      │         └── Prometheus
      │
      └── VM 3
           └── Ubuntu
                └── Grafana
```

También sería posible ejecutar varios servicios dentro de una única VM si la arquitectura lo requiere.

---

# 23. Flujo futuro

Una vez OpenStack funcione, el siguiente objetivo será preparar:

```text
1. Proyecto
2. Usuario
3. Imagen Ubuntu
4. Flavor
5. Red
6. Subred
7. Router
8. Security Groups
9. SSH Key
10. Primera VM
```

Después podremos automatizar la creación y configuración de VM.

Ejemplo:

```text
Solicitud de nueva máquina
        │
        ▼
OpenStack crea VM
        │
        ▼
Se obtiene IP
        │
        ▼
Ansible configura VM
        │
        ├── Wazuh
        ├── Prometheus
        └── Grafana
```

---

# 24. Importante: no ejecutar todo de golpe

Para esta primera instalación se recomienda avanzar por fases.

## Fase 1

Ejecutar únicamente:

```bash
lsb_release -a
nproc
free -h
df -h /
ip -br addr
ip route
```

Verificar recursos.

---

## Fase 2

Actualizar:

```bash
sudo -i

apt update
apt dist-upgrade -y
apt install -y git ca-certificates curl

reboot
```

---

## Fase 3

Descargar OpenStack-Ansible:

```bash
sudo -i

git clone https://opendev.org/openstack/openstack-ansible \
    /opt/openstack-ansible

cd /opt/openstack-ansible

git checkout stable/2026.1

LATEST_TAG=$(git describe --abbrev=0 --tags)

echo "$LATEST_TAG"

git checkout "$LATEST_TAG"
```

---

## Fase 4

Bootstrap de Ansible:

```bash
cd /opt/openstack-ansible

scripts/bootstrap-ansible.sh
```

---

## Fase 5

Preparar AIO:

```bash
cd /opt/openstack-ansible

scripts/bootstrap-aio.sh
```

---

## Fase 6

Instalar OpenStack:

```bash
openstack-ansible openstack.osa.setup_hosts
```

```bash
openstack-ansible openstack.osa.setup_infrastructure
```

```bash
openstack-ansible openstack.osa.setup_openstack
```

---

# 25. Resumen rápido

La instalación completa queda conceptualmente:

```text
Ubuntu 26.04
    │
    ▼
Actualizar servidor
    │
    ▼
Clonar OpenStack-Ansible
    │
    ▼
Seleccionar stable/2026.1
    │
    ▼
Seleccionar último tag estable
    │
    ▼
bootstrap-ansible.sh
    │
    ▼
bootstrap-aio.sh
    │
    ▼
setup_hosts
    │
    ▼
setup_infrastructure
    │
    ▼
setup_openstack
    │
    ▼
Horizon
    │
    ▼
Crear red / imagen / flavor
    │
    ▼
Crear primera VM
```

---

# 26. Comandos principales

```bash
# Entrar como root
sudo -i

# Actualizar
apt update
apt dist-upgrade -y
apt install -y git ca-certificates curl

# Reiniciar
reboot
```

Después:

```bash
sudo -i

git clone https://opendev.org/openstack/openstack-ansible \
    /opt/openstack-ansible

cd /opt/openstack-ansible

git checkout stable/2026.1

LATEST_TAG=$(git describe --abbrev=0 --tags)

git checkout "$LATEST_TAG"
```

Bootstrap:

```bash
scripts/bootstrap-ansible.sh
```

Preparar AIO:

```bash
scripts/bootstrap-aio.sh
```

Instalación:

```bash
openstack-ansible openstack.osa.setup_hosts

openstack-ansible openstack.osa.setup_infrastructure

openstack-ansible openstack.osa.setup_openstack
```

Comprobar:

```bash
lxc-ls -f
```

Contraseña Horizon:

```bash
grep keystone_auth_admin_password \
    /etc/openstack_deploy/user_secrets.yml
```

Acceso:

```text
https://IP_SERVIDOR

Usuario: admin
```

---

# 27. Después de instalar OpenStack

Una vez comprobemos que Horizon funciona, continuaremos con:

1. Revisar servicios.
2. Configurar red externa.
3. Crear red interna.
4. Crear subred.
5. Crear router.
6. Descargar una imagen Ubuntu Cloud.
7. Importarla en Glance.
8. Crear flavors.
9. Crear claves SSH.
10. Configurar Security Groups.
11. Lanzar la primera VM.
12. Comprobar acceso SSH.
13. Automatizar creación de VM.
14. Integrar OpenStack con Ansible/AWX.
15. Automatizar Wazuh, Prometheus y Grafana.