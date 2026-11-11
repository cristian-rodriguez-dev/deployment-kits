# Despliegue de monitorización con AWX

Guía para instalar Wazuh, Prometheus, Node Exporter y Grafana en Ubuntu mediante cuatro playbooks de Ansible.

Las variables se configuran en el inventario de AWX y las contraseñas se guardan en sus credenciales.

## Índice

1. [Alcance](#1-alcance)
2. [Requisitos previos](#2-requisitos-previos)
3. [Estructura del repositorio](#3-estructura-del-repositorio)
4. [Crear el proyecto](#4-crear-el-proyecto)
5. [Crear el inventario](#5-crear-el-inventario)
6. [Configurar las variables](#6-configurar-las-variables)
7. [Configurar las credenciales](#7-configurar-las-credenciales)
8. [Crear las plantillas de trabajo](#8-crear-las-plantillas-de-trabajo)
9. [Crear el workflow](#9-crear-el-workflow)
10. [Ejecutar y comprobar](#10-ejecutar-y-comprobar)
11. [Añadir equipos a Prometheus](#11-añadir-equipos-a-prometheus)

## 1. Alcance

Esta guía explica la configuración dentro de un AWX ya instalado:

- Proyecto conectado a Git.
- Inventario, host y grupos.
- Variables de los servicios.
- Credenciales SSH y de las aplicaciones.
- Cuatro plantillas de trabajo.
- Un workflow para ejecutarlas en orden.

Los playbooks utilizados son:

| Playbook | Función |
| --- | --- |
| `instalar_wazuh.yml` | Instalar Wazuh, preparar certificados y configurar credenciales iniciales. |
| `configurar_wazuh.yml` | Configurar el tema y la zona horaria del Dashboard. |
| `instalar_prometheus.yml` | Instalar Prometheus y Node Exporter local. |
| `instalar_grafana.yml` | Instalar Grafana y configurar Prometheus como fuente de datos. |

No se incluye:

- La instalación de AWX desde cero.
- La construcción completa de su entorno de ejecución.
- La instalación de Docker.
- La instalación de agentes en equipos remotos.
- La importación automática de dashboards en Grafana.
- La integración de Wazuh como fuente de datos de Grafana.

## 2. Requisitos previos

### Servidor de destino

El servidor debe disponer de:

- Ubuntu.
- Python 3.
- Servicio SSH.
- Usuario SSH con permisos.
- Docker instalado.
- Docker Compose 2.18.0 o posterior.

### Entorno de ejecución de AWX

Los playbooks necesitan las siguientes colecciones para su correcto funcionamiento:

```yaml
---
collections:
  - name: community.docker
    version: "5.3.0"

  - name: ansible.posix
    version: "2.1.0"
```

Si se utiliza la instalación de dependencias durante la sincronización del proyecto, colocar el archivo en:

```text
monitorizacion/collections/requirements.yml
```

Esta ruta es relativa a la raíz del repositorio Git. Crear el archivo no sustituye la comprobación de que AWX instala y encuentra las colecciones.

### Valores utilizados en los ejemplos

| Elemento | Valor |
| --- | --- |
| Servidor Ubuntu | `10.10.3.100` |
| Host en AWX | `ansible_server` |
| Usuario SSH | `pruebas` |
| Directorio base | `/home/pruebas/instalacion` |
| Wazuh Dashboard | `5601` |
| Prometheus | `9090` |
| Node Exporter | `9100` |
| Grafana | `3000` |

***(Adaptar estos valores al entorno de instalación)***.

Si ya existe una instalación, conservar sus rutas, proyectos Docker, versiones y credenciales.

## 3. Estructura del repositorio

Esta sería la estructura que debe de tener el repositorio para usar los playbooks correctamente.

```text
raiz_de_tu_repositorio/
├── collections/
│   └── requirements.yml
└── monitorizacion/
    ├── README.md
    ├── playbooks/
    │   ├── instalar_wazuh.yml
    │   ├── configurar_wazuh.yml
    │   ├── instalar_prometheus.yml
    │   └── instalar_grafana.yml
    └── templates/
        ├── wazuh/
        │   └── compose.credentials.yml.j2
        ├── prometheus/
        │   ├── docker-compose.yml.j2
        │   └── prometheus.yml.j2
        └── grafana/
            ├── docker-compose.yml.j2
            └── datasources.yml.j2
```

Todos los archivos deben tener contenido y estar guardados en la rama que utiliza AWX.

Las plantillas `.j2` se utilizan desde los playbooks. No se seleccionan como playbooks en la interfaz de AWX.

No guardar contraseñas reales, claves privadas ni archivos generados con secretos en el repositorio.

## 4. Crear el proyecto

En AWX:

1. Entrar en **Recursos → Proyectos → Añadir**.
2. Configurar los campos:

    | Campo | Valor |
    | --- | --- |
    | Nombre | `Nombre_Proyecto` |
    | Organización | `Nombre_Organización` |
    | Tipo de control de código fuente | `Git` |
    | URL del repositorio | URL de `Nombre_Repositorio` |
    | Rama | `Rama_Git_Usada` |
    | Credencial de control de código fuente | Credencial de Git, solo si el repositorio es privado |
    | Opciones | ✅ Limpiar <br> ✅ Permitir la anulación de la rama |

3. Guardar.
4. Sincronizar el proyecto.
5. Esperar a que la sincronización termine correctamente.

## 5. Crear el inventario

### 5.1. Inventario

En **Recursos → Inventarios → Añadir**, crear:

```text
Nombre: Nombre_Inventario
Organización: Nombre_Organización
```

Guardar.

### 5.2. Host

Dentro del inventario que se acaba de crear, entrar en **Servidores → Añadir**.

Nombre:

```text
ansible_server
```

Variables:

```yaml
---
ansible_host: 10.10.3.100

ansible_become: true
ansible_become_method: sudo
ansible_become_user: root
```

Estas variables indican la IP del servidor y la elevación de privilegios mediante sudo.

El usuario SSH se define en la credencial de Máquina.

***(Revisar compatibilidad con sudo-rs antes de guardar)***
Guardar.

### Compatibilidad con sudo-rs

En el servidor utilizado durante las pruebas fue necesario añadir:

```yaml
ansible_become_exe: /usr/bin/sudo.ws
```

Se utilizó porque la versión de Ansible del entorno de AWX no reconocía correctamente la petición de contraseña de `sudo-rs`.
*(No se probó con `sudo su`)*

Antes de utilizarla en otro servidor, comprobar:

```bash
command -v sudo.ws
```

No añadir esta variable si el ejecutable no existe. No todos los servidores Ubuntu necesitan este ajuste.

### 5.3. Grupos

**Inventarios** -> **Nombre_Inventario** -> **Grupos** -> **Añadir** y crea estos tres grupos:

```text
wazuh-servers
prometheus-servers
grafana-servers
```

Asociar el host existente `ansible_server` a los tres grupos.
***(Para ello -> Nombre_Grupo -> Servidores -> Añadir -> Agregar_Host_Existente -> Seleccionar Nombre_Host y Guardar)***

No crear tres copias del mismo host.

Los nombres deben coincidir exactamente con los nombres en los playbooks:

```yaml
hosts: wazuh-servers
```

```yaml
hosts: prometheus-servers
```

```yaml
hosts: grafana-servers
```

## 6. Configurar las variables

Introducir los bloques en:

**Inventarios -> Nombre_Inventario → Grupos → grupo correspondiente → Editar → Variables**:

Las variables propias de los playbooks utilizan el prefijo `var_`.

Las variables reservadas de Ansible, como `ansible_host` y `ansible_become`, conservan sus nombres.

***(Ante cualquier duda de como nombrar una variable, revisar el playbook al que pertenece el grupo que se esté modificando)***

### 6.1. Grupo wazuh-servers

```yaml
---
var_wazuh_install_dir: /home/pruebas/instalacion/wazuh-docker
var_wazuh_access_group: pruebas
var_wazuh_project_name: wazuh
var_wazuh_version: "4.14.8"
var_wazuh_dashboard_port: 5601

var_wazuh_dashboard_timezone: Europe/Madrid
var_wazuh_dashboard_dark_mode: true
```

### 6.2. Grupo prometheus-servers

```yaml
---
var_prometheus_install_dir: /home/pruebas/instalacion/prometheus_server
var_prometheus_access_group: pruebas
var_prometheus_project_name: prometheus

var_prometheus_image: prom/prometheus:v3.15.0
var_node_exporter_image: prom/node-exporter:v1.12.1

var_prometheus_port: 9090
var_node_exporter_port: 9100

# Cantidad de días durante los que se conservan las métricas.
var_prometheus_retention: 15d

# Cantidad de segundos entre consultas.
var_prometheus_scrape_interval: 15s

var_prometheus_local_name: Servidor-Principal

# Red compartida con Grafana.
var_monitorizacion_network: monitorizacion

# Lista de equipos remotos.
# El servidor local ya se añade desde la plantilla.
var_prometheus_departamentos: []

# Ejemplo: sustituir la lista vacía anterior por este bloque.
#
# var_prometheus_departamentos:
#   - nombre: Informatica
#     equipos:
#       - nombre: Equipo-01
#         direccion: 10.10.3.101
#         puerto: 9100
#
#   - nombre: Administracion
#     equipos:
#       - nombre: Equipo-02
#         direccion: 10.10.3.102
#         puerto: 9100
```

### 6.3. Grupo grafana-servers

```yaml
---
var_grafana_install_dir: /home/pruebas/instalacion/grafana
var_grafana_access_group: pruebas
var_grafana_project_name: grafana
var_grafana_image: grafana/grafana:13.2.3
var_grafana_port: 3000
var_grafana_admin_user: admin
var_grafana_admin_email: admin@localhost

# Debe coincidir con la red utilizada por Prometheus.
var_monitorizacion_network: monitorizacion

var_grafana_prometheus_url: http://prometheus:9090
```

### 6.4. Variables compartidas

El mismo host pertenece a varios grupos y recibe sus variables.

```yaml
var_monitorizacion_network: monitorizacion
```

Debe coincidir en Prometheus y Grafana.

*(Las variables también pueden definirse una sola vez en las variables del inventario o en las variables del WorkFlow que une los trabajos, eliminando las copias de los grupos)*.

### 6.5. Acceso a los directorios

Las variables `var_*_access_group` indican un grupo de Linux del servidor, no un grupo de AWX.

Consultar el grupo principal del usuario:

```bash
id -gn
```

Consultar todos sus grupos:

```bash
id -nG
```

Consultar un usuario concreto:

```bash
id pruebas
```

Los directorios principales se crean con:

```yaml
owner: root
group: "{{ var_grafana_access_group }}"
mode: "0750"
```

***(Si quieres que tengan unas poderes específicos cámbialos en mode: " ")***

Cada playbook utiliza su variable de grupo correspondiente.

Los miembros del grupo pueden entrar y listar el directorio. Los archivos de credenciales y los directorios de datos mantienen permisos específicos.

Los directorios superiores también deben permitir el acceso al usuario.

## 7. Configurar las credenciales

### 7.1. Credencial de Máquina

Entrar en **Recursos → Credenciales → Añadir**.

| Campo | Valor |
| --- | --- |
| Nombre | `SSH - Nombre_Inventario` |
| Organización | `Nombre_Organización` |
| Tipo de credencial | Máquina |
| Usuario | Usuario SSH del servidor |
| Contraseña | Contraseña SSH, si se utiliza |
| Clave privada SSH | Si se utiliza autenticación mediante clave |
| Método de escalado de privilegios | `sudo` |
| Usuario de escalado | `root` |
| Contraseña de escalado | La contraseña que requiere sudo para ese usuario |

Para ejecutar el workflow sin intervención, guardar las credenciales necesarias en AWX y no dejarlas pendientes de solicitud al lanzar el trabajo.

### 7.2. Tipo de credencial de Wazuh

Entrar en:

**Administración → Tipos de credenciales → Añadir**:

Nombre:

```text
Credenciales Wazuh
```

En configuración de entrada introducir:

```yaml
---
fields:
  - id: admin_password
    type: string
    label: Contraseña del administrador del Indexer
    secret: true

  - id: api_password
    type: string
    label: Contraseña de la API de Wazuh
    secret: true

required:
  - admin_password
  - api_password
```

En configuración del inyector introducir:

```yaml
---
env:
  VAR_WAZUH_ADMIN_PASSWORD: "{{ admin_password }}"
  VAR_WAZUH_API_PASSWORD: "{{ api_password }}"
```

El playbook `instalar_wazuh.yml` debe leer esos mismos nombres:

```yaml
var_wazuh_admin_password: >-
  {{ lookup('ansible.builtin.env', 'VAR_WAZUH_ADMIN_PASSWORD') }}

var_wazuh_api_password: >-
  {{ lookup('ansible.builtin.env', 'VAR_WAZUH_API_PASSWORD') }}
```

Guardar el tipo de credencial.

Después, entrar en **Recursos → Credenciales → Añadir**:

| Campo | Valor |
| --- | --- |
| Nombre | `Wazuh - Nombre_Inventario` |
| Organización | `Nombre_Organización` |
| Tipo de credencial | `Credenciales Wazuh` |
| Contraseña del administrador | Contraseña_Real |
| Contraseña de la API | Contraseña_Real |

Requisitos de las contraseñas del playbook:

- Administrador: al menos 8 caracteres.
- API: entre 8 y 64 caracteres, con mayúscula, minúscula, número y símbolo.

Guardar la credencial.

### 7.3. Tipo de credencial de Grafana

Entrar en:

**Administración → Tipos de credenciales → Añadir**:

Nombre:

```text
Credenciales Grafana
```

En configuración de entrada introducir:

```yaml
---
fields:
  - id: admin_password
    type: string
    label: Contraseña del administrador de Grafana
    secret: true

required:
  - admin_password
```

En configuración del inyector introducir:

```yaml
---
env:
  VAR_GRAFANA_ADMIN_PASSWORD: "{{ admin_password }}"
```

El playbook `instalar_grafana.yml` debe leer:

```yaml
var_grafana_admin_password: >-
  {{ lookup('ansible.builtin.env', 'VAR_GRAFANA_ADMIN_PASSWORD') }}
```

Guardar el tipo de credencial.

Después, entrar en **Recursos → Credenciales → Añadir**:

| Campo | Valor |
| --- | --- |
| Nombre | `Grafana - Nombre_Inventario` |
| Organización | `Nombre_Organización` |
| Tipo de credencial | `Credenciales Grafana` |
| Contraseña del administrador | Contraseña_Real |

El playbook exige al menos 8 caracteres, sin saltos de línea ni espacios al principio o al final.

Guardar la credencial.

### 7.4. Correspondencia de nombres

Los campos de entrada, las variables de entorno y las variables del playbook tienen funciones diferentes:

| Elemento | Ejemplo |
| --- | --- |
| Campo de la credencial | `admin_password` |
| Variable de entorno inyectada | `VAR_GRAFANA_ADMIN_PASSWORD` |
| Variable del playbook | `var_grafana_admin_password` |

El nombre del inyector debe coincidir exactamente con el utilizado en el `lookup`.

## 8. Crear las plantillas de trabajo

Entrar en:

**Recursos → Plantillas → Añadir → Plantilla de trabajo**:

Configuración común:

| Campo | Valor |
| --- | --- |
| Tipo de trabajo | Ejecutar |
| Inventario | `Nombre_Inventario` |
| Proyecto | `Nombre_Proyecto` |
| Entorno de ejecución | Entorno con las dependencias necesarias <br> *(AWX EE Latest)* |
| Elevación de privilegios | Activada |

Crear las siguientes plantillas:

| Nombre | Playbook | Credenciales |
| --- | --- | --- |
| `01 - Instalar Wazuh` | `monitorizacion/playbooks/instalar_wazuh.yml` | Máquina + Wazuh |
| `02 - Configurar Wazuh` | `monitorizacion/playbooks/configurar_wazuh.yml` | Máquina |
| `03 - Instalar Prometheus` | `monitorizacion/playbooks/instalar_prometheus.yml` | Máquina |
| `04 - Instalar Grafana` | `monitorizacion/playbooks/instalar_grafana.yml` | Máquina + Grafana |

Puede seleccionarse una credencial de Máquina y credenciales personalizadas de tipos diferentes en la misma plantilla.

**No duplicar las variables de los grupos** en las Variables adicionales de la plantilla.
*(Se machacaria la de plantilla encima de la de grupo)*

Si no aparece el playbook en el desplegable:

1. Comprobar que está guardado en Git.
2. Revisar la rama del proyecto.
3. Sincronizar el proyecto.
4. Comprobar la ruta relativa del archivo.
5. O escribir la ruta a mano y luego pulsar en sincronizar.

## 9. Crear el workflow

Entrar en:

**Recursos → Plantillas → Añadir → Plantilla de flujo de trabajo**:

Nombre:

```text
Nombre_WorkFlow
```

Inventario:

```text
Nombre_Inventario
```

Organización:

```text
Nombre_Organización
```

Guardar.

Iniciar el visualizador y añadir los nodos en este orden:

1. `01 - Instalar Wazuh`.
2. `02 - Configurar Wazuh`.
3. `03 - Instalar Prometheus`.
4. `04 - Instalar Grafana`.

Conectar cada nodo con el siguiente mediante:

```text
En caso de éxito / On Success
```

Si se utiliza un playbook para instalación de Docker, situarlo antes de `01 - Instalar Wazuh`.

Guardar.

Prometheus debe ejecutarse antes de Grafana, porque el instalador de Grafana comprueba la conexión con su fuente de datos.

Las credenciales se configuran en las plantillas de trabajo de cada nodo.

## 10. Ejecutar y comprobar

### 10.1. Antes de ejecutar

1. Sincronizar el proyecto Git.
2. Comprobar que el servidor pertenece a los tres grupos.
3. Revisar variables y credenciales.
4. Lanzar el workflow.

### 10.2. Wazuh

Acceso:

```text
https://10.10.3.100:5601
```

Usuario:

```text
admin
```

Contraseña: la guardada en la credencial de Wazuh para el administrador.

El mapeo previsto es:

```yaml
ports:
  - "5601:5601"
```

El primer puerto corresponde al servidor; el segundo, al interior del contenedor.

Comprobar también que se han aplicado el tema y la zona horaria.

### 10.3. Prometheus

Interfaz:

```text
http://10.10.3.100:9090
```

Estado de los targets:

```text
http://10.10.3.100:9090/targets
```

Los targets esperados deben aparecer como:

```text
UP
```

### 10.4. Grafana

Interfaz:

```text
http://10.10.3.100:3000
```

Usuario: el valor de `var_grafana_admin_user`.

Contraseña: la guardada en la credencial de Grafana.

La fuente de datos Prometheus se configura automáticamente con:

```yaml
name: Prometheus
uid: prometheus
url: http://prometheus:9090
```

El instalador comprueba la salud de Grafana y su conexión con Prometheus.

La importación de dashboards se realiza por separado. El dashboard utilizado durante las pruebas para Node Exporter fue `Node Exporter Full`, ID `1860`.

En caso de querer importar este dashboard:

**Dashboards -> New -> Import Dashboard**:

Introducir `1860` en el campo de `Find and import` y pulsar `Load`.

Tras esto, en la parte inferior pulsar el botón de `Import` y ya estaría importado el dashboard.

## 11. Añadir equipos a Prometheus

Node Exporter debe estar instalado en cada equipo Ubuntu y ser accesible desde Prometheus.

En las variables del grupo `prometheus-servers`, configurar:

```yaml
var_prometheus_departamentos:
  - nombre: Informatica
    equipos:
      - nombre: Equipo-01
        direccion: 10.10.3.101
        puerto: 9100

      - nombre: Equipo-02
        direccion: 10.10.3.102
        puerto: 9100

  - nombre: Administracion
    equipos:
      - nombre: Equipo-03
        direccion: 10.10.3.103
        puerto: 9100
```

**(Esto es un ejemplo, después en cada apartado `nombre` escribir el nombre del departamento e ir metiendo los equipos asociados a ese departamento)**

Después:

1. Guardar las variables.
2. Ejecutar `03 - Instalar Prometheus`.
3. Revisar `/targets`.

El departamento se utiliza como `job_name` y el nombre del equipo como etiqueta `nodename`.

La lista debe contener todos los equipos remotos que se desean monitorizar. La configuración se genera completa en cada ejecución.

**Añadir un target no instala Node Exporter en el remoto.**

## Extensión: Wazuh Active Response SSH

El bloqueo reversible de IPs y su persistencia se automatizan **fuera de los
playbooks de instalación y del Dashboard**. La auditoría, el despliegue de
agentes y la preparación del Manager son pasos independientes.

Ruta de documentación y controles de autorización:
[`docs/WAZUH_ACTIVE_RESPONSE.md`](docs/WAZUH_ACTIVE_RESPONSE.md).

**No incluir automáticamente la escritura del Manager en el workflow general**:
primero validar los agentes, después aprobar por separado la migración de
`defined-agent` a `local` y el reinicio controlado de `wazuh.manager`.
