# AWX: organizaciones, equipos y permisos

Guía complementaria al README de despliegue de monitorización. Explica cómo organizar las personas que utilizan AWX y controlar qué pueden consultar, ejecutar y administrar.

## Índice

1. [Conceptos](#1-conceptos)
2. [Crear una organización](#2-crear-una-organización)
3. [Crear usuarios](#3-crear-usuarios)
4. [Crear equipos y añadir miembros](#4-crear-equipos-y-añadir-miembros)
5. [Qué significa cada permiso](#5-qué-significa-cada-permiso)
6. [Asignar permisos a los recursos](#6-asignar-permisos-a-los-recursos)
7. [Ejemplo para monitorización](#7-ejemplo-para-monitorización)
8. [Comprobar y retirar permisos](#8-comprobar-y-retirar-permisos)

## 1. Conceptos

| Concepto | Qué representa | Ejemplo |
| --- | --- | --- |
| Organización | Agrupa usuarios o grupos de usuarios. | `Octavio` |
| Usuario de AWX | Persona que inicia sesión en la web de AWX. | `Cristian` |
| Equipo / Team | Conjunto de usuarios al que se asignan permisos. | `Octavio-Sistemas` |
| Inventario | Máquinas que se pueden gestionar. | `Hosts` |
| Grupo del inventario | Máquinas usadas por los playbooks. | `wazuh-servers` |
| Rol | Permiso asignado sobre un recurso a un usuario o grupo de usuarios. | `Execute` sobre un workflow |
| Credencial de Máquina | Datos que usa Ansible para entrar por SSH y elevar privilegios. | `SSH - Nombre_Servidor` |

**Un equipo de usuarios y un grupo del inventario son cosas diferentes.**

- Los usuarios se añaden a **Equipos / Teams**.
- Las máquinas se añaden a **Inventarios → Grupos**.

## 2. Crear una organización

Realizar la configuración inicial con una cuenta administradora del sistema AWX.

1. Entrar en **Acceso → Organizaciones**.
2. Pulsar **Añadir**.
3. Introducir un nombre y una descripción.
4. Guardar.
***(Puedes ponerle por asegurar: Entorno de ejecución -> AWX EE Latest)***

Ejemplo:

```yaml
# Ejemplo descriptivo de los campos del formulario.
nombre: Octavio
descripcion: Automatización y monitorización de infraestructura
```

Si la organización `Octavio` ya existe, no hace falta crear otra por cada playbook o servicio.

### Añadir miembros y administradores

1. Abrir la organización.
2. Entrar en **Acceso**.
3. Pulsar **Añadir**.
4. Seleccionar el usuario.
5. Elegir el rol y guardar.

## 3. Crear usuarios

1. Entrar en **Acceso → Usuarios → Añadir**.
2. Introducir nombre de usuario, datos personales y contraseña para una cuenta local.
3. Seleccionar un usuario normal para el trabajo habitual.
4. Guardar.
5. Añadirlo a la organización y a su equipo.

| Tipo de cuenta | Alcance |
| --- | --- |
| Usuario normal | Accede según los roles que recibe. |
| Administrador del sistema / Superuser | Control global de AWX. |
| Auditor del sistema | Consultor global |

No escribir las contraseñas de las cuentas en el README ni en Git.

## 4. Crear equipos y añadir miembros

Ejemplo:

```yaml
organizacion: Octavio
equipos:
  - nombre: Monitorizacion-Administradores
    finalidad: Mantener la configuración del despliegue
  - nombre: Monitorizacion-Operadores
    finalidad: Ejecutar el workflow preparado
  - nombre: Monitorizacion-Consulta
    finalidad: Revisar los recursos y resultados autorizados
```

### Crear cada equipo

1. Entrar en **Acceso → Equipos → Añadir**.
2. Introducir nombre y descripción.
3. Seleccionar la organización `Octavio`.
4. Guardar.

### Añadir personas

1. Abrir el equipo.
2. Entrar en **Acceso**.
3. Pulsar **Añadir**.
4. Seleccionar las personas y guardar.

Añadir a una persona al equipo le permite recibir los permisos asignados a ese equipo. **El nombre del equipo no concede permisos por sí mismo**

Los permisos sobre los recursos se asignan en el siguiente paso.

## 5. Qué significa cada permiso

Los roles disponibles dependen del recurso seleccionado.

| Rol | Uso habitual |
| --- | --- |
| `Lectura` | Consultar el recurso. |
| `Ejecutar` | Ejecutar una plantilla de trabajo o workflow. |
| `Admin` | Administrar el recurso y sus accesos dentro del alcance concedido. |
| `Admin_Sección_Concreta` | Administrar solo una sección del recusor, pudiendo ser proyectos, inventarios, credenciales, etc. |
| `Aprobar` | Ejecutar acciones ad hoc sobre un inventario. No es necesario para lanzar un workflow preparado. |

Los permisos se acumulan: una persona puede recibirlos directamente, por sus equipos y por roles de mayor alcance. Un rol `Read` no anula otro rol `Admin` que ya tenga.

## 6. Asignar permisos a los recursos

Procedimiento general:

1. Abrir el recurso: inventario, proyecto, credencial, plantilla o workflow.
2. Entrar en **Acceso / Acceso de equipos**.
3. Pulsar **Añadir**.
4. Elegir el usuario o equipo.
5. Seleccionar el rol o roles que se desee para ese recurso.
6. Revisar y guardar.

Para un workflow ya preparado, el operador puede ejecutarlo con el permiso de ejecución del workflow sin recibir automáticamente permiso para lanzar por separado todas las plantillas que contiene.

Si también debe lanzar una plantilla individual, por ejemplo `03 - Instalar Prometheus`, asignarle `Execute` sobre esa plantilla.

## 7. Ejemplo para monitorización

### 7.1. Responsables de administración

Hay dos posibilidades:

- Si deben gestionar toda `Octavio`, asignar administración de organización a las personas responsables.
- Si solo deben mantener monitorización, asignar permisos sobre sus recursos concretos, sin convertirlos en administradores globales.

Propuesta sobre recursos ya creados para `Monitorizacion-Administradores`:

| Recurso | Rol propuesto |
| --- | --- |
| Proyecto `Nombre_Proyecto` | `Admin` |
| Inventario `Nombre_Inventario` | `Admin` |
| Cuatro plantillas de trabajo | `Admin` |
| Workflow `Desplegar monitorización` | `Admin` |
| Credenciales necesarias | `Admin` solo si también gestionan sus valores y accesos |

Administrar recursos existentes no garantiza poder crear cualquier recurso nuevo ni tipos de credenciales personalizados. Esas tareas pueden requerir intervención del administrador de la organización o del sistema, según el recurso y la versión.

### 7.2. Operadores

Propuesta para `Monitorizacion-Operadores`:

| Recurso | Rol propuesto |
| --- | --- |
| Workflow `Desplegar monitorización` | `Ejecutar` |
| Plantillas individuales | `Ejecutar` solo si necesitan lanzarlas por separado |
| Inventario y proyecto | `Lectura` si necesitan consultarlos |
| Credenciales | Sin asignación directa para el uso de plantillas fijas |

No conceder administración del inventario si solo deben ejecutar trabajos: editar hosts o variables puede cambiar el destino y el comportamiento del despliegue.

### 7.3. Consulta

Propuesta para `Monitorizacion-Consulta`:

1. Asignar `Lectura` al workflow y a las plantillas que necesitan revisar.
2. Añadir `Lectura` al proyecto e inventario cuando corresponda.
3. Verificar con una cuenta de prueba qué resultados y trabajos puede consultar.
4. No conceder `Ejecutar`, `Admin` (ni `Ad Hoc` que puede aparecer en alguna versión).

Si necesita consultar todos los recursos de la organización, valorar el rol de auditor de organización. El auditor del sistema tiene un alcance mayor y no es equivalente.

### 7.4. Grupos del inventario

Los grupos que ya utilizan los playbooks siguen siendo:

Ejemplo:

```yaml
inventario: Monitorización
host: ansible_server
grupos:
  - wazuh-servers
  - prometheus-servers
  - grafana-servers
```

Estos grupos seleccionan máquinas y proporcionan variables. No sirven para agrupar personas ni concederles roles de AWX.

## 8. Comprobar y retirar permisos

### Comprobar

Usar una cuenta normal de prueba o una sesión privada con la cuenta del usuario. No comprobar restricciones con la cuenta superusuario, porque puede acceder a todos los recursos.

| Perfil | Comprobación esperada |
| --- | --- |
| Administrador de monitorización | Puede modificar los recursos autorizados. |
| Operador | Puede ejecutar el workflow; no puede editar sus nodos o credenciales si no se le han concedido esos permisos. |
| Consulta | Puede consultar los recursos concedidos, pero no lanzarlos ni modificarlos. |

Probar primero la ejecución en un inventario de pruebas: ejecutar el workflow real puede modificar los servidores.

### Retirar permisos

1. Abrir el recurso y retirar el rol directo que ya no corresponda.
2. Revisar los equipos a los que pertenece el usuario.
3. Retirar su pertenencia al equipo si ya no debe recibir sus permisos.
4. Comprobar si mantiene roles de organización o sistema.
5. Verificar el acceso efectivo con su cuenta.

Quitar un rol directo no elimina el mismo permiso si se sigue heredando de un equipo u otro ámbito. No dar por supuesto que mover recursos o cambiar pertenencias limpia todas las asignaciones anteriores.
***(Mejor dar siempre los permisos del mismo modo)***
