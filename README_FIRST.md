# TODO LO RELATIVO AL DESPLIEGUE ESTÁ EN LA CARPETA: MONITORIZACIÓN

## OpenStack

## Proyectos interesantes de OpenStack

1. **Nova**

    - VMs / Instancias compute

2. **Neutron**

    - Redes / Security Groups

3. **Glance**

    - Imágenes Ubuntu

4. **Cinder**

    - Almacenamiento persistente

5. **Keystone**

    - Usuarios / Autenticación / Permisos

6. **Horizon**

    - Interfaz web administración

***Flujo esperado usando OpenStack???***

    Ejecuto un Workflow desde AWX

            ↓

    Creo VM en OpenStack

            ↓

    Esperar a que arranque la VM

            ↓

    Obtener su IP

            ↓

    Añadirla al inventario que se quiera

            ↓

    Instalar Docker

            ↓

    Desplegar Wazuh/Prometheus/Grafana

            ↓

    Configurar agentes

            ↓

    Añadir targets a Prometheus
    

## Especializado en Ubuntu -> OpenStack - Sunbeam

Mete los componentes de OpenStack en contenedores, la instalación el SO de tu servidor.

Para actualizar sirve con solo actualizar las imágenes de los contenedores en los K8s.

## Instalación (Revisarlo)

0. Actualizar el sistema

        sudo apt update -y

1. Instalar el componente OpenStack via Snap

(Descarga las herramientas oficiales de despliegue)

        sudo snap install openstack

2. Preparación de nodo

Generar y ejecutar script de configuración de repositorios, dependencias y permisos. *(Incluido sudo sin contraseña para el usuario actual)*.

        sunbeam prepare-node-script --bootstrap | bash -x
        newgrp snap_daemon

3. Inicializar el clúster

Prepara el entorno de demostración, con usuario, proyecto, redes y recursos básicos, y guarda las variables de autenticación en demo-openrc

        sunbeam cluster bootstrap --accept-defaults --role control,compute,storage

        *Nota: (--accept-defaults utiliza la configuración por defecto)*.

4. Configurar la nube

Generar los rangos de red internos y el archivo de credenciales de acceso.

        sunbeam configure --accept-defaults --openrc demo-openrc

5. Lanzar primera instancia de prueba

Verificar que todo funciona, levantando una pequeña VM.

        sunbeam launch ubuntu --name servidor-pruebas

6. Acceso a la interfaz gráfica (Dashboard Horizon)

Introducir la IP que monstró el instalador para cargar el panel.

Usuario por defecto: admin

Consultar credenciales de acceso generadas: *(Por defecto el siguiente directorio)*

        cat ~/devstack/demo-openrc

7. Cargar las credenciales

        source ~/devstack/demo-openrc

8. Verificar acceso

        openstack service list

## Comandos útiles

Imágenes disponibles

        openstack image list

Plantillas

        openstack flavor list

Redes

        openstack network list
