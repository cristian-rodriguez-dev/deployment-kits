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
    