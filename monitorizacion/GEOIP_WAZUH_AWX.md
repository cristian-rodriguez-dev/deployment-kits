# Wazuh GeoIP — Auditoría segura desde AWX

## Objetivo

Verificar, sin cambiar la instalación actual, que Wazuh Indexer dispone del pipeline usado para enriquecer alertas SSH con `data.srcip` → `GeoLocation`, y comprobar el número de documentos ya indexados con coordenadas. Opcionalmente, ejecutar una simulación **sin indexar** la IP pública de prueba `8.8.8.8`.

Este bloque **no instala** GeoIP, **no reconfigura** Filebeat, **no modifica** los mappings, **no reindexa** datos y **no reinicia** Wazuh.

## Archivos

- `monitorizacion/playbooks/auditar_geoip_wazuh.yml`: Job 15, solo auditoría.
- `monitorizacion/examples/variables_geoip_wazuh.yml`: variables compatibles con el inventario anterior.

## Requisitos

- AWX debe poder conectar por SSH con el servidor miembro de `wazuh-servers`.
- El Wazuh Indexer debe responder desde ese mismo host en `https://127.0.0.1:9200` (o en el puerto local configurado). El playbook **no conecta con una IP externa**.
- En el Job Template, usar la credencial de Máquina habitual **y** la credencial personalizada Wazuh que inyecta `VAR_WAZUH_ADMIN_PASSWORD`. La contraseña de la API de agentes (`VAR_WAZUH_API_PASSWORD`) no sirve para consultar el Indexer.
- Entorno de ejecución con `ansible-core` y módulo `ansible.builtin.uri`.

El Indexer utiliza TLS interno; por compatibilidad con los certificados del laboratorio se desactiva la validación TLS **únicamente** para la conexión a loopback `127.0.0.1`. No extrapolar esta excepción a conexiones de red ni a producción.

## Crear el Job 15

En AWX, sincronizar el proyecto Git y crear una plantilla:

| Campo | Valor |
|---|---|
| Nombre | `15 - Auditar Wazuh GeoIP` |
| Playbook | `monitorizacion/playbooks/auditar_geoip_wazuh.yml` |
| Inventario | El mismo del instalador Wazuh |
| Credenciales | Máquina + Wazuh (Indexer's admin) |
| Grupo objetivo | `wazuh-servers` |
| Elevación | No es necesaria para las llamadas HTTP locales |

Se recomienda comenzar sin variables adicionales: se usan `9200`, usuario `admin`, pipeline `filebeat-7.10.2-wazuh-alerts-pipeline`, consulta de documentos habilitada y simulación deshabilitada. Si el puerto o pipeline real no coinciden, corregir **solo** la variable correspondiente en AWX, tras consultar el estado actual; nunca modificar el pipeline para hacer que coincida con este ejemplo.

Variables opcionales:

```yaml
var_geoip_indexer_port: 9200
var_geoip_indexer_user: admin
var_geoip_pipeline_id: filebeat-7.10.2-wazuh-alerts-pipeline
var_geoip_count_alerts: true
var_geoip_simulate: false
```

## Primera ejecución: solo lectura

Debe finalizar con `changed=0` y `failed=0`. Revisar la tarea **Mostrar resumen de auditoria sin documentos ni credenciales**. No se imprimen documentos completos, IP de clientes, credenciales ni el contenido del pipeline.

Un conteo de `0` documentos geolocalizados **no implica un error**: si solo existen eventos de red privada `192.168.56.0/24`, puede no haber coordenadas públicas.

## Segunda ejecución opcional: simulación

Después de comprobar el primer resultado, si queremos probar el enriquecimiento del pipeline podemos habilitar:

```yaml
var_geoip_simulate: true
```

Este modo envía un documento sintético al endpoint `/_simulate`. OpenSearch devuelve el documento transformado **sin indexarlo**, pero sigue siendo una solicitud POST de prueba. La validación exige que la respuesta incluya `GeoLocation.location`; el país y sus coordenadas concretas dependen de la base GeoIP y no se fijan como una constante.

Si falla la simulación, el playbook no modifica el pipeline: se revisarán el esquema del documento que espera Filebeat y los procesadores instalados antes de preparar un playbook de configuración.

## Seguridad, reversión y siguiente bloque

El Job 15 no realiza escrituras persistentes: **no requiere rollback**. Todos los accesos a Indexer tienen `no_log: true`; los mensajes visibles sólo incluyen estado HTTP, número de procesadores y recuentos.

**No adjuntar** logs de `-vvvv`, definiciones completas del pipeline o respuestas HTTP con datos internos sin revisarlos antes.

Tras validarlo, preparar de manera independiente un **Job 16 — Adoptar y gestionar GeoIP**. Antes de habilitar cualquier escritura será necesario exportar el JSON real del pipeline a una ubicación protegida, comprobar cómo lo publica Filebeat y documentar los mappings/índices. Ese futuro Job 16 deberá usar modo auditoría por defecto y bloquear cambios hasta contar con backup, autorización expresa y recuperación probada.

Documentación del proyecto antiguo a mantener: `monitorizacion/README_DESPLIEGUE_AWX.md` (alta del Job 15) y el registro del estado GeoIP, sin mezclarlo con el repositorio `infrastructure-platform`.
