# Grafana Alerting — consolidación operativa 12/11/2026 (laboratorio antiguo)

## Estado verificado en la plataforma

- Grafana 13.2.3, 10 reglas en total; cinco originales conservadas y cinco incorporadas desde AWX (Jobs 25–26).
- Dos reglas K3s, Wazuh, Loki y bot: habilitadas, estado Normal al cerrar las pruebas.
- El target Prometheus `security-triage-bot` corresponde al **mismo contenedor principal** `security-triage-bot`, vía alias Docker `triage-metrics` en `triage-metrics-private`.
- Prueba real de parada del contenedor: se confirmó caída, estado `Firing`, recepción por Telegram directo y correo SMTP directo. Recuperación del servicio debe confirmarse operativa tras cada intervención.
- Último respaldo Job 24 `capture`: 10 reglas, 3 **integraciones contact point** según API; 1 árbol de políticas; 0 mute timings, 0 templates; sin escrituras.
- Respaldo privado en servidor (no Git): `/home/servidor/instalacion/grafana/backups/alerting/alerting-20261112T142334Z-1a2469f43f7f.json`; SHA256 bytes `9d36790e87e6f76c1595f3e519154a15d0cbd2ff38fad8293044bfa8fe3e198f`.

**No confundir:** 3 entradas en la API de contact points no necesariamente representan tres grupos visibles en la interfaz; las integraciones pueden agruparse bajo un mismo nombre.

## Límites de responsabilidad

| Origen | Recurso | Estado de gestión |
| --- | --- | --- |
| Antes de Jobs 25–26 | Cinco reglas originales (Host Down, High CPU, High Memory, High Disk Usage, LAB IA) | Conservadas; **no gestionadas declarativamente** por este bloque |
| Job 25 | Dos reglas K3s | Definiciones en `grafana_k3s_rules.py`; creación solo pausada, luego activadas manualmente |
| Job 26 | Tres reglas bot/Wazuh/Loki | Definiciones en `grafana_critical_services_rules.py`; creación solo pausada, luego activadas manualmente |
| UI Grafana | Routing de emergencia, plantillas de mensajes e integraciones Telegram/Email | Configuradas manualmente y respaldadas en snapshot privado; **no se reaprovisionan** |
| Servidor | SMTP de Grafana | Docker Compose + `.env` privado; **contraseña fuera de Git y AWX** |
| Job 24 | Snapshot de reglas/contact points/políticas | Respaldo sensible en el servidor (modo solo lectura) |

### Punto crítico: instalador histórico de Grafana

El archivo del repositorio `monitorizacion/templates/grafana/docker-compose.yml.j2` del **Job 05** no refleja todavía la configuración SMTP manual actual. Si relanzas ese instalador, su tarea de template puede **sobrescribir `docker-compose.yml`** y eliminar la configuración SMTP aplicada al laboratorio. **No ejecutar Job 05 de instalación/reconciliación** hasta incorporar SMTP de modo seguro en su template y revisar las dependencias, `.env`, persistencia y el diff. No cambiar el template ni el instalador de forma impulsiva durante esta fase de lectura.

## Job 27 recomendado: auditoría operativa de solo lectura

Se entrega `auditar_alerting_operativo_grafana.yml`, que hace estas comprobaciones:

1. Grafana accesible y base de datos `ok`.
2. Conteo de 10 reglas y 3 integraciones contact point (configurable para futuros cambios aprobados).
3. Las cinco reglas creadas desde AWX existen por UID, están **activadas** y sus títulos, pendientes, expresiones y umbral `> 0` coinciden con Git.
4. Existe un contact point con nombre `Infraestructura - Emergencias` con integraciones `telegram` y `email`, sin mostrar ajustes ni destinatarios.
5. Cuando Grafana exponga `notification_settings` en su API, confirma que la alerta del bot utiliza directamente ese contact point. Si la API **no expone** el campo, informa `NOT_EXPOSED_IN_API` (no finge haber comprobado el enrutamiento). Verificar routing en UI en ese caso.
6. Si detecta deriva, falla **después de mostrar solo UID y campos diferentes**, sin ningún cambio remoto sobre Grafana.

La auditoría usa exclusivamente `GET` de la API Grafana, aunque Ansible **crea/copía tres herramientas sin secretos** en el directorio privado `.alerting_operational_audit` del host. El primer Job puede mostrar `changed` por estas copias, sin implicar cambio de alertas.

> Nota: El API clásico `/api/v1/provisioning` sigue funcionando en Grafana 13 pero es heredado; para una refactorización futura hay API App Platform. La captura actual del Job 24 es el respaldo operativo, no un manifiesto completo reproducible en Git.

## Procedimiento recomendado

1. Integrar el contenido del paquete en la raíz de `deployment-kits`, **sin copiar cachés, backups ni credenciales**. Los dos archivos originales `grafana_k3s_rules.py` y `grafana_critical_services_rules.py` incluidos aquí corresponden al último paquete funcional del Bloque 06; revisar `git diff` si ya existen. No sobrescribir ajustes posteriores sin revisarlos.
2. `python -m unittest discover -s tests -p test_alerting_operational_audit.py -v` (usar `uv run --python 3.15 --no-project -m unittest ...` si Python no está en el PATH de Windows).
3. `git diff --check` y `git status --short`; versionar solo los archivos del bloque y documentación. Commit/push **sin datos de `.env`, `.env.mail` ni respaldos JSON**.
4. Sincronizar **Projects → Sync** en AWX (indispensable antes de lanzar nuevos playbooks).
5. Crear Job Template `27 - Verificar Grafana Alerting operativo` (si el número 27 está disponible), con `monitorizacion/playbooks/auditar_alerting_operativo_grafana.yml`, el mismo inventario/credenciales del Job 24. Usa las variables en `monitorizacion/examples/variables_auditoria_alerting_operativo.yml` (ajustar el nombre del contact point si es diferente).
6. Ejecutar; revisar **Mostrar resumen seguro del estado declarado** y `PLAY RECAP`. Se espera `Resultado: OK`, `Reglas: 10`, `Integraciones contact points: 3`, `Reglas nuevas verificadas: 5`, `Emergencias por: email, telegram`, `Ruta directa del bot: DIRECT_OK` o `NOT_EXPOSED_IN_API`, `Incidencias: ninguna`, `Consultas solo GET: True`.
7. Mantener Job 24 `capture` para respaldos antes/después de cambios reales, sin subir contenido sensible a Git.

## Qué aún no queda automatizado

- La **creación/activación/reconciliación de diez reglas** no es totalmente declarativa: Jobs 25/26 solo crean *nuevas reglas pausadas* y no sobrescriben existentes. Las cinco originales siguen bajo administración histórica/UI.
- Los contact points y las plantillas de correo/Telegram se adoptan de forma documental y se auditan parcialmente, sin guardar secretos en Git.
- El `UP` de `triage-metrics` vigila el endpoint del propio contenedor; no comprueba la lógica Gemini, colas o integraciones funcionales.
- El test de Telegram + email ha demostrado el envío real. Futuras pruebas deben evitar interrupciones adicionales en laboratorio de trabajo sin necesidad.

**Principio de seguridad:** observar y validar antes de automatizar escrituras. No ejecutar scripts de creación para "corregir" una deriva detectada.

## Corrección de la comparación PromQL — v2

La primera ejecución del Job 27 detectó `DRIFT_awx-k3s-crashloop` únicamente en
`promql`, mientras las otras cuatro reglas, ruta directa y contactos eran correctos.
El comparador v1 comparaba texto con `strip()` y consideraba distintas dos
consultas equivalentes si Grafana reformateaba saltos de línea o espacios.

La versión v2 compara **tokens PromQL** y conserva intactos los contenidos
de cadenas entrecomilladas. Es más tolerante con la presentación, sin
ignorar cambios de funciones, nombres de métricas, etiquetas, operadores o
valores numéricos. **No es una prueba de equivalencia semántica general**.

Repetir Job 27 después de sincronizar el proyecto: si indica `OK`, la
diferencia se debía únicamente al formato; si mantiene `DRIFT` en `promql`,
existe otra diferencia que debe inspeccionarse y aprobarse antes de cambiar
Git o Grafana. No ejecutar Jobs 25/26 en `apply` para reparar esta auditoría.

La corrección modifica solo el auditor y sus pruebas/documentación; no
cambia alertas, credenciales, SMTP, contactos ni el Job 05.
