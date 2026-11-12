# Traefik → Alloy → Loki → Wazuh (modo detección)

**Estado (12-11-2026):** probado `Traefik → Alloy → Loki` (peticiones `/dashboard`, HTTP 401, 2 entradas JSON en Loki); Wazuh 4.14.8 decodifica correctamente los campos JSON con `wazuh-logtest`. **Este paquete no se ha desplegado**: puente Loki → archivo, ingestión efectiva por Manager, nuevas reglas y reinicio siguen pendientes. No habilita Active Response web.

## Propósito y alcance

- Reutilizar Alloy y Loki ya desplegados. No configurar una segunda ingesta de Traefik en Alloy.
- Consultar **solo** logs `{app="traefik",namespace="kube-system"}` con Loki `/loki/api/v1/query_range`.
- Seleccionar respuestas 401/403/404/429 y solicitudes a rutas sensibles. No interpretar un único HTTP 401 como ataque.
- Emitir un objeto JSON por línea (campos permitidos) y añadir `integration=traefik_loki` y `EventId` para distinguirlos de otros JSON.
- Guardar cursor y huellas de eventos en SQLite. Reprocesamiento solapado para minimizar pérdidas por latencia; defensa frente a páginas truncadas; **entrega al menos una vez** (una interrupción entre escritura y confirmación podría duplicar un evento).
- Wazuh lee un directorio **dedicado** mediante bind mount de solo lectura en el contenedor. No escribir directamente en `/var/lib/docker/volumes/...` ni usar Docker socket en el puente.
- Las reglas detectan rutas sensibles y errores repetidos por `ClientHost`. Sin bloqueos automáticos ni modificaciones del bot de IA.

## Archivos

- `monitorizacion/integrations/traefik_wazuh_bridge/bridge.py`: puente Python estándar (Linux; no bibliotecas externas).
- `config.example.json`: ejemplo de configuración (**Loki 127.0.0.1:13100 únicamente para pruebas con port-forward**).
- `traefik-wazuh-bridge.service`: ejemplo de servicio systemd bajo usuario sin privilegios.
- `compose.override.example.yml`: ejemplo de bind mount de logs en el servicio `wazuh.manager` sin alterar otros volúmenes.
- `wazuh-localfile.xml`: entrada que añadir al `ossec.conf` real del Manager.
- `traefik_rules.xml`: reglas de Wazuh **para validar, no aplicadas**.
- `monitorizacion/manifests/traefik-access-logs.helmchartconfig.yaml`: versión declarativa de la configuración Traefik que ya está activa en K3s.
- `tests/test_traefik_wazuh_bridge.py`: pruebas offline, sin conexiones ni modificaciones de servicios.

## Comprobación local, segura y sin despliegue

Desde la raíz del repositorio donde se han extraído estos archivos:

```bash
python3 -m unittest discover -s tests -p 'test_traefik_wazuh_bridge.py' -v
python3 -m py_compile monitorizacion/integrations/traefik_wazuh_bridge/bridge.py
```

Para probar **solo la lectura de Loki** mediante el port-forward temporal ya utilizado en laboratorio:

```bash
sudo k3s kubectl -n logging port-forward pod/loki-0 13100:3100 --address 127.0.0.1
```

En **otro terminal**, copiar `config.example.json` a `/tmp/traefik-wazuh-bridge.json` y ejecutar:

```bash
python3 monitorizacion/integrations/traefik_wazuh_bridge/bridge.py \
  --config /tmp/traefik-wazuh-bridge.json --dry-run
```

`--dry-run` solo consulta Loki; no crea base de datos ni escribe registros para Wazuh. El número de eventos seleccionados puede incluir duplicados entre ventanas solapadas: **no** es una prueba de entrega ni de alertas Wazuh. Cerrar el port-forward tras la prueba. Para un servicio continuo debe existir una URL Loki estable, accesible y **no pública** desde el host (verificarla antes; NO utilizar port-forward como dependencia permanente).

## Activación planeada (NO ejecutar automáticamente)

1. Preparar un directorio restringido de eventos en el host, p. ej. `/srv/traefik-wazuh-bridge/events`, y un directorio separado de estado `/var/lib/traefik-wazuh-bridge`. Crear usuario de servicio sin acceso a Docker y aplicar permisos mínimos. Proteger el archivo de salida, ya que las rutas HTTP podrían contener datos sensibles incluso tras retirar los parámetros de consulta. No copiar a Git los eventos, el estado ni las credenciales.
2. Configurar `loki_url` con una dirección interna estable y accesible desde el host, preferentemente con TLS y controles de red. Validar `/ready` y una consulta `query_range` antes de arrancar el servicio.
3. Mediante **override documentado de Compose**, montar el directorio de eventos del host en el servicio `wazuh.manager` como `:ro` en `/var/ossec/logs/traefik-bridge`. La modificación del montaje recreará el contenedor Manager; exigir ventana de mantenimiento y backup del Compose original. Respetar todos los volúmenes actuales; nunca `down -v`.
4. Verificar que el archivo `traefik-access.jsonl` existe y es legible en el contenedor. Añadir el bloque `wazuh-localfile.xml` al `wazuh_manager.conf` persistente real (host: `single-node/config/wazuh_cluster/wazuh_manager.conf`); su montaje se realiza a través de `/wazuh-config-mount/etc/ossec.conf`. Revisar configuración XML completa y planificar reinicio controlado del Manager.
5. Copiar `traefik_rules.xml` a un fichero independiente bajo `/var/ossec/etc/rules/` (volumen persistente). **Antes**, comprobar colisiones en el rango de reglas `100600–100605`, validar XML y probar ejemplos con `wazuh-logtest`. La incorporación de reglas a la detección activa requiere recargar/reiniciar Wazuh Manager de forma controlada.
6. Activar servicio systemd del puente, monitorizar logs de su propia unidad, estado SQLite, tamaño del JSONL, Loki y Wazuh; validar emisión real de alertas de prueba. Desplegar/actualizar con Ansible/AWX en una etapa posterior; no mezclar este cambio con el piloto de Active Response SSH del agente `005`.
7. Incorporar el YAML de Traefik a la gestión declarativa por AWX, con estrategia de **adopción**: comparar primero contra `HelmChartConfig` del clúster; no aplicar si hubiera personalizaciones divergentes ni reinstalar Traefik desde cero.

### Riesgos y límites de la primera iteración

- **No es exactamente una vez**: ante crash de host inmediatamente después de escribir una línea puede emitirse otra vez al reiniciar. Conservar `EventId` para su investigación; no utilizar estos eventos como base de bloqueos automáticos sin validación adicional.
- **Fichero acotado**: el puente se detiene si el archivo sobrepasa `max_output_bytes` (50 MiB por defecto); antes de producción hace falta política de rotación sin pérdida y monitoring del servicio/volumen. No truncar a ciegas.
- Una consulta Loki saturada detiene el avance del cursor, en lugar de saltar eventos; ajustar ventana/límite y volumen según tráfico. Los registros retrasados más que `overlap_seconds` podrían no recogerse; hay que ajustar con datos reales de latencia.
- Los IPs `ClientHost` pueden corresponder a un proxy, un balanceador o una dirección privada. Confirmar cabeceras de origen y la cadena de proxies confiables antes de usar esos IPs para análisis o bloqueos. El script **no** confía en `X-Forwarded-For` por defecto.
- Los eventos se atribuyen al Manager (`000`) al procesarlos localmente, **no** al agente `005`; ajustar paneles y filtros del bot si se decide incluirlos.
- Si el usuario no ha solicitado expresamente desplegar, conservar las operaciones en modo de lectura/ensayo.
- Tras un cambio de Loki, Traefik, Wazuh o reglas, actualizar README/ADRs y el contrato de almacenamiento o seguridad aplicable **antes del commit**.

## Ejemplos para `wazuh-logtest` (cuando el archivo de reglas esté preparado)

Solicitud de ruta sensible: debe coincidir con la regla `100601`:

```json
{"integration":"traefik_loki","RequestMethod":"GET","RequestPath":"/.env","DownstreamStatus":404,"ClientHost":"192.0.2.10","RouterName":"dashboard"}
```

Una sola respuesta 401 debe quedar en regla base sin alerta alta:

```json
{"integration":"traefik_loki","RequestMethod":"GET","RequestPath":"/dashboard","DownstreamStatus":401,"ClientHost":"192.0.2.10","RouterName":"dashboard"}
```

Las reglas de correlación `100603` y `100605` necesitan varios eventos del mismo cliente en la ventana definida; una sola invocación no demuestra la frecuencia. Reservar las verificaciones de correlación para el entorno de prueba antes de activarlas.

## No hacer

- No conectar los logs de Traefik a la respuesta SSH `5763` ni ampliar `defined-agent=005`.
- No crear `DROP` automáticos por un 401/403 aislado.
- No publicar Loki en internet ni dar al puente acceso al Docker socket.
- No editar volúmenes internos Docker usando rutas de `_data` directamente.
- No confirmar una integración E2E a Wazuh sin haber verificado que el Manager consume el archivo y genera una alerta real.
