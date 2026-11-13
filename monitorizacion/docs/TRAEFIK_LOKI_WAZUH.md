# Traefik → Alloy → Loki → Wazuh (modo detección)

**Estado validado (13-11-2026):** Traefik 3.7.13 genera access logs JSON; Alloy los entrega a Loki y se han registrado 3/3 peticiones HTTPS 401 en una prueba controlada. El puente Python funciona como servicio `traefik-wazuh-bridge` (activo y habilitado), almacena cursor SQLite y escribe JSONL filtrado. El Manager Wazuh original (proyecto Compose `wazuh`) tiene un bind mount de solo lectura a `/var/ossec/traefik-bridge`, lee `traefik-access.jsonl` y carga las reglas `100600–100605`. Una entrada sintética a `/.env` añadida al JSONL produjo una **alerta real 100601 de nivel 7**. La correlación `100603` (8 eventos/120 s) y `100605` (15 eventos/120 s) **no se han probado extremo a extremo**. No hay Active Response para HTTP; el piloto SSH del agente `005` sigue separado. **Automatización Ansible/AWX de esta nueva integración: pendiente**.

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
- `traefik_rules.xml`: reglas Wazuh instaladas y validadas en el Manager; validar diferencias antes de cualquier actualización.
- `monitorizacion/manifests/traefik-access-logs.helmchartconfig.yaml`: versión declarativa del HelmChartConfig activo en K3s (Chart 40.1.5+up40.1.0).
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

## Despliegue manual validado y requisitos para automatizar

1. Preparar un directorio restringido de eventos en el host, p. ej. `/srv/traefik-wazuh-bridge/events`, y un directorio separado de estado `/var/lib/traefik-wazuh-bridge`. Crear usuario de servicio sin acceso a Docker y aplicar permisos mínimos. Proteger el archivo de salida, ya que las rutas HTTP podrían contener datos sensibles incluso tras retirar los parámetros de consulta. No copiar a Git los eventos, el estado ni las credenciales.
2. Configurar `loki_url` con una dirección interna estable y accesible desde el host, preferentemente con TLS y controles de red. Validar `/ready` y una consulta `query_range` antes de arrancar el servicio.
3. El override `compose.traefik-bridge.yml` ya monta `/srv/traefik-wazuh-bridge/events` en `/var/ossec/traefik-bridge` como solo lectura. En la automatización, **fijar `-p wazuh`** y los tres archivos `docker-compose.yml`, `compose.credentials.yml` y `compose.traefik-bridge.yml`; nunca depender del nombre del directorio `single-node` como proyecto. En un intento anterior sin `-p`, Docker creó el proyecto erróneo `single-node`, con un contenedor `Created` y volúmenes nuevos; se deben revisar y limpiar **solo** esos recursos verificados, sin `prune` ni `down -v`. El Manager original `wazuh` siguió operativo y luego fue recreado correctamente con `-p wazuh` y sus volúmenes originales.
4. Archivo de eventos validado como legible en el contenedor; el Manager tiene activo el `<localfile>` para `/var/ossec/traefik-bridge/traefik-access.jsonl`. Su fichero de origen es `single-node/config/wazuh_cluster/wazuh_manager.conf`, que contiene **dos bloques `<ossec_config>`**; automatizar la inserción XML sin dar por hecho que solo hay uno, con backup y comparación exacta. No repetir el reinicio si no hay cambios.
5. `traefik_rules.xml` ya está copiado a `/var/ossec/etc/rules/traefik_rules.xml` (volumen persistente). No se encontraron colisiones de IDs `100600–100605`; `wazuh-analysisd -t` pasó y `wazuh-logtest` coincidió con la regla `100601` (nivel 7). Adoptar archivos existentes antes de imponer cambios; cambios reales de reglas exigen control de versiones y reinicio autorizado.
6. `traefik-wazuh-bridge.service` ya está activo/habilitado como `traefik-wazuh` sin acceso al Docker socket. Escribe en `/srv/traefik-wazuh-bridge/events/traefik-access.jsonl` y mantiene SQLite en `/var/lib/traefik-wazuh-bridge/state.sqlite`. La URL Loki de laboratorio es `http://10.43.213.25:3100`, pero **no fijarla en el repositorio como endpoint permanente**; resolverla/validarla mediante el servicio Kubernetes. Vigilar errores de systemd, disponibilidad Loki y tamaño del JSONL.
7. Próximo bloque: Ansible/AWX con estrategia **adoptar → comparar → gestionar**; inicialmente sin escrituras ni recreaciones, después con aprobación explícita para cambios del Manager. Incorporar el YAML de Traefik a la gestión declarativa sin reinstalar Traefik ni pisar personalizaciones. Sincronizar README, procedimientos de recuperación y documentación de red/seguridad/almacenamiento antes del commit.

### Riesgos y límites de la primera iteración

- **No es exactamente una vez**: ante crash de host inmediatamente después de escribir una línea puede emitirse otra vez al reiniciar. Conservar `EventId` para su investigación; no utilizar estos eventos como base de bloqueos automáticos sin validación adicional.
- **Fichero acotado**: el puente se detiene si el archivo sobrepasa `max_output_bytes` (50 MiB por defecto); antes de producción hace falta política de rotación sin pérdida y monitoring del servicio/volumen. No truncar a ciegas.
- Una consulta Loki saturada detiene el avance del cursor, en lugar de saltar eventos; ajustar ventana/límite y volumen según tráfico. Los registros retrasados más que `overlap_seconds` podrían no recogerse; hay que ajustar con datos reales de latencia.
- Los IPs `ClientHost` pueden corresponder a un proxy, un balanceador o una dirección privada. Confirmar cabeceras de origen y la cadena de proxies confiables antes de usar esos IPs para análisis o bloqueos. El script **no** confía en `X-Forwarded-For` por defecto.
- Los eventos se atribuyen al Manager (`000`) al procesarlos localmente, **no** al agente `005`; ajustar paneles y filtros del bot si se decide incluirlos.
- Si el usuario no ha solicitado expresamente desplegar, conservar las operaciones en modo de lectura/ensayo.
- Tras un cambio de Loki, Traefik, Wazuh o reglas, actualizar README/ADRs y el contrato de almacenamiento o seguridad aplicable **antes del commit**.

## Ejemplos reproducibles para `wazuh-logtest`

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
- No confundir la alerta real `100601` desde un evento JSONL sintético con la validación de correlaciones HTTP `100603`/`100605`, aún pendientes.
