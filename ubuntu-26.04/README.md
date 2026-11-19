# Pilas Observabilidad · Ubuntu 26.04 · instalación limpia

Servidor Ubuntu 26.04 único: K3s + Traefik + AWX, Docker Compose para Wazuh, Prometheus, Node Exporter, cAdvisor, Grafana y Security Triage Bot (FastAPI, SMTP, Telegram), más Loki, Alloy y kube-state-metrics. Solo despliegue desde cero, sin adoptar equipos existentes ni migrar históricos. El código de Ubuntu 24.04 permanece en `monitorizacion/`; no usar `infrastructure-platform`.

El workflow central tiene **21 Jobs centrales (00 → 18, con 08B y 09A–09E; el 17 es remoto)**. Los clientes remotos 06 y 07 quedan fuera. El Job **17** prepara por separado el piloto SSH original en un agente autorizado, sin habilitar cortafuegos ni Active Response. Consulta `pilot-ssh/README.md`. Los Jobs 14, 15 y 16 añaden el bot, sus métricas y sus comprobaciones. El Job 18 recupera las 10 reglas originales de Grafana en modo stage (todas pausadas), sin contactos ni notificaciones hasta autorización explícita.

- Entrada: `awx/bootstrap/install-awx.sh --install` en un Ubuntu 26.04 limpio.
- AWX: crear proyecto, inventario monohost y credenciales. Importar `awx/workflow/workflow.json` con `awx/workflow/manage_workflow.py`.
- Accesos HTTPS: `awx`, `grafana`, `wazuh` y `prometheus` bajo `*.octavio.internal`, vía Traefik de K3s.
- Triage: proyecto versionado en `triage-bot/`. Las credenciales y datos se generan/almacenan **solo en el servidor destino**; consultar `awx/TRIAGE_CREDENCIAL.md`.
- Guía única: `../GUIA_UNICA_UBUNTU26.md`.

Las verificaciones estáticas no equivalen a un despliegue real en Ubuntu 26.04. Los valores privados de los contactos de Grafana, las protecciones específicas de Traefik y el piloto SSH Active Response requieren la configuración del manager y autorización correspondientes; los scripts y el servicio del agente ya se han recuperado; no se sustituyen por reglas nuevas inventadas. No activar envíos a destinatarios reales ni bloqueo de IPs como pruebas automáticas.

## Precisión GeoIP (Job 11)

El Job 11 conserva el pipeline original de Filebeat y solo añade el procesador `data.srcip → GeoLocation` si todavía no existe exactamente esa transformación. La prueba `_simulate` envía `message` con un evento JSON de ejemplo, como el pipeline de alertas del laboratorio antiguo; no indexa el evento ni modifica volúmenes. La reproducción exacta de las reglas, decodificadores y `ossec.conf` personalizados del manager antiguo sigue pendiente de una exportación saneada y una comprobación contra el entorno anterior.

## Configuración recuperada del Wazuh Manager (origen 24.04)

El archivo saneado confirma `sca.enabled=yes` con intervalo `12h`, `syscheck.disabled=no` con frecuencia `43200` segundos y `vulnerability-detection.enabled=yes`. El Job 02 aplica solo esos valores al fichero de configuración del Manager **antes del primer arranque**; crea un respaldo privado `.pre-manager-profile` y valida el resultado. En reintentos, solo verifica: si existe deriva, falla sin sobrescribir el despliegue activo ni reiniciar contenedores.

El Job 14 ya reproduce la integración `custom-security-triage` con nivel `10` y formato `json`. La activación de `ssh-block-pilot` (regla `5763`, `defined-agent`, tiempo `180`) sigue fuera del workflow central porque depende de un agente nuevo y una autorización independiente.

Las fuentes de logs de origen `active-responses.log`, `geoip-lab.log` y `/var/ossec/traefik-bridge/traefik-access.jsonl` se han identificado, pero no se instalan automáticamente: GeoIP-Lab es una fuente de laboratorio y el puente Traefik→Wazuh necesita desplegar antes su servicio, el montaje y las reglas específicas. La exportación seleccionada no incluye el texto de tres comandos `localfile`; no se han reconstruido arbitrariamente. **No declarar equivalencia completa de Wazuh 24.04 hasta validar esas integraciones.**

## Traefik → Alloy → Loki → Wazuh

El Job `09E` instala el puente Python original (hash SHA256 contrastado con el servidor 24.04), su servicio systemd, las reglas `100600–100605`, el `localfile` JSONL y el bind mount de solo lectura al Manager. Se coloca tras `09C`, cuando Loki ya está disponible. El Job `08` conserva logs de acceso JSON de Traefik y Alloy publica `app=traefik` a partir del nombre del contenedor, para mantener la consulta LogQL original. El Job 09E obtiene la dirección del gateway Loki del clúster en ejecución; no conserva direcciones ClusterIP antiguas ni expone un puerto al exterior. El estado SQLite y el JSONL persisten ante reintentos.

El Job 09E puede recrear **solo el contenedor Wazuh Manager** si cambia su configuración, reglas o montaje. No borra volúmenes ni datos; no activa Active Response web. El script solo selecciona eventos sospechosos: si no hay ninguno, el JSONL puede permanecer inalterado aunque el servicio esté sano. Antes de declarar E2E verificado, comprobar tráfico real en Loki, traducción a JSONL y las reglas Wazuh (las correlaciones 100603 y 100605 siguen sin validar).
