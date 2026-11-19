# Pilas Observabilidad · Ubuntu Server 26.04 · guía única

**19/11/2026.** Preparación para instalación limpia del lunes 23/11/2026. Un único servidor físico, AWX y los servicios centrales en el mismo host. Se preserva `monitorizacion/` de Ubuntu 24.04. Sin copia de históricos, sin instalar servicios previstos pero no operativos y **sin ejecutar nada en producción desde esta entrega**.

## 1. Windows: incorporar el paquete a `deployment-kits`

En PowerShell, desde el repositorio actual (no desde `infrastructure-platform`):

```powershell
cd C:\deployment-kits
$bk = "$env:USERPROFILE\Downloads\ubuntu26-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
Copy-Item .\ubuntu-26.04 $bk -Recurse
Expand-Archive "$env:USERPROFILE\Downloads\deployment-kits-ubuntu26-triage-integrado.zip" -DestinationPath . -Force
uv run --no-project --python 3.12 --with pytest --with pyyaml --with jinja2 -m pytest -q .\ubuntu-26.04\tests
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\workflow\manage_workflow.py --plan --repo-root .
git status --short
```

El ZIP se **superpone** a `C:\deployment-kits`; no reemplaza `monitorizacion/`. Comprueba `git diff --check` y `git status` antes de subir los archivos a la **misma rama Git que AWX leerá**. Los archivos `ubuntu-26.04/triage-bot/` incluyen el código original del bot y notificadores sin SQLite, `.env` ni contraseñas. No subas el ZIP original del servidor antiguo a Git. Si tu remoto es privado, prepara credencial SCM en AWX antes de sincronizar.

## 2. Ubuntu limpio: instalar K3s, Traefik integrado y AWX

Desde PowerShell (sustituye usuario e IP):

```powershell
scp .\ubuntu-26.04\awx\bootstrap\install-awx.sh usuario@IP_SERVIDOR:/home/usuario/
scp .\ubuntu-26.04\awx\bootstrap\awx-bootstrap.env.example usuario@IP_SERVIDOR:/home/usuario/awx-bootstrap.env
```

En el servidor Ubuntu 26.04 con SSH y sudo:

```bash
chmod 600 ~/awx-bootstrap.env
bash -n ~/install-awx.sh
sudo bash ~/install-awx.sh --check
sudo bash ~/install-awx.sh --install
sudo bash ~/install-awx.sh --status
sudo k3s kubectl -n kube-system rollout status deployment/traefik
```

Para reintentar **solo el bootstrap instalado por este script**, `sudo bash ~/install-awx.sh --resume`. Nunca uses `--uninstall-lab` en producción: es destructivo. Consulta la contraseña inicial de AWX en el propio servidor con `sudo k3s kubectl -n awx get secret awx-admin-password -o jsonpath='{.data.password}' | base64 -d`.

## 3. Inventario, credenciales y host único en AWX

En Windows abre un túnel (mantén la consola):

```powershell
ssh -t -L 18080:127.0.0.1:18080 usuario@IP_SERVIDOR "sudo k3s kubectl -n awx port-forward svc/awx-service 18080:80"
```

En `http://127.0.0.1:18080`, crea un token de AWX y estas credenciales:

- `SSH - Ubuntu 26.04`: Machine, SSH/sudo.
- `Wazuh - Credenciales 26.04`: tipo personalizado que inyecta `VAR_WAZUH_ADMIN_PASSWORD` y `VAR_WAZUH_API_PASSWORD` al entorno de los Jobs.
- `Grafana - Admin 26.04`: tipo personalizado que inyecta `VAR_GRAFANA_ADMIN_PASSWORD`.
- `Triage - Secretos 26.04`: crear exactamente como indica `ubuntu-26.04/awx/TRIAGE_CREDENCIAL.md`. Tiene tokens **distintos** de webhook y métricas, más un usuario/contraseña de solo lectura para el Indexer; correo, Telegram y Gemini son opcionales y se activan explícitamente.

Copiar el archivo de variables fuera del repositorio:

```powershell
Copy-Item .\ubuntu-26.04\examples\variables_host_central.yml.example "$env:USERPROFILE\Downloads\host-central-26.yml"
notepad "$env:USERPROFILE\Downloads\host-central-26.yml"
```

Rellena el hostname real de K3s, dirección del único host, departamento, rutas y credenciales que **no** deben ir en YAML. Si se deben recuperar correo y Telegram como en el servidor antiguo, configura `var_triage_mail_enabled: true`, `var_triage_telegram_enabled: true`, `var_triage_mail_from`, `var_triage_mail_to`, `var_triage_smtp_host`, `var_triage_smtp_user` y los valores privados correspondientes en la credencial AWX; no pegues el `.env` antiguo. Los envíos estarán **deshabilitados por defecto**, por seguridad. `AI_ENABLED` y la transmisión de datos reales a Gemini también permanecen deshabilitados hasta autorización explícita.

```powershell
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\setup_inventory.py --url http://127.0.0.1:18080 --scm-url URL_REAL_GIT --branch RAMA_REAL --host HOST_REAL --host-ip IP_SERVIDOR --vars-file "$env:USERPROFILE\Downloads\host-central-26.yml" --apply
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\workflow\manage_workflow.py --apply --url http://127.0.0.1:18080 --repo-root .
```

Los scripts solicitan el token de forma oculta cuando no existe `AWX_TOKEN`. Un solo host debe pertenecer a los cinco grupos centrales: `docker_servers`, `wazuh-servers`, `prometheus-servers`, `grafana-servers`, `k3s-servers`; `monitoring-agents` permanece separado. Los scripts crean/importan recursos pero **no ejecutan** Jobs.

## 4. DNS y certificados antes del Job 12

Debes disponer de A records internos a la IP del servidor para `awx.octavio.internal`, `grafana.octavio.internal`, `wazuh.octavio.internal`, `prometheus.octavio.internal`; certificado de la CA interna que cubra los cuatro nombres y fichero htpasswd para Prometheus. Copia certificado, clave privada y htpasswd por canal seguro **solo al servidor**, con estas rutas configuradas en el inventario:

```bash
sudo install -d -m 0700 /etc/deployment-kits/tls
sudo install -m 0644 /tmp/octavio.internal.crt /etc/deployment-kits/tls/octavio.internal.crt
sudo install -m 0600 /tmp/octavio.internal.key /etc/deployment-kits/tls/octavio.internal.key
sudo install -m 0600 /tmp/prometheus-users /etc/deployment-kits/tls/prometheus-users
```

El certificado TLS/clave y htpasswd **no** están en el ZIP. Si faltan, el Job 12 fallará deliberadamente y tendrás que reanudar desde ese paso.

## 5. Ejecutar el workflow central de 21 Jobs

En AWX, lanza manualmente `26.04 - Produccion un host`:

`00 → 01 → 02 → 03 → 04 → 05 → 08 → 08B → 09A → 09B → 09D → 09C → 09E → 10 → 11 → 12 → 13 → 14 → 15 → 16`.

Los Jobs 06 y 07 (clientes remotos) y el 17 (preparación del piloto SSH) quedan fuera del workflow central. Todos los enlaces del central son **por éxito**; un Job fallido detiene la secuencia.

- `14`: usa el **código original del ZIP** en `/opt/security-triage-bot`, crea un usuario Wazuh Indexer con lectura limitada, configura Wazuh Integrator para nivel ≥10, crea una base SQLite nueva y monta tres contenedores (bot, SMTP, Telegram) con credenciales privadas. Wazuh Manager puede recrearse **una sola vez cuando cambie su integración**; no se borran volúmenes.
- `15`: crea el target `security-triage-bot` en Prometheus con un token Bearer de lectura, mediante una red Docker interna y un fichero `scrape.d`, manteniendo la TSDB existente.
- `16`: verifica salud del bot, endpoint autenticado, presencia del integrador y `up=1` en Prometheus, **sin simular un incidente crítico ni enviar correos o Telegram reales**.

Si el código del bot cambia, Compose reconstruirá la imagen y recreará los contenedores que corresponda; los datos persisten en `triage-data`. Nunca uses `docker compose down -v`, `prune`, ni borres PVC o certificados para resolver un fallo.

Para preparar una reanudación desde un Job sin ejecutarla automáticamente:

```powershell
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\workflow\manage_workflow.py --apply --url http://127.0.0.1:18080 --repo-root . --resume-from 14
```

Luego lanza en AWX el workflow creado con nombre `- Reanudar 14`. No cambies credenciales entre reintentos de una cuenta Indexer ya creada: si difieren, el Job falla por seguridad.

## 6. Verificación final y fuentes todavía pendientes

En el servidor, después del workflow:

```bash
sudo k3s kubectl get nodes
sudo k3s kubectl -n logging get pods,pvc
sudo docker ps
curl -fsS http://127.0.0.1:18080/health
curl -fsS http://IP_REAL_DEL_SERVIDOR:9090/-/ready
curl -fsS http://127.0.0.1:3000/api/health
```

En Prometheus (escuchando en `var_prometheus_bind_address`) consulta `up{job="security-triage-bot"}`. Debe valer `1`. El Job 09E instala el puente original Traefik → Alloy → Loki → Wazuh con montaje JSONL en solo lectura, reglas 100600–100605 y persistencia de cursor SQLite. Puede recrear únicamente el Wazuh Manager para aplicar su montaje y localfile, conservando sus volúmenes. No activa respuesta automática HTTP. El Job 13 verifica el núcleo de métricas, Loki, Grafana y Wazuh; el Job 16 añade verificaciones del bot. **Pendientes de una prueba real en Ubuntu 26.04:** recepción de un evento Wazuh de prueba, enriquecimiento de una consulta Indexer/Prometheus/Loki asociada a evento, entrega SMTP/Telegram solo a destinatarios de prueba expresamente autorizados, integración Grafana Alerting y flujo completo de Alloy.

Se han recuperado 10 reglas originales de Grafana Alerting que se importan inicialmente pausadas (Job 18); 3 contactos y políticas están documentados pero necesitan ajustes privados y autorización para enviarse. El piloto SSH original está preparado como Job 17 remoto independiente, sin habilitar bloqueos automáticos. GeoIP (Job 11) requiere una validación real de extremo a extremo. El puente de acceso externo al dashboard del bot también se conserva como fuente opcional, pero no se instala automáticamente sin determinar su autenticación real. **No se ha probado ni ejecutado este workflow completo en un servidor Ubuntu 26.04 desde aquí.**

**Reversión:** conserva el backup de Windows `$bk`, vuelve a la rama anterior si necesitas revertir código y examina las copias `*.bak` del `wazuh_manager.conf` generadas por Ansible antes de restaurar la configuración del manager. Deshabilitar una integración no requiere borrar la base SQLite. Protege los secretos y evalúa cada paso que recree contenedores.

### Verificación del puente Traefik tras el Job 09E

```bash
systemctl is-active traefik-wazuh-bridge.service
sudo -u traefik-wazuh /usr/bin/python3 /opt/traefik-wazuh-bridge/bridge.py --config /etc/traefik-wazuh-bridge/config.json --once --dry-run
sudo docker exec wazuh-wazuh.manager-1 test -r /var/ossec/traefik-bridge/traefik-access.jsonl
sudo docker exec wazuh-wazuh.manager-1 sha256sum /var/ossec/etc/rules/traefik_rules.xml
```

El comando `--dry-run` consulta Loki sin escribir en SQLite ni JSONL. Un resultado `scanned=0 selected=0` puede indicar que no ha habido accesos recientes; por sí solo no prueba fallo. Comprueba después con eventos de prueba autorizados que el JSONL se incrementa y Wazuh genera la regla esperada. No hacer pruebas de bloqueo web.
