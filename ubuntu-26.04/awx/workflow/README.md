# Workflow central · Ubuntu 26.04

Secuencia de **21 Jobs** encadenados solo por éxito:

`00 → 01 → 02 → 03 → 04 → 05 → 08 → 08B → 09A → 09B → 09D → 09C → 09E → 10 → 11 → 12 → 13 → 14 → 15 → 16 → 18`.

Los clientes remotos `06`, `07` y `17` son plantillas separadas; el `17` solo prepara los archivos del piloto SSH en el cliente elegido, sin activar bloqueos. Consulta `../../pilot-ssh/README.md`. El bot original está en `ubuntu-26.04/triage-bot/`, sin `.env`, SQLite ni secretos. Job 14 prepara el RO Indexer, despliega el bot/notificadores y configura la integración Wazuh; Job 15 enlaza las métricas privadas a Prometheus; Job 16 valida la salud y el target sin emitir alertas sintéticas ni notificaciones.

El Job 18 se ejecuta por defecto en modo `stage`: crea o conserva 10 reglas pausadas, sin crear contactos ni cambiar políticas. Para activar notificaciones tras recuperar datos privados, consulta `../../alerting/README.md`.

Crea las credenciales `SSH - Ubuntu 26.04`, `Wazuh - Credenciales 26.04`, `Grafana - Admin 26.04` y `Triage - Secretos 26.04` antes de importar. Consulta `../TRIAGE_CREDENCIAL.md`.

```powershell
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\workflow\manage_workflow.py --plan --repo-root C:\deployment-kits
$env:AWX_TOKEN = Read-Host 'Token AWX'
uv run --no-project --python 3.12 .\ubuntu-26.04\awx\workflow\manage_workflow.py --apply --url http://127.0.0.1:18080 --repo-root C:\deployment-kits
Remove-Item Env:AWX_TOKEN
```

El script **solo importa**, nunca lanza Jobs. La URL `127.0.0.1:18080` debe corresponder a un túnel SSH válido. Para reanudar desde un paso concreto, usa `--resume-from 14` junto con `--apply` y lanza manualmente el workflow de reanudación creado. No elimina volúmenes ni credenciales.
