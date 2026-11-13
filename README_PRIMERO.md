# Paquete de preparación — Traefik / Loki / Wazuh

**Este paquete es un punto de partida para la automatización.** Se validó el despliegue manual en noviembre de 2026; no ejecutar directamente sobre producción sin revisar el estado real. No contiene secretos ni datos de SQLite/JSONL.

Estado validado: Traefik access logs JSON → Alloy → Loki; puente systemd con JSONL y SQLite; Manager Wazuh leyendo el JSONL y alerta real `100601` (nivel 7). Correlaciones `100603` y `100605` y gestión declarativa desde AWX pendientes. Detalle: montaje efectivo `/var/ossec/traefik-bridge` y proyecto Compose `wazuh` (obligatorio `-p wazuh`).

1. Extraer en raíz `deployment-kits/` evitando incluir o copiar `.git`.
2. Leer `monitorizacion/docs/TRAEFIK_LOKI_WAZUH.md` (riesgos, fases y comandos de ensayo).
3. Validar las pruebas offline: `python3 -m unittest discover -s tests -p 'test_traefik_wazuh_bridge.py' -v`.
4. No recrear Docker ni volver a instalar el puente por defecto: primero adoptar la instalación existente, verificar diferencias y exigir aprobación para cambios que requieran recreación.

## Cambios de configuración

- `monitorizacion/manifests/traefik-access-logs.helmchartconfig.yaml` reproduce la configuración Helm validada en K3s; solo es referencia declarativa, no implica aplicar de nuevo.
- `monitorizacion/integrations/traefik_wazuh_bridge/traefik_rules.xml` son reglas **propuestas**, no reglas activas; IDs 100600–100605 deben comprobarse contra los ya existentes.
- `bridge.py` y el servicio son implementación de una primera versión, preparados para pruebas offline y un ensayo sin escritura, no despliegue automatizado aprobado.
