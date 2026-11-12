# Paquete de preparación — Traefik / Loki / Wazuh

**No hay despliegue automático.** Este ZIP contiene **solo archivos nuevos** que se extraen en la raíz de `deployment-kits` sin sobrescribir los existentes.

Estado validado fuera de este paquete: Traefik access logs JSON → Alloy → Loki (dos entradas de `/dashboard`, HTTP 401) y Wazuh `wazuh-logtest` decodificando los campos JSON. Aún falta habilitar la entrega de logs al Manager y validar las reglas nuevas.

1. Extraer en raíz `deployment-kits/` evitando incluir o copiar `.git`.
2. Leer `monitorizacion/docs/TRAEFIK_LOKI_WAZUH.md` (riesgos, fases y comandos de ensayo).
3. Validar las pruebas offline: `python3 -m unittest discover -s tests -p 'test_traefik_wazuh_bridge.py' -v`.
4. No editar Compose/Manager ni ejecutar el servicio systemd hasta confirmar endpoint estable de Loki, bind mount seguro y ventana de aplicación.

## Cambios de configuración

- `monitorizacion/manifests/traefik-access-logs.helmchartconfig.yaml` reproduce la configuración Helm validada en K3s; solo es referencia declarativa, no implica aplicar de nuevo.
- `monitorizacion/integrations/traefik_wazuh_bridge/traefik_rules.xml` son reglas **propuestas**, no reglas activas; IDs 100600–100605 deben comprobarse contra los ya existentes.
- `bridge.py` y el servicio son implementación de una primera versión, preparados para pruebas offline y un ensayo sin escritura, no despliegue automatizado aprobado.
