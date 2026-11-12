# Bloque 07 — Consolidación Grafana Alerting AWX (laboratorio antiguo)

**Alcance:** verificación segura en AWX de las 10 alertas y canales de emergencia ya configurados. No se necesita volver a crear reglas, detener contenedores ni reinstalar Grafana.

## Contenido

- `monitorizacion/playbooks/auditar_alerting_operativo_grafana.yml` — nuevo Job 27, verifica mediante API GET.
- `monitorizacion/files/grafana_alerting_operational_audit.py` — auditor de deriva, sin datos sensibles en stdout.
- `monitorizacion/files/grafana_k3s_rules.py` y `grafana_critical_services_rules.py` — referencias **idénticas al Bloque 06** para comparar lo declarado. Revisar `git diff` antes de sustituir archivos que hayan cambiado localmente.
- `monitorizacion/examples/variables_auditoria_alerting_operativo.yml` — parámetros iniciales, sin secretos.
- `monitorizacion/ALERTING_OPERATIVO_GRAFANA_AWX.md` — arquitectura, riesgo de sobrescribir SMTP con Job 05, límites y pasos.
- `tests/test_alerting_operational_audit.py` — pruebas locales.

## Inicio rápido

1. Descomprimir en `C:\deployment-kits` conservando la jerarquía.
2. Ejecutar `python -m unittest discover -s tests -p test_alerting_operational_audit.py -v` (o `uv run --python 3.15 --no-project -m unittest ...`).
3. `git diff --check; git status --short`; revisar que nada sensible vaya al commit.
4. Commit, push y sincronizar el proyecto AWX.
5. Crear Job 27 con `monitorizacion/playbooks/auditar_alerting_operativo_grafana.yml`, copiando el inventario y credenciales del Job 24.
6. Ejecutar con variables de `monitorizacion/examples/variables_auditoria_alerting_operativo.yml`; enviar solo el resumen seguro y `PLAY RECAP`.

**NO ejecutar el Job 05 instalador** para aplicar este bloque: su template antiguo no contiene el SMTP recién configurado. **NO** versionar `.env`, `.env.mail`, `secrets/`, respaldos de Grafana ni el JSON privado del Job 24.

No se ha realizado ninguna ejecución contra el servidor real; solo pruebas locales con datos simulados.
