# Bloque 07 — Corrección v2 de la comparación de PromQL (Job 27)

**Motivo:** Job 27 detectó un `DRIFT` únicamente en `awx-k3s-crashloop/promql`.
El comparador v1 distinguía texto multilínea y texto de una línea aunque los
operadores y tokens fuesen idénticos. La versión v2 tokeniza la expresión,
ignorando espacios de formato, pero **no** cambios reales de contenido.

## Archivos

- `monitorizacion/files/grafana_alerting_operational_audit.py`: reemplaza
  únicamente la comparación de expresiones en la auditoría.
- `tests/test_alerting_operational_audit.py`: añade tres pruebas de no-deriva
  por formato y deriva verdadera por modificación de la consulta.
- `monitorizacion/ALERTING_OPERATIVO_GRAFANA_AWX.md`: documenta la corrección.

## Aplicación

1. Extraer en la raíz de `C:\deployment-kits`.
2. Probar: `uv run --python 3.15 --no-project -m unittest discover -s tests -p test_alerting_operational_audit.py -v`.
3. Revisar `git diff --check`, hacer commit y push; sincronizar proyecto en AWX.
4. Repetir **Job 27** sin cambiar sus Extra Variables.
5. Si `Resultado: OK`, se ha descartado una falsa deriva causada por formato.
   Si continúa `DRIFT` en `promql`, no hacer escrituras: investigar la diferencia
   real antes de actualizar la referencia declarativa.

No se cambia el playbook ni se realizan peticiones de escritura a Grafana.
No ejecutar el instalador de Grafana Job 05: su Compose histórico no incluye SMTP.
No versionar `.env`, contraseñas, ficheros de secretos ni respaldos privados.
