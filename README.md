# Wazuh GeoIP AWX — v3 (correccion del Job 16)

El Job 16 anterior podía devolver HTTP 200 sin `GeoLocation.location` por enviar el evento directamente como `data.srcip`. El pipeline de Wazuh comienza normalmente con un procesador JSON que lee `message`; por eso esta revision envía un mensaje **JSON sintético**, con `data.srcip=8.8.8.8`, y comprueba el resultado.

## Contenido

- `monitorizacion/playbooks/adoptar_geoip_wazuh.yml`: **sustituye exclusivamente** el Job 16 anterior.
- `monitorizacion/GEOIP_ADOPCION_AWX.md`: guía de adopción.
- `monitorizacion/examples/variables_geoip_adopcion.yml`: ejemplo sin secretos.
- `tests/test_geoip_adopcion.py`: tests estáticos actualizados.

## Cómo aplicarlo

1. Extraer en la raíz de `deployment-kits`; comprobar `git diff -- monitorizacion/playbooks/adoptar_geoip_wazuh.yml`.
2. Ejecutar pruebas en local: `uv run --python 3.15 --no-project -m unittest discover -s tests -p test_geoip_adopcion.py -v` (desde la raíz que contenga los tests de este paquete).
3. Hacer commit/push y sincronizar el proyecto de AWX.
4. Repetir Job 16 con:

```yaml
var_geoip_save_snapshot: false
var_geoip_simulate: true
```

5. Si la simulación devuelve `GeoLocation.location presente: True`, ejecutar de nuevo con `var_geoip_save_snapshot: true` para crear una copia privada del pipeline.

No se realizan escrituras en el Indexer; sólo se crean respaldos locales cuando se autoriza `var_geoip_save_snapshot`.

Si todavía falla: recopilar sólo `Mostrar diagnostico de simulacion sin datos sensibles` y la validación; **no publicar JSON de alertas ni credenciales**.
