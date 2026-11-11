# Parche de seguridad previo a la adopción de Wazuh Active Response

Contenido: solo 5 archivos a sustituir en `C:\deployment-kits` conservando sus rutas.

- El script comprueba que el `alert.agent.id` coincide con el ID local del agente leyendo **solo el primer campo** de `/var/ossec/etc/client.keys` (sin exponer la clave).
- Se rechazan eventos dirigidos desde otro agente mientras el Manager permanezca en `defined-agent`.
- Se retira `8.8.8.8` como exclusión predeterminada de prueba en los archivos de variables.
- Dos pruebas simuladas nuevas cubren identidades ajenas y `client.keys` ambiguo, manteniendo las pruebas portables de Windows.
- No se modifican los hosts, AWX ni el Manager. **NO desplegar** todavía: primero repetir tests y `--syntax-check`, y confirmar la presencia de un ID único en `client.keys` sin imprimir el secreto.

Valida en Windows desde la raíz del proyecto:

```powershell
uv run --python 3.13 --with pytest --with pyyaml --no-project python -m pytest -v tests/test_wazuh_active_response.py
```

Después copia únicamente los archivos modificados al repositorio de validación de Ubuntu. No commitear ni guardar el archivo real `client.keys`.
