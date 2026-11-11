# Wazuh Active Response — corrección de tests para Windows

Esta entrega **solo modifica** `tests/test_wazuh_active_response.py`.

## Cambios

- Simulación explícita de `fcntl.flock` durante las pruebas funcionales del script que se ejecuta en Ubuntu.
- Simulación de `os.fchown` exclusivamente cuando no está disponible (Windows); en POSIX continúa probándose la llamada real.
- No hay modificaciones del script operativo, roles, playbooks, firewall, Manager ni documentación previa.

## Instalación

1. Cierra cualquier edición activa del archivo de tests.
2. Extrae este ZIP directamente en `C:\deployment-kits`.
3. Si Windows pregunta, reemplaza **únicamente** `tests/test_wazuh_active_response.py`.
4. Desde PowerShell:

```powershell
cd C:\deployment-kits
uv run --python 3.13 --with pytest --with pyyaml --no-project python -m pytest -v tests/test_wazuh_active_response.py
```

## Validación realizada

- Linux, Python 3.13: `12 passed, 18 subtests passed`.
- No se ha ejecutado la suite en el equipo Windows del usuario; debe confirmarse allí.
- Ningún despliegue ni prueba sobre hosts reales.
