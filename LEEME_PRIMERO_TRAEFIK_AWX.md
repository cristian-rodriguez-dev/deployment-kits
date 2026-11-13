# Nuevo bloque de automatización segura Traefik → Alloy → Loki → Wazuh

Extraer en la raíz de `C:\deployment-kits`. Solo se añaden archivos nuevos bajo `monitorizacion/` y `tests/`; no incluir ni sobreescribir `.git`. El parche de alineación de rutas y documentación del 13-11-2026 debe estar aplicado antes, como ya confirmó el usuario.

**No hace falta desplegar el Manager de nuevo.** El rol primero audita la instalación ya operativa y en modo `adopt` aplica solo cambios autorizados. La configuración de Wazuh/Compose y sus reglas se inspeccionan pero no se escriben; un drift detiene la adopción. Las acciones potencialmente disruptivas Traefik/puente están apagadas de forma predeterminada.

1. Ejecutar tests: `uv run --python 3.13 --no-project python -m unittest discover -s tests -p "test_traefik_wazuh_ansible.py" -v`.
2. Leer `monitorizacion/docs/TRAEFIK_WAZUH_AWX.md` (seguridad, pruebas, variables, plantillas AWX, rollback).
3. Revisar el inventario: `ansible_server` debe referirse al mismo servidor Ubuntu que contiene Wazuh Manager, Loki y el puente.
4. Primero ejecutar **auditoría** con `Limit: ansible_server` y `changed=0`.
5. Tras comprobarla, crear adopción con `var_tlw_apply: true`, el mismo límite y sin activar variables de actualización. Se espera `changed=0` si no existe deriva.
6. No hacer commit antes de validar syntax-check de los dos playbooks sobre el mismo Ansible/AWX que se utilizará y revisar las modificaciones en documentación relacionada.
