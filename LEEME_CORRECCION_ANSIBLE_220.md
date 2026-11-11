# Corrección de condiciones para ansible-core 2.20

Solo sustituye dos archivos del rol de agente. No modifica los scripts de bloqueo ni el Manager.

- `tasks/apply.yml`: expresa correctamente como cadena YAML la condición UFW `Status: active`.
- `tasks/audit.yml`: ejecuta cinco consultas estrictamente de solo lectura incluso al pasar `--check`, para que UFW/firewalld y las reglas se detecten realmente.

## Aplicación
Extrae desde la raíz `C:\deployment-kits` en Windows, o en `~/wazuh-ar-validation` en Ubuntu.
Valida con `ansible-playbook --syntax-check` y repite solo la simulación `--check --diff` antes de cualquier despliegue.
No ejecutar `configurar_*` sin `--check` hasta revisar el resultado de la simulación y preflight.
