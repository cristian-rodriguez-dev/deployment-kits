# Bloque 05 — Grafana Alerting AWX v2

**Objeto:** el Job 24 que guarda la configuración de alerting existente en un snapshot protegido, y puede compararla con el estado posterior, sin modificar Grafana.

**Corrección v2:** `diff: false` es una palabra clave de tarea de Ansible, no un parámetro de `ansible.builtin.copy`. Se ha movido fuera del módulo. No se modifica el exportador ni el comportamiento del respaldo.

## Instalación

1. Incorporar las carpetas `monitorizacion/` y `tests/` de este ZIP a la **raíz** de `deployment-kits`.
2. Revisar Git (`git status --short`, `git diff`); comprobar que no se han incluido backups, secretos ni `.env`.
3. Ejecutar los tests (`uv run --python 3.15 --no-project -m unittest discover -s tests -p test_grafana_alerting.py -v`).
4. Hacer commit, push y sincronizar el proyecto en AWX.
5. Actualizar el Job `24 - Respaldar y comparar alerting Grafana` con `monitorizacion/playbooks/gestionar_alerting_grafana.yml`.
6. Reutilizar las credenciales e inventario del Job 10. Extra Vars:

```yaml
var_grafana_alerting_mode: capture
```

7. Ejecutar una vez. Copiar solamente la tarea **Mostrar inventario sin contenidos ni credenciales** y el `PLAY RECAP`.

La ejecución generará una captura sensible con permisos privados en el servidor. **No enviar aquí ese archivo y no subirlo a Git**.

## Qué NO hace

Este Job **no** aprovisiona reglas ni contact points ni cambia notificaciones, y tampoco habilita modo de escritura. No reemplaza el Job 13 de backup integral, ni comprueba que un correo o mensaje Telegram sea entregado. El despliegue declarativo será la siguiente fase, una vez comprobado el inventario real.

Más detalles: `monitorizacion/ALERTING_GRAFANA_AWX.md`.
