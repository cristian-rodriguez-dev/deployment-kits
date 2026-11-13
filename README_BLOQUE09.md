# Bloque 09 — Protección de Prometheus Job 04 (v1)

Objetivo: impedir que una ejecución accidental de `04 - Instalar Prometheus` vuelva a generar la configuración y sustituya los targets actuales. En el laboratorio hay nueve jobs de Prometheus, incluido `security-triage-bot`; la plantilla histórica del instalador no representa necesariamente la configuración actual.

**No ejecutar `install` en el laboratorio actual.** Este bloque NO gestiona/adopta ni modifica instalaciones existentes.

## Integración (Windows Git Bash, raíz `C:/deployment-kits`)

1. Extrae el ZIP en la raíz del repositorio. Los archivos de prueba y la guía son nuevos; el playbook existente se modifica exclusivamente con el parche.
2. Comprueba la aplicabilidad sin cambiar archivos:

   ```bash
   git apply --check proteccion-job04-prometheus.patch
   ```

   Si falla, **no sobrescribas** tu playbook; revisa las diferencias del repositorio con la copia de partida.
3. Aplica el parche:

   ```bash
   git apply proteccion-job04-prometheus.patch
   ```

4. Prueba la sintaxis y el orden de salvaguardas:

   ```bash
   uv run --with PyYAML --no-project -m unittest discover -s tests -p test_job04_prometheus_guard.py -v
   git diff --check
   git diff -- monitorizacion/playbooks/instalar_prometheus.yml
   ```

5. Agrega únicamente los cambios funcionales y la documentación (no hace falta versionar el parche):

   ```bash
   git add monitorizacion/playbooks/instalar_prometheus.yml monitorizacion/PROTECCION_PROMETHEUS_JOB04.md tests/test_job04_prometheus_guard.py
   git commit -m "fix(prometheus): safeguard AWX job 04 against existing deployments"
   git push origin main
   ```

6. Sincroniza el proyecto en AWX. Verifica que la `SCM Revision` corresponde al nuevo commit antes de lanzar el job.
7. Ejecuta **directamente** `04 - Instalar Prometheus`, no desde el workflow de instalación, con estas Extra Variables:

   ```yaml
   var_prometheus_job04_mode: inspect
   ```

   Esperamos `changed=0`, `failed=0`, `Modo: INSPECT` y `Directorio/Compose/Configuracion/Almacenamiento existentes: True` (según el despliegue real).

## Garantías y límites

- `inspect` es el valor predeterminado. Antes de `meta: end_play` solo hay `assert`, `stat` y `debug` (más la recogida estándar de facts de Ansible).
- `install` exige la cadena de confirmación `INSTALL_NEW_PROMETHEUS`, un directorio de instalación **inexistente** y que no existan contenedores del proyecto Compose. No es una ruta para modificar producción.
- No se toca la plantilla actual de `prometheus.yml`; **no la relances** sobre este laboratorio para recuperar jobs añadidos manualmente.
- Las pruebas incluidas son estáticas (estructura YAML y orden de guardas), **no** equivalen a una ejecución AWX.
- El workflow original podría forzar el modo `install` vía variables y los demás Jobs podrían tener otros efectos. Hay que revisar explícitamente el workflow antes de ejecutarlo de nuevo.
- No incluye secretos, snapshots ni exportaciones del servidor.
