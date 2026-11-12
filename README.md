# Bloque 08 — Protección del Job 05 (Grafana legado)

**Objetivo**: impedir que el instalador original sobrescriba por accidente el Compose SMTP o la DB/alertas de Grafana ya operativo. Este paquete **NO despliega ni modifica nada en el servidor**.

## Archivos incluidos

- `monitorizacion/playbooks/instalar_grafana.yml`: preflight estricto: `inspect` de solo lectura; `install` exclusivamente para instalaciones limpias. En ambos modos el control se ejecuta **antes** de las tareas con escrituras. Conserva el resto del instalador original.
- `monitorizacion/templates/grafana/docker-compose.yml.j2`: soporte SMTP opcional en instalaciones nuevas, con referencias a `.env` privado (sin valores de contraseñas en Git).
- `monitorizacion/examples/variables_grafana.yml`: modos documentados.
- `monitorizacion/PROTECCION_GRAFANA_JOB05.md`: procedimiento, límites y validación.
- `tests/test_grafana_job05_guard.py`: regresión estática + render Jinja/YAML.

## Aplicación al repositorio `deployment-kits`

1. Antes de sustituir, revisar `git diff` contra los archivos actuales. Esta entrega se elaboró contra `deployment-kits.zip` facilitado anteriormente. Si Job 05 cambió desde entonces, **fusionar las modificaciones en vez de sobrescribirlas**.
2. Copiar los archivos respetando rutas. No añadir `.env`, secretos, backups, `.git`, ni `__pycache__` al commit.
3. Ejecutar `python -m unittest discover -s tests -p test_grafana_job05_guard.py -v` (requiere PyYAML y Jinja2) y `git diff --check`.
4. Commit / push / sincronizar **el proyecto AWX**.
5. **En el Grafana operativo**, ejecutar Job 05 **solo** con `var_grafana_job05_mode: inspect`. Debe terminar tras reportar Compose, DB, `.env` y SMTP; no reiniciar servicios.

## Comportamiento / limitaciones

- `var_grafana_job05_mode: inspect`: lectura, `meta: end_play`, ninguna escritura; no se comprueban credenciales SMTP ni se muestra contenido.
- `var_grafana_job05_mode: install` (por defecto): falla **antes de cambios** si existe `docker-compose.yml` o `data/grafana.db`. Esto modifica deliberadamente la semántica de reejecución del instalador legado. El objetivo es protección prioritaria; no proporciona adopción ni actualización de un Grafana existente.
- Solo para nueva VM, `var_grafana_smtp_enabled: true` habilita valores `${GRAFANA_SMTP_*}` (host, usuario, contraseña y remitente), siempre cargados desde `${var_grafana_install_dir}/.env`. Nunca enviar las credenciales por Extra Variables, Git o logs.
- Este parche no migra la instalación antigua al estado plenamente declarativo, no cambia Grafana existente y no cubre restauración. Una futura gestión de un Grafana existente necesita un bloque de adopción separado, con copia validada y aprobación explícita.
- No ejecutar Job 05 en modo `install` sobre el servidor que ya contiene 10 reglas y SMTP funcional. No ejecutar un flujo AWX que fuerce ese modo hasta revisar el workflow.
