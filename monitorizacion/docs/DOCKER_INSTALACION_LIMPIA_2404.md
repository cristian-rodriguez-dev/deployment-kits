# Job 01 — Instalación limpia de Docker en Ubuntu 24.04

## Objetivo y alcance

Se **adapta el playbook existente** `monitorizacion/playbooks/instalar_docker.yml`. No se añade un segundo instalador, no se realiza adopción y no se modifica `infrastructure-platform`.

Esta fase sirve **solo para una VM Ubuntu Server 24.04 nueva**, sin Docker ni containerd ni datos Docker existentes. Los hosts del laboratorio anterior deben mantenerse fuera del inventario/límite de esta prueba.

## Garantías

1. **Bloqueado por defecto.** El Job 01 exige `var_docker_install_mode: install` y `var_docker_install_confirm: INSTALL_NEW_DOCKER_2404` antes de ejecutar tareas de escritura.
2. Rechaza versiones de Ubuntu distintas a 24.04 y arquitecturas no verificadas (`x86_64`, `aarch64`). No implica soporte verificado de Ubuntu 26.04.
3. En una VM sin marca propia, rechaza binarios, paquetes, runtime, `daemon.json`, repositorios o directorios de datos Docker preexistentes. No elimina ni modifica instalaciones ajenas.
4. Conserva la instalación desde el repositorio oficial apt y la verificación de Docker/Compose del playbook original.
5. Escribe `daemon.json` **antes de instalar** Docker, para que el servicio nazca con el pool configurado. No usa handlers de reinicio.
6. Crea una **marca root-only** `/etc/deployment-kits/docker-clean-install-2404` al iniciar la instalación propia. Permite reintentos tras un fallo parcial y la segunda ejecución del mismo playbook. La marca no prueba por sí sola que la instalación terminara: las comprobaciones finales sí.
7. Las siguientes ejecuciones comprueban que `daemon.json` sigue igual. Si alguien lo cambió o eliminó, falla sin sobrescribirlo.
8. La incorporación del usuario al grupo `docker` está desactivada por defecto: equivale a conceder privilegios root. AWX ejecutará los demás playbooks con `become: true` cuando corresponda.
9. `apt state: present` no solicita explícitamente upgrades; el servicio usa `state: started` (no reinicio si ya está activo). No hay `prune`, `down -v`, ni limpieza automática.

## AWX — configuración mínima para VM nueva

- Inventario: **nuevo**, no reutilizar el inventario operativo como objetivo de prueba.
- Grupo: `docker_servers`; añadir **solo** la VM Ubuntu 24.04 nueva.
- Credencial: SSH con `become` autorizado, como en los playbooks actuales.
- Proyecto: Git `deployment-kits`, actualizado a la revisión que contenga este cambio.
- Job Template: `01 - Instalar Docker - CLEAN Ubuntu 24.04`.
- Playbook: `monitorizacion/playbooks/instalar_docker.yml`.
- Variables: copiar el ejemplo de `monitorizacion/examples/variables_docker_clean_2404.yml`.
- Desactivar Surveys y prompts de variables que permitan alterar accidentalmente las protecciones; no programar lanzamientos.
- **Limitar a la VM nueva**. No habilitar el workflow 01–05 antiguo mientras se prueba este primer bloque.

## Validación de aceptación

1. Ejecutar `python -B -m unittest discover -s monitorizacion/tests -p 'test_docker_clean_install.py' -v` con dependencias PyYAML + Jinja2.
2. Comprobar que el Job 01 **rechaza** una VM distinta o con Docker existente (sin cambios).
3. En una VM nueva: Job 01 finaliza sin fallos; Docker y Compose devuelven versión; `docker info` responde y `dockerd --validate --config-file /etc/docker/daemon.json` es correcto.
4. Repetir el Job 01 con las mismas variables: `changed=0` esperado, si no hubo actualizaciones externas de claves/repositorios/paquetes y el sistema no sufrió cambios de estado.
5. **No** probar sobre el servidor actual. La creación/limpieza de VM para ensayos es manual, fuera de este bloque.

## Problemas conocidos y decisiones diferidas

- Se conserva `ansible.builtin.apt_repository`, que ya utiliza el repositorio. En futuras versiones de Ansible convendrá migrar a Deb822 si es necesario, **sin hacerlo dentro de este cambio mínimo**.
- El proyecto sigue usando las versiones actuales del repositorio apt; para reproducibilidad estricta se fijarán versiones una vez validadas en una VM nueva. Nunca actualizar por sorpresa un Docker ya en uso.
- No hay adopción, actualización de versiones, rollback automático ni migración de datos. Si una instalación queda parcialmente realizada, conservar la VM para diagnóstico o reconstruir una nueva; **no borrar `/var/lib/docker` para forzar el reintento**.
- Los cambios de configuración del daemon posteriores a la primera instalación requieren un procedimiento específico, no reutilizar Job 01.
- La comprobación funcional en AWX está pendiente hasta ejecutar el Job sobre una VM desechable. Los tests incluidos son offline y estáticos, no una prueba de instalación real.

## Reversión

En Windows, restaurar las copias de seguridad de los archivos del repositorio si no se ha hecho commit. Tras publicarlo, revertir **solo el commit correspondiente**. En una VM de pruebas de instalación limpia, la reversión del despliegue consiste en **descartar/recrear la VM**, no en borrar manualmente configuraciones o volúmenes.

## Dependencias del workflow maestro

El Job 01 deberá ejecutarse y validar Docker antes de Job 02 Wazuh y Job 04 Prometheus/Job 05 Grafana. No encadenarlo con adopción ni recuperación en esta fase.
