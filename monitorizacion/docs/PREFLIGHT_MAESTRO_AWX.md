# PREFLIGHT-00 — Workflow maestro AWX (proyecto antiguo `deployment-kits`)

**Versión:** 0.1 — primer bloque de solo lectura. No forma parte de `infrastructure-platform`.

## Propósito

Este job verifica inventario, conectividad y privilegios, Ubuntu, información básica de recursos, estado de Docker/K3s y presencia de las rutas de Wazuh, Prometheus y Grafana. **No instala ni repara nada** y no debe utilizarse por sí solo como autorización final para instalar todos los componentes.

## Ubicación

Copiar `preflight-lab.yml` a `monitorizacion/playbooks/preflight-lab.yml`. Mantener esta guía como `monitorizacion/docs/PREFLIGHT_MAESTRO_AWX.md`.

## Contrato de inventario real del repositorio

Los playbooks existentes emplean exactamente los grupos:

- `docker_servers` (guion bajo)
- `wazuh-servers` (guion)
- `prometheus-servers` (guion)
- `grafana-servers` (guion)
- `monitoring-agents` (guion)

Los hosts de las tres plataformas centrales pueden ser la **misma VM** y pertenecer a varios grupos; los agentes remotos no deben pertenecer a los grupos de servidores centrales. En instalaciones nuevas, los servidores centrales deben pertenecer también a `docker_servers`.

## Configuración de AWX

Crear un **Job Template** independiente, por ejemplo `00 - Preflight LAB (read-only)`, con:

- **Proyecto:** Git de `deployment-kits` (sincronizado con el nuevo playbook).
- **Playbook:** `monitorizacion/playbooks/preflight-lab.yml`.
- **Inventario:** el que incluya los cinco grupos anteriores y sus hosts.
- **Credencial:** Machine SSH con elevación de privilegios (`become`) operativa.
- **Entorno de ejecución:** Ansible compatible con los módulos `assert`, `service_facts`, `stat`, `command` y filtros estándar; sin colecciones adicionales para este job.
- **Limit:** no fijar un subconjunto en el Job Template maestro. El preflight necesita todos los grupos. Evitar saltar el control de inventario mediante `--limit`.

### Modo 1: auditoría del laboratorio existente (recomendado ahora)

Variables adicionales:

```yaml
var_preflight_mode: audit
```

Este es también el modo por defecto. **Una ruta de instalación existente se informa, no se considera un error.** No se leen archivos `.env`, passwords, certificados ni datos de Wazuh, Prometheus o Grafana. No ejecutar un instalador a partir de este resultado.

### Modo 2: comprobar una instalación nueva

**Solo sobre inventario aislado de VMs preparadas para reconstrucción**, no sobre el laboratorio operativo:

```yaml
var_preflight_mode: new_install
var_preflight_confirm: CHECK_NEW_EMPTY_LAB
```

El job rechaza rutas de Wazuh y Prometheus ya existentes. Para Grafana admite una ruta inexistente o una carpeta que contenga **exclusivamente** un `.env` previamente provisionado para SMTP; rechaza otras huellas. Comprueba además pertenencia de servidores al grupo Docker y requiere K3s activo para el playbook de observabilidad. `CHECK_NEW_EMPTY_LAB` **no habilita ninguna instalación**: únicamente permite esas comprobaciones adicionales. Los jobs 04/05 mantienen sus propios modos y confirmaciones.

## Secuencia para probarlo

1. Guardar los dos archivos en las ubicaciones indicadas, todavía sin hacer commit.
2. Revisar el diff y hacer validación sintáctica local (`ansible-playbook --syntax-check ...` en un entorno con Ansible y un inventario de prueba apropiado). La carga de YAML genérico no reemplaza la validación Ansible.
3. Registrar solo los archivos definitivos y su documentación; no subir inventarios desechables, secretos o logs.
4. Sincronizar el Project de AWX y ejecutar el job **en modo `audit`** con las VMs actuales.
5. Verificar `changed=0` para los hosts y ausencia de errores de inventario/SSH/`become`. La recolección de facts es de solo lectura.
6. No incluir aún instaladores en el workflow maestro hasta revisar el resultado y añadir los bloqueos faltantes.

## Límites expresos de esta versión

- No comprueba DNS/resolución, rutas de red, salida a repositorios, puertos libres o firewall.
- Informa memoria y vCPUs, pero **no valida capacidad mínima**; falta definir umbrales reales para el tamaño del laboratorio.
- No comprueba colisiones por nombre de proyecto Docker Compose, contenedores ni volúmenes existentes.
- No comprueba secretos ni credenciales de servicios; estas comprobaciones se harán sin imprimirlos.
- No comprueba que la API de Kubernetes o el token de scrape sean utilizables; solo presencia del servicio K3s para `new_install`.
- No valida contenido de dashboards, GeoIP, bot o canales de alertas. Son etapas posteriores.
- Solo prueba el inventario utilizado; el AWX remoto, sus credenciales efectivas y su ejecución deben verificarse en AWX.

## Criterios de aceptación de este bloque

- Los cinco grupos existen y no se mezclan agentes con servidores centrales.
- Todos los destinos son alcanzables con SSH y pueden elevar privilegios mediante la credencial AWX.
- Los destinos declaran Ubuntu y el job completa sin modificar archivos, servicios ni configuraciones.
- En `new_install`, Wazuh/Prometheus no presentan raíces preexistentes; Grafana solo puede tener un `.env` preparado, los servidores están cubiertos por Docker y K3s está activo donde hace falta.
- Los resultados dejan visibles los límites pendientes antes de autorizar una instalación real.

## Documentación relacionada

Al integrar este bloque en el repositorio, actualizar los enlaces/orden de ejecución de `README.md` y `monitorizacion/README_DESPLIEGUE_AWX.md`. Cuando diseñemos el workflow maestro definitivo, documentar también el inventario, las aprobaciones, variables y controles de no alteración.
