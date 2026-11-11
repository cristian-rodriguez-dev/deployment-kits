# Bloque 03 — Job 19: Auditoría de rutas Traefik en K3s

## Contexto verificado

El Job 18 terminó con `ok=12 changed=0 failed=0`: `1/1` réplicas Traefik disponibles, Service `LoadBalancer`, una `IngressRoute` actual, ninguna `Ingress` clásica y `HelmChart` presente.

En K3s, `LoadBalancer` no demuestra por sí solo exposición a Internet: puede tratarse de ServiceLB para una red interna. Una `IngressRoute` es un recurso distinto del `Ingress` clásico y puede estar activa aunque el recuento de `Ingress` sea cero.

## Archivos añadidos

- `monitorizacion/playbooks/auditar_rutas_traefik_k3s.yml`
- `monitorizacion/scripts/analizar_rutas_traefik.py`
- `monitorizacion/TRAEFIK_RUTAS_AWX.md`

No se sustituyen archivos previos. El script Python es reutilizable y necesario para interpretar los recursos desde AWX, no es un script de laboratorio desechable.

## Alcance

- Consultar IngressRoutes actuales de Traefik (CRD `traefik.io`), los Services del clúster, EndpointSlices si están disponibles, el Service frontal de Traefik y la **existencia** de `HelmChartConfig` (nunca sus valores).
- Contar reglas, referencias a `Service`, comprobar existencia y puertos declarados; opcionalmente examinar si existe algún endpoint listo.
- Informar de referencias `TraefikService`/tipos de backend especiales como **NO EVALUADAS**, sin considerarlas Service inexistentes.
- Mostrar solo resúmenes agregados: no imprimir IP internas, rutas HTTP, hosts, especificaciones, certificados ni contenidos de Secrets.
- Ejecutar comandos exclusivamente de lectura (`kubectl get`). Sin escrituras remotas, sin `helm upgrade`, sin cambios ni reinicios.

### Limitaciones

- No verifica certificados, accesibilidad externa, políticas de seguridad, middlewares efectivos ni reglas `Gateway API`/TCP/UDP.
- TLS configurado no prueba que HTTPS funcione correctamente.
- `EndpointSlices` inaccesibles se informa como falta de comprobación, no como cero endpoints.
- El contador de endpoints **no** garantiza respuesta HTTP exitosa.
- Si hay backends no `Service`, no se validan en esta versión.
- En sistemas con otros proveedores de tráfico las rutas no inventariadas no se detectan aquí.

## Configuración AWX

1. Extraer este paquete sobre la raíz de `deployment-kits`, respetando `monitorizacion/`.
2. Revisar cambios en Git (sin secretos ni backups), commit, push y sincronizar el proyecto AWX.
3. Crear Job Template: `19 - Auditar rutas Traefik K3s`.
4. Playbook: `monitorizacion/playbooks/auditar_rutas_traefik_k3s.yml`.
5. Mismo inventario/grupo (`prometheus-servers`) y credenciales SSH+BECOME que el Job 18.
6. Comprobar que el Execution Environment tiene Python 3 (normalmente disponible con Ansible) para analizar el JSON en `localhost` (entorno AWX), no en el host remoto.
7. Ejecución inicial sin variables extra. No se activan validaciones estrictas hasta revisar resultados reales.

Variables opcionales:

```yaml
var_traefik_namespace: kube-system
var_traefik_service_name: traefik
var_traefik_fail_on_missing_backends: false
var_traefik_fail_on_no_ready_endpoints: false
```

Solo activar los dos últimos `true` una vez confirmada la cobertura de rutas/backends en el laboratorio; en especial, la segunda requiere permisos para EndpointSlices y que todos los Services referenciados sean aplicables.

## Salida que compartir

- `TASK [Mostrar resumen de rutas Traefik sin datos sensibles]`
- `PLAY RECAP`

No copiar las tareas que muestran documentos completos de Kubernetes, aunque no deberían imprimirse por `no_log`.

## Siguiente fase

Si la ruta resulta válida, considerar una auditoría de configuración del chart (`HelmChart`/`HelmChartConfig`), TLS y políticas de acceso, preservando el Traefik administrado por K3s. No reemplazar `/var/lib/rancher/k3s/server/manifests/traefik.yaml`, porque K3s lo regenera; las personalizaciones se realizan mediante `HelmChartConfig` después de respaldar y aprobar cambios.
