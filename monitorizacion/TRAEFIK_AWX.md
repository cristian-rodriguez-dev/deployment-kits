# Bloque 03 — Auditoría Traefik en AWX (laboratorio antiguo)

## Objetivo

Comprobar el estado del Traefik integrado en K3s **sin modificar el clúster**. Es el paso previo a automatizar rutas, TLS, HelmChart y comprobaciones de salud. No sustituye ninguna instalación existente.

## Archivo nuevo

`monitorizacion/playbooks/auditar_traefik_k3s.yml`

## Comportamiento

- Usa el grupo `prometheus-servers` porque el playbook existente `instalar_observabilidad_k3s.yml` ya utiliza ese grupo para consultar K3s desde el servidor.
- Consulta exclusivamente el API Kubernetes con `kubectl get` y `/readyz`.
- Comprueba `Deployment` y `Service` Traefik en `kube-system`, pods con la etiqueta estándar, Ingress, IngressClasses, IngressRoutes de ambas APIs y HelmChart K3s.
- No imprime especificaciones completas, hosts de rutas, certificados, tokens, Secrets ni variables de entorno.
- Las APIs opcionales no disponibles se informan como tal; el Job no las confunde con cero recursos existentes.
- Las consultas básicas de Kubernetes fallan si no hay permisos, en lugar de dar un falso resultado vacío.

**Advertencia:** `IngressRoutes` no cubre necesariamente todo el tráfico que gestiona Traefik. Podría haber TCP/UDP routes, Gateway API o reglas configuradas por otras vías; por eso esto es una auditoría inicial, no una certificación completa de seguridad.

## Alta en AWX

1. Descomprimir el paquete en la raíz de `deployment-kits` manteniendo su estructura. No añadir carpetas temporales ni archivos `.git`.
2. Revisar `git status --short` y `git diff --stat`, hacer commit y push con los dos archivos nuevos.
3. Sincronizar el proyecto AWX.
4. Crear Job Template `18 - Auditar Traefik K3s`, playbook `monitorizacion/playbooks/auditar_traefik_k3s.yml`.
5. Reutilizar el mismo inventario/credencial SSH+BECOME que en `instalar_observabilidad_k3s.yml`. No necesita credenciales de Grafana ni Wazuh.
6. Ejecutar inicialmente **sin configurar variables adicionales**.

Los valores predeterminados son:

```yaml
var_traefik_namespace: kube-system
var_traefik_deployment_name: traefik
var_traefik_service_name: traefik
var_traefik_ingress_class_name: traefik
var_traefik_fail_if_missing: false
var_traefik_fail_if_not_ready: false
```

Si el laboratorio usa nombres distintos, ajustar esos valores en AWX, no en el playbook. Cuando confirmemos el despliegue se podrán poner las dos últimas variables en `true` para utilizar el Job como comprobación de salud estricta.

## Salida que debes compartir

Solo `Mostrar resumen de auditoria de Traefik sin datos sensibles` y `PLAY RECAP`. No envíes la salida JSON de recursos que podría incluir direcciones internas.

## Seguridad y próximos pasos

- El Job no instala chart ni edita IngressRoutes, EntryPoints, Secrets, puertos o certificados.
- No ejecutar `helm upgrade`, `kubectl apply`, `kubectl patch` ni `rollout restart` en esta primera fase.
- Antes de automatizar cambios, inventariar rutas/puertos, revisar el despliegue real y preparar un procedimiento de reversión.
- Las pruebas de sintaxis y estructura locales no demuestran que la conexión de AWX al clúster funcione. Esa validación solo se obtiene al ejecutar el Job.

## Integración con repositorio

Se añaden únicamente dos archivos reutilizables. No incluir playbooks de prueba desechables, inventarios temporales, `.venv` ni archivos de salida. Mantener actualizada esta documentación si cambian el grupo AWX o las consultas del Job.
