# Bloque 03 — Job 20: Auditoría de TLS y exposición declarada Traefik

## Contexto

El Job 18 verificó Traefik `1/1` disponible, Service `LoadBalancer` y una IngressRoute. El Job 19 verificó una regla, un backend Service existente con puerto correcto y endpoints listos; la ruta declaró TLS, no usó middleware y no detectó HelmChartConfig accesible.

## Archivos nuevos

- `monitorizacion/playbooks/auditar_tls_traefik_k3s.yml`
- `monitorizacion/scripts/analizar_tls_traefik.py`
- `monitorizacion/tests/test_analizar_tls_traefik.py`
- `monitorizacion/TRAEFIK_TLS_AWX.md`

No sustituir Jobs 18 ni 19. Evitar agregar scripts de prueba específicos del laboratorio o archivos temporales al repositorio. Las pruebas unitarias de este analizador sí son reutilizables.

## Qué verifica

- Tipo de TLS declarado por cada IngressRoute: Secret, certResolver o mecanismo predeterminado.
- Si hay referencias `tls.secretName`, comprueba **existencia y tipo** usando solo metadatos de Secrets (`namespace`, `name`, `type`). No lee `tls.key` ni `tls.crt`.
- Puertos y tipo de Service frontal, recuento y categoría global/no global de IP declarada en el estado LoadBalancer, sin imprimir IP.
- Cuenta rutas con middleware y referencias TLSOptions; no presupone que tener cero middlewares sea inseguro.

**No verifica** expiración, cadena de confianza, hostname del certificado servido, redirección HTTP→HTTPS, accesibilidad real desde Internet o efectividad de autenticación. Un `LoadBalancer` no equivale a exposición pública. Tener TLS en IngressRoute no garantiza un certificado correcto. Si no hay permisos `list secrets`, indica referencias **no evaluables**, nunca `ausentes`.

## Seguridad

Solo operaciones `kubectl get` y Python sin efectos secundarios, `changed_when: false`, y `no_log: true` para respuestas potencialmente sensibles. En los mensajes solo figuran contadores agregados y booleanos. No se crea, modifica ni elimina ningún recurso Kubernetes, manifiesto, Secret o archivo remoto.

El script se ejecuta **en el Execution Environment de AWX**, donde necesita Python 3, siguiendo la estrategia del Job 19.

## Instalación y ejecución

1. Extraer sobre la raíz de `deployment-kits`, conservando `monitorizacion/` y sin incluir otros archivos.
2. Revisar el diff (en especial no añadir secretos), commit, push y sincronizar AWX.
3. Nuevo Job Template **`20 - Auditar TLS Traefik K3s`**, playbook `monitorizacion/playbooks/auditar_tls_traefik_k3s.yml`.
4. Mismo inventario, grupo `prometheus-servers`, credenciales SSH+BECOME y entorno de ejecución que Jobs 18/19.
5. Primera ejecución sin variables adicionales; no activar verificaciones estrictas.

Variables opcionales:

```yaml
var_traefik_namespace: kube-system
var_traefik_service_name: traefik
var_traefik_fail_on_invalid_tls_secrets: false
```

Si desea validar la estructura del código sin ejecutar Kubernetes:

```powershell
uv run --python 3.15 --no-project -m unittest discover -s .\monitorizacion\tests -p 'test_analizar_tls_traefik.py' -v
```

## Salida que compartir

Solo la tarea `Mostrar resumen de seguridad TLS Traefik sin datos sensibles` y el `PLAY RECAP`.

## Después

Con este resultado decidiremos si hace falta configurar certificados/TLSOptions, auditar HTTP→HTTPS y revisar restricciones de acceso. Cualquier cambio real debe ir en un playbook independiente, con respaldo y modo auditoría por defecto; nunca reescribir el chart administrado por K3s.
