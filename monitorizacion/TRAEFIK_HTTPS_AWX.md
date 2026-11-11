# Bloque 03 — Job 21: Auditoría no destructiva de HTTPS Traefik

## Estado previo

Los Jobs 18–20 completaron auditorías de K3s, rutas y TLS sin modificaciones. Se detectó una única `IngressRoute`, un backend válido, TLS declarado sin Secret explícito ni `certResolver`, y un LoadBalancer con una IP no global. **Todavía no se conoce qué certificado entrega realmente el servicio.**

## Archivos nuevos

- `monitorizacion/playbooks/auditar_https_traefik_k3s.yml`
- `monitorizacion/scripts/auditar_https_traefik.py`
- `monitorizacion/tests/test_auditar_https_traefik.py`
- `monitorizacion/TRAEFIK_HTTPS_AWX.md`

No se modifica ningún playbook anterior. El script es reutilizable, no es un archivo temporal del laboratorio.

## Funcionamiento

1. Lee `IngressRoutes` y el `Service traefik` mediante `kubectl get`.
2. Obtiene **solo una IP interna** del `status.loadBalancer.ingress` y un hostname `Host(...)` inequívoco declarado en la ruta. No resuelve ni contacta dominios externos. Si hay más de un hostname, no realiza conexiones salvo que se seleccione uno **que ya esté en las IngressRoutes**.
3. Desde el host SSH `ansible_server` (no desde el contenedor de AWX), abre conexiones de prueba a los puertos 443 y 80 de esa IP privada, con timeout corto.
4. En TLS, obtiene el certificado público presentado y comprueba fecha de caducidad y coincidencia con SNI mediante `openssl x509`. Comprueba además si el certificado es de confianza para **ese host**, sin desactivar controles en aplicaciones.
5. En HTTP, envía únicamente una solicitud `HEAD /`, sin seguir redirecciones, y clasifica si se observa un `Location: https://...`.

El script se ejecuta con `python3 -c` y `stdin`, **sin copiar archivos al servidor**. No lee claves privadas, no consulta Secrets, no crea archivos y no imprime IP, hostname, certificados ni respuestas HTTP completas. No se envían credenciales.

### Limitaciones importantes

- `HEAD /` solo representa esa ruta y ese método. Un 404/405/200 no prueba que no exista otra regla de redirección HTTP→HTTPS.
- Un certificado autofirmado puede ser adecuado en laboratorio; que no esté en la trust store del host no demuestra por sí solo una avería.
- La verificación de confianza se realiza desde `ansible_server`, no desde Internet ni desde un navegador externo.
- La auditoría **no prueba exposición real desde Internet**, ni garantiza que un backend HTTP específico responda correctamente.
- Se necesita `python3` y `openssl` en el host; si falta OpenSSL se podrá observar TLS, pero no examinar vencimiento o hostname.
- El script no revisa ni modifica recursos K3s. Una prueba de conexión de red es de bajo impacto, pero no equivale a lectura pasiva.

## Configuración AWX

1. Descomprimir sobre la raíz del repo `deployment-kits`, conservando `monitorizacion/`.
2. Revisar `git status --short`, evitar incluir credenciales, backups, caches de Python o ficheros `.git`.
3. Commit, push y sincronizar el mismo Project de AWX usado en Jobs 18–20.
4. Crear el Job Template **`21 - Auditar HTTPS Traefik K3s`** con playbook `monitorizacion/playbooks/auditar_https_traefik_k3s.yml`.
5. Reusar inventario y credenciales SSH/BECOME del Job 20.
6. Primera ejecución sin variables adicionales.

Variables opcionales:

```yaml
var_traefik_namespace: kube-system
var_traefik_service_name: traefik
var_traefik_probe_hostname: ''  # solo si hay varios Host(...) y ha sido confirmado en las rutas
var_traefik_probe_timeout: 4
var_traefik_cert_warning_days: 30
```

Si el resultado es `SIN_IP_INTERNA_EN_LOADBALANCER` o `HOST_AMBIGUO_O_NO_EXTRAIBLE`, el job informa que la prueba **no es concluyente**; no modifica recursos ni fuerza una prueba por IP pública.

Pruebas reutilizables:

```powershell
uv run --python 3.15 --no-project -m unittest discover -s .\monitorizacion\tests -p 'test_auditar_https_traefik.py' -v
```

## Qué salida compartir

La tarea `Mostrar resumen de prueba HTTPS Traefik sin datos sensibles` y el `PLAY RECAP`.

## Decisión posterior

Si el servicio presenta un certificado autofirmado, puede dejarse tal cual para un laboratorio privado con acceso controlado. Si se necesita acceso de usuarios, validar CA interna o certificado adecuado antes de cambiar el chart, gestionar certificados o exigir redirección. Cualquier cambio de configuración requeriría un Job nuevo con auditoría previa y respaldo; no intervenir directamente en el HelmChart administrado por K3s.
