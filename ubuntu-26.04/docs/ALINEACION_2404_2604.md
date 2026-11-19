# Alineación Ubuntu 24.04 → 26.04 · Bloque 1

## Objetivo

Reproducir en un servidor Ubuntu 26.04 nuevo el comportamiento del laboratorio original `monitorizacion/`, sin un segundo Traefik ni un plan nuevo de puertos. Este bloque solo corrige los ajustes de arranque de K3s y retira los valores de entorno cargados automáticamente desde `playbooks/group_vars/all.yml`.

## Cambios controlados

1. En **futuras instalaciones nuevas**, el bootstrap instala K3s con Traefik y ServiceLB integrados. Al desplegar Traefik, ServiceLB puede ocupar los puertos 80/443 del nodo. Comprobar previamente que están libres y autorizados; no mezclar con otro proxy frontal.
2. El host Ubuntu 26.04 **que ya tiene AWX funcionando** conserva su K3s actual, instalado con Traefik y ServiceLB desactivados. No se reinicia ni se modifica automáticamente. Para probar Traefik allí hará falta una intervención programada y comprobación de continuidad de AWX.
3. Se retira `playbooks/group_vars/all.yml`. El ejemplo `examples/variables_host_central.yml.example` es información orientativa y **Ansible no lo carga automáticamente**.
4. En AWX, abrir Inventarios → Host central → Variables y configurar únicamente los parámetros no secretos necesarios, usando el ejemplo como referencia. Los grupos centrales `docker_servers`, `wazuh-servers`, `prometheus-servers`, `grafana-servers` y `k3s-servers` siguen apuntando al mismo host; agentes remotos en sus grupos. Las variables particulares de Jobs van en sus plantillas; secretos mediante AWX Credentials, nunca aquí.
5. Se retira la configuración `GF_SERVER_ROOT_URL` añadida por el paquete HTTPS no aprobado. La configuración HTTPS queda para más adelante.

## Auditoría Traefik del proyecto original

El playbook reutilizable **ya existe** en `monitorizacion/playbooks/auditar_traefik_k3s.yml`. No lo duplicamos. En el laboratorio original apunta al grupo `prometheus-servers`; en el monohost 26 ese grupo contiene el servidor central, por lo que permite auditarlo con la misma credencial SSH+sudo. Es de solo lectura y, por defecto, informa `NO ENCONTRADO` si Traefik aún no está instalado.

Ejecutar sobre la VM de pruebas desde AWX o por Ansible, una vez disponibles inventario y credenciales. No ejecutar el playbook de **adopción** ni modificar recursos en el clúster actual como parte de este bloque.

## Verificación de los archivos

Windows, en `C:\deployment-kits`:

```powershell
py -3 .\ubuntu-26.04\tools\alinear_2404.py --check
py -3 .\ubuntu-26.04\tools\alinear_2404.py --apply
python -m pytest -q .\ubuntu-26.04\tests\test_monohost.py
```

Si Python se ejecuta mediante `uv`, usar `uv run --no-project --python 3.12` seguido de la ruta del script.

`--apply` crea un respaldo de los archivos modificados en `Downloads`. Para revertir antes de continuar, recuperar desde esa carpeta los archivos originales y, si procede, restaurar `playbooks/group_vars/all.yml`. No volver a introducir secretos ni copias en Git.

## Comprobación en Ubuntu (solo lectura)

```bash
sudo k3s kubectl -n awx get pods
sudo k3s kubectl -n kube-system get deploy,svc,helmchart | grep -i traefik || true
sudo systemctl cat k3s | grep -E -- '--disable|ExecStart' || true
```

El resultado de la segunda línea puede estar vacío en el `servidor26` ya existente; **es esperado** y no debe interpretarse como un fallo de AWX. El cambio de flags aplica a instalaciones nuevas, no instala componentes de K3s de forma retroactiva.

## Próximos bloques

- Completar la auditoría del Job 01 Docker y Jobs 02–05 frente a los playbooks originales; preservar verificaciones y modos seguros.
- Comprobar AWX después de reiniciar la VM y realizar la prueba de Traefik integrado en una instalación limpia autorizada o durante una ventana planificada.
- Reincorporar los Jobs de mantenimiento/auditoría heredados, dashboards, alertas, GeoIP y el bot según la cobertura realmente automatizada.
