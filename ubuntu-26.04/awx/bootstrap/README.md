# AWX en Ubuntu Server 26.04 LTS

Instalación para un host nuevo Ubuntu 26.04 LTS amd64, físico o virtual. El archivo `install-awx.sh` es autónomo; `awx-bootstrap.env` es opcional. Versiones fijadas: K3s `v1.34.9+k3s1`, AWX Operator `2.19.1` y AWX `24.6.1` (valor por defecto del Operator). En una instalación limpia, K3s mantiene Traefik y ServiceLB integrados, junto con `--write-kubeconfig-mode 0600 --secrets-encryption`. La VM existente conserva su configuración hasta que se migre expresamente.

## Qué corrige

- Desactiva de forma conservadora una entrada de CD-ROM residual de APT.
- Instala y carga antes de K3s un perfil AppArmor compatible con la etiqueta `cri-containerd.apparmor.d//&unconfined`, basado en el perfil predeterminado de containerd 2.2.5, con las dos reglas exactas añadidas por containerd#14487. Mantiene `kernel.apparmor_restrict_unprivileged_unconfined=1`, sin una desactivación global. Conserva el perfil en `/etc/apparmor.d/` para el siguiente arranque y ordena K3s tras `apparmor.service`.
- Espera la disponibilidad del nodo, el Operator, PostgreSQL, la finalización de migraciones, los Deployments `web` y `task` y una respuesta HTTP de la aplicación. Evita considerar terminado AWX solo porque aparece `awx-web`.
- Evita adoptar un K3s ajeno y ofrece borrado explícito **solo para el laboratorio que instaló este script**.

## Instalar

```bash
bash install-awx.sh --check
sudo bash install-awx.sh --install
sudo bash install-awx.sh --status
```

Si el proceso se interrumpe:

```bash
sudo bash install-awx.sh --resume
```

La primera instalación puede tardar varios minutos por la descarga de imágenes y las migraciones. El tiempo límite de espera de AWX es configurable con `READY_TIMEOUT_SECONDS` y por defecto es 2400 s.

## Restablecer el laboratorio para una prueba desde cero

**Destructivo:** elimina todo el K3s que pertenece al script, incluida la instancia AWX, la base de datos PostgreSQL, PVC/volúmenes locales y cualquier otra carga de trabajo de K3s. No borra Ubuntu ni Docker. El script se niega a operar sobre instalaciones sin marca de propiedad y con namespaces adicionales no previstos. No ejecutar en producción.

```bash
sudo bash install-awx.sh --uninstall-lab
sudo bash install-awx.sh --install
```

Requiere escribir `BORRAR AWX Y K3S` en el terminal. No se ejecuta una instalación automáticamente después del borrado: son acciones separadas para poder revisar el resultado.

## Acceso privado y prueba

Desde Windows:

```powershell
ssh -t -L 8080:127.0.0.1:8080 servidor@192.168.56.23 "sudo k3s kubectl -n awx port-forward svc/awx-service 8080:80"
```

En el navegador de Windows: `http://localhost:8080`. La IP anterior corresponde exclusivamente a la VM del laboratorio; adaptar en servidores físicos.

Contraseña inicial (no enviarla por chat ni guardarla en Git):

```bash
sudo k3s kubectl -n awx get secret awx-admin-password -o jsonpath='{.data.password}' | base64 -d; echo
```

Comprobar el inicio de sesión y la ejecución real de un Job antes de aprobar la instalación para producción.

## Reversión de la mitigación AppArmor

`--uninstall-lab` elimina el perfil AppArmor solo si el propio script dejó la marca `apparmor-profile-owner`. En producción, retirar este perfil únicamente después de actualizar K3s/containerd a una versión que incorpore el parche nativo y de volver a probar PostgreSQL.

## Procedencia técnica

- https://docs.k3s.io/release-notes/v1.34.X
- https://github.com/containerd/containerd/issues/14485
- https://github.com/containerd/containerd/pull/14487
- https://raw.githubusercontent.com/containerd/containerd/v2.2.5/contrib/apparmor/template.go
- https://docs.ansible.com/projects/awx-operator/en/latest/installation/basic-install.html

Este paquete se ha revisado estáticamente y no se ha ejecutado contra el Ubuntu de destino desde aquí. La validación real queda pendiente de la reinstalación de laboratorio y de un reinicio de comprobación. No se considera todavía un instalador de producción validado.
