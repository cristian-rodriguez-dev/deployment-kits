# Grafana Alerting original · Ubuntu 26.04

Fuente: `alerting-20261112T153119Z-c358f34d1aa4.json`, exportación saneada del servidor anterior. Contiene 10 UID únicos con sus expresiones, umbrales y etiquetas; 3 integraciones de contacto (Telegram, correo y webhook al Triage Bot) **solo como metadatos**; y un árbol de políticas cuya ruta `triage=enabled` conduce al bot. La regla `awx-critical-triage-down` deriva directamente a `Infraestructura - Emergencias`, que en el origen agrupaba correo y Telegram. El UID de la carpeta original se conserva (`bg3s5j2ylm1vka`); el título de la carpeta **no estaba en la exportación**, por lo que `Infrastructure` es solo un valor inicial configurable.

## Job 18 (encadenado después del 16)

- `var_grafana_alerting_restore_mode: stage` (valor por defecto): importa las **10 reglas pausadas** por API, sin crear contactos, modificar políticas ni enviar notificaciones. Es la opción segura del workflow central de instalación limpia. Repetir el Job conserva reglas existentes equivalentes y no despausa ninguna.
- `var_grafana_alerting_restore_mode: activate`: solo después de configurar los contactos privados y poner `var_grafana_alerting_authorize_notifications: true`. Importa las tres integraciones por UID, sustituye el árbol de políticas y habilita las nueve reglas operativas. La alerta `LAB - Prueba de notificaciones IA` siempre queda pausada. Esta operación **puede generar notificaciones reales** y debe realizarse únicamente tras autorización expresa, con destinatarios de prueba si se quiere validar.

El Job usa la credencial AWX existente `Grafana - Admin 26.04` (`VAR_GRAFANA_ADMIN_PASSWORD`) y consulta la API por la IP privada de `var_grafana_bind_address`, sin exponer Grafana en un puerto nuevo. La API puede requerir que la carpeta y las fuentes de datos estén disponibles; ejecutarlo después de los Jobs 05, 09 y 15. No se exportan ni se copian la base de datos de Grafana ni las contraseñas antiguas.

Para `activate`, la credencial adicional `Grafana Alerting - Contactos 26.04` debe inyectar la variable de entorno **secreta** `VAR_GRAFANA_ALERTING_CONTACTS_JSON`. Su contenido es una lista JSON con 3 objetos `uid`, `name`, `type`, `settings`; sus UID, nombres, tipos y claves de `settings` deben coincidir exactamente con los metadatos saneados en `grafana-alerting-sanitized.json`. Completar los valores reales (URL del webhook, autenticación, destinos, token de Telegram, dirección de correo, texto y demás opciones) desde la configuración original, sin incluirlos en Git, documentación ni Extra Variables. No se deben inventar los valores perdidos por el saneamiento. Vincular esta credencial **únicamente al Job 18** cuando se autorice la activación, no al workflow de instalación por defecto.

**Límites:** no constan el intervalo de evaluación original del grupo, el nombre real de la carpeta ni los valores de los ajustes de los contactos. Su recuperación y la compatibilidad exacta de la API de Grafana 13.2.3 deben verificarse en Ubuntu 26.04 antes de considerar la restauración completa. El receiver raíz de la política exportada es literalmente `empty`: no se sustituye por un contacto inventado; comprobar su funcionamiento en el nuevo Grafana antes de activar la política. El valor de UID del datasource Prometheus de las reglas es `prometheus` y se mantiene.

Prueba offline sin acceso a Grafana:

```powershell
uv run --no-project --python 3.12 .\ubuntu-26.04\tools\restore_grafana_alerting.py --source .\ubuntu-26.04\alerting\grafana-alerting-sanitized.json --mode plan
uv run --no-project --python 3.12 --with pytest --with pyyaml --with jinja2 -m pytest -q .\ubuntu-26.04\tests
```

**No utilizar `activate` sin confirmar políticas, contactos y destinatarios autorizados.**
