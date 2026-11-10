# Bloque 01 · Fase 4 — Incorporación ADITIVA de los ocho dashboards restantes

**Proyecto:** `deployment-kits` (laboratorio antiguo) · **Fecha:** 10 de noviembre de 2026.

## Validación realizada con el respaldo de AWX

- ZIP recibido: `grafana-dashboards-export.zip`.
- SHA256 del ZIP: `fc2791cdb2f67e7d1208954129e3d5a54aeabae6633091ca56423be7f07e9e7f` (**coincide** con Job 12).
- Manifiesto: **15 dashboards V2**, UID únicos y SHA256 de cada recurso correctos.
- **7/7** definiciones originales ya incorporadas a Git: `spec` idéntico a la exportación.
- **8/8** nuevos JSON: fieles, sin transformación, a las respuestas de API V2 de Grafana.
- Total confirmado tras incorporar todos los archivos: **15 dashboards / 351 paneles** (los 7 originales: 187; los 8 adicionales: 164).

## ARCHIVOS DEL PAQUETE — solo añadidos

```text
monitorizacion/dashboards/
├── geoip-map.json
├── node-exporter-full.json
├── wazuh-vulnerabilities.json
├── wazuh-agent-status.json
├── wazuh-correlation-prometheus.json
├── wazuh-fim.json
├── wazuh-sca.json
└── wazuh-security-overview.json

tools/verificar_cobertura_dashboards.py
```

**No contiene ningún reemplazo** de los 7 JSON originales, ni de los playbooks 10, 11, 12, ni de variables AWX, ni de `docker-compose`.

## Instrucciones: primero copia local, luego auditoría

1. Descomprimir este paquete **en la raíz del repositorio existente** que ya contiene `monitorizacion/dashboards/*.json` (los siete originales de la fase 2).
2. No borrar ni reemplazar los siete originales. Revisar los ocho JSON exportados antes de añadirlos a Git privado: pueden contener direcciones internas, consultas y metadatos de instalación. La comprobación básica no encontró claves con nombres de contraseña/token/secret en esos JSON, pero no es una garantía exhaustiva. No publicar sin revisión.
3. Ejecutar desde la raíz del repositorio (Windows PowerShell):

   ```powershell
   python .\tools\verificar_cobertura_dashboards.py --repo . --export "$HOME\Downloads\grafana-dashboards-export.zip"
   ```

   Si guardaste el ZIP en otra carpeta, sustituye esa ruta. Debe mostrar **15 dashboards, 351 paneles, 15/15 coincidentes**. Si no lo conservas, omite `--export` para validar la cobertura y los SHA de los ocho nuevos.
4. Revisar `git status --short` y el contenido antes del commit. Añadir exclusivamente los ocho JSON y la herramienta:

   ```bash
   git add monitorizacion/dashboards tools/verificar_cobertura_dashboards.py
   git commit -m "feat: track all Grafana dashboards from verified export"
   git push
   ```

5. Sincronizar el proyecto Git de AWX.
6. Ejecutar únicamente **Job Template 11 — Gestionar Dashboards**, que en la versión v2 tiene el modo de escritura bloqueado por código. Confirmar:

   ```yaml
   var_grafana_dashboards_apply: false
   var_grafana_dashboards_allow_updates: false
   ```

7. Esperar `Dashboards definidos en Git: 15` y quince decisiones `SIN CAMBIOS`; `changed=0`, `failed=0`. Si aparece `CREAR` o `ACTUALIZAR`, detenerse y revisar la diferencia; **no activar escrituras**.

## Qué NO se ha implementado

- No se han cambiado dashboards del servidor ni creado nuevos. **Solo se amplía la fuente versionada.**
- No se ha activado la aplicación por API (el Job 11 permanece bloqueado en modo auditoría).
- Todavía falta una **copia de seguridad integral** de Grafana (DB, plugins, configuración, permisos, credenciales/datasources) y una **restauración probada** en un entorno separado.
- Este respaldo de JSON no permite por sí solo recuperar una instancia completa ni reconstruir los secretos de los datasources.

## Próximo bloque

Tras verificar el Job 11 con los 15: preparar backup integral y restauración segura sin tocar la instancia funcional; después evaluar sincronización declarativa solo con autorización explícita y rollback probado.
