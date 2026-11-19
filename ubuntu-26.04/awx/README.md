# AWX en un único host Ubuntu 26.04

El bootstrap instala AWX en K3s. El Job 08 reutiliza ese mismo clúster.

Consulta `bootstrap/README.md`, `workflow/README.md` y `../docs/OPERACION_MONOHOST.md`.

**Alerting original:** el Job 18 añade 10 reglas pausadas por defecto, tras el 16; las notificaciones reales requieren credencial de contactos y autorización independiente. Consulta `../alerting/README.md`.
