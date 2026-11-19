# Operación Ubuntu 26.04 en un solo host

La ruta única vigente es [`GUIA_UNICA_UBUNTU26.md`](../../GUIA_UNICA_UBUNTU26.md). Esta guía incluye la instalación limpia desde Windows, el bootstrap K3s/AWX, las variables del host, las credenciales, la secuencia de **21 Jobs** y la recuperación sin destruir volúmenes.

La operación heredada de Ubuntu 24.04 permanece en `monitorizacion/` y no debe mezclarse con el despliegue nuevo. El bot original está empaquetado en `ubuntu-26.04/triage-bot/`; los secretos y datos se generan **solo en el host destino**.

No se ha validado todavía la secuencia completa en Ubuntu 26.04. No lanzar el workflow en producción sin autorización, DNS/TLS internos y las credenciales indicadas en la guía.
