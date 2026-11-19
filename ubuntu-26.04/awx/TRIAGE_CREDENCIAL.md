# Credencial AWX del Security Triage Bot

Crea un Credential Type llamado `Triage Bot - variables privadas` (si el nombre de tipo ya existe, reutilízalo) y una credencial de ese tipo con **nombre exactamente** `Triage - Secretos 26.04`. Los valores nunca se guardan en Git, inventarios ni Extra Variables.

## Input Configuration (Credential Type)

```yaml
fields:
  - id: webhook_token
    type: string
    label: Token del webhook Wazuh y Grafana
    secret: true
  - id: metrics_token
    type: string
    label: Token independiente de métricas
    secret: true
  - id: indexer_password
    type: string
    label: Contraseña usuario de solo lectura del Indexer
    secret: true
  - id: gemini_api_key
    type: string
    label: Clave Gemini (opcional)
    secret: true
  - id: smtp_password
    type: string
    label: Contraseña SMTP (opcional)
    secret: true
  - id: telegram_bot_token
    type: string
    label: Token Telegram (opcional)
    secret: true
  - id: telegram_chat_id
    type: string
    label: Chat ID Telegram (opcional)
    secret: true
required:
  - webhook_token
  - metrics_token
  - indexer_password
```

## Injector Configuration (Credential Type)

```yaml
env:
  VAR_TRIAGE_WEBHOOK_TOKEN: '{{ webhook_token }}'
  VAR_TRIAGE_METRICS_TOKEN: '{{ metrics_token }}'
  VAR_TRIAGE_INDEXER_PASSWORD: '{{ indexer_password }}'
  VAR_TRIAGE_GEMINI_API_KEY: '{{ gemini_api_key }}'
  VAR_TRIAGE_SMTP_PASSWORD: '{{ smtp_password }}'
  VAR_TRIAGE_TELEGRAM_BOT_TOKEN: '{{ telegram_bot_token }}'
  VAR_TRIAGE_TELEGRAM_CHAT_ID: '{{ telegram_chat_id }}'
```

Rellena `webhook_token`, `metrics_token` (ambos aleatorios independientes de al menos 32 caracteres) y `indexer_password` (12 o más caracteres). No reutilices la contraseña de administrador. Mantén deshabilitadas las notificaciones hasta introducir correo y destinatarios autorizados en el inventario; usa las variables `var_triage_mail_enabled` y `var_triage_telegram_enabled` de la guía.

El Job 14 usa también la credencial `Wazuh - Credenciales 26.04`. Esta debe inyectar `VAR_WAZUH_ADMIN_PASSWORD` al entorno del Job. El usuario de solo lectura se crea mediante la API del Indexer cuando aún no existe y **no se sustituye su contraseña** en reintentos: si el valor almacenado en AWX y el usuario real difieren, falla antes de desplegar el bot.

El código original del bot no conserva contraseñas: `/opt/security-triage-bot/.env*`, `.local-secrets/`, los secretos TLS y los archivos de datos solo existen en el servidor. La credencial SMTP/Telegram debe residir en AWX, no en el repositorio.
