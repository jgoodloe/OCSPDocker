# Certificate Checker Docker Service

A Docker-based service that monitors SSL/TLS certificates, checks expiration dates, validates certificate chains, and sends notifications to multiple destinations.

## Features

- ✅ **Certificate Verification**: Check certificates directly from files (PEM or DER format)
- ✅ **Certificate Chain Validation**: Validate entire certificate chains
- ✅ **Expiration Warnings**: Configurable warnings for certificate and CRL expiration
- ✅ **Multiple Notification Methods**:
  - HTTP Push (Uptime Kuma compatible)
  - Generic Webhooks
  - Microsoft Teams
  - Google Chat
  - SMS (via Twilio)
- ✅ **Scheduled Monitoring**: Run checks at configurable intervals (60 seconds, 5 min, 15 min, 1 hour, etc.)

## Quick Start

### Using Environment Variables

```bash
docker run -d \
  -v /path/to/cert.pem:/app/certs/certificate.pem:ro \
  -e CERTIFICATE_PATH=/app/certs/certificate.pem \
  -e SCHEDULE_INTERVAL=300 \
  -e HTTP_PUSH_URL="http://192.168.2.5:3001/api/push/9TwqAsFUR0?status=up&msg=OK&OCSP=OK" \
  -e CERT_EXPIRY_WARNING_DAYS=30 \
  -e CRL_EXPIRY_WARNING_HOURS=24 \
  your-image-name
```

### Using Configuration File

1. Create a `config.yaml` file:

```yaml
certificate: /app/certs/certificate.pem
schedule_interval: 300
cert_expiry_warning_days: 30
crl_expiry_warning_hours: 24
notifications:
  http_push:
    url: http://192.168.2.5:3001/api/push/9TwqAsFUR0?status=up&msg=OK&OCSP=OK
```

2. Run the container:

```bash
docker run -d \
  -v /path/to/cert.pem:/app/certs/certificate.pem:ro \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  your-image-name
```

## Building the Image

```bash
docker build -t certificate-checker .
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTIFICATE_PATH` | Path to certificate file in container | Required |
| `SCHEDULE_INTERVAL` | Check interval in seconds | 60 |
| `CERT_EXPIRY_WARNING_HOURS` | Warn if cert expires within X hours | 24 |
| `CERT_EXPIRY_WARNING_DAYS` | Warn if cert expires within X days | 30 |
| `CRL_EXPIRY_WARNING_HOURS` | Warn if CRL expires within X hours | 24 |
| `CRL_EXPIRY_WARNING_MINUTES` | Warn if CRL expires within X minutes | 60 |
| `HTTP_PUSH_URL` or `NOTIFICATIONS_HTTP_PUSH_URL` | HTTP push notification URL | - |
| `WEBHOOK_URL` or `NOTIFICATIONS_WEBHOOK_URL` | Generic webhook URL | - |
| `TEAMS_WEBHOOK_URL` or `NOTIFICATIONS_TEAMS_WEBHOOK_URL` | Microsoft Teams webhook URL | - |
| `GOOGLE_CHAT_WEBHOOK_URL` or `NOTIFICATIONS_GOOGLE_CHAT_WEBHOOK_URL` | Google Chat webhook URL | - |
| `TWILIO_ACCOUNT_SID` or `NOTIFICATIONS_TWILIO_ACCOUNT_SID` | Twilio account SID (for SMS) | - |
| `TWILIO_AUTH_TOKEN` or `NOTIFICATIONS_TWILIO_AUTH_TOKEN` | Twilio auth token | - |
| `TWILIO_FROM` or `NOTIFICATIONS_TWILIO_FROM` | Twilio sender phone number | - |
| `TWILIO_TO` or `NOTIFICATIONS_TWILIO_TO` | Recipient phone number | - |
| `CONFIG_PATH` | Path to config.yaml file | /app/config.yaml |

**Note:** Both naming conventions are supported (e.g., `HTTP_PUSH_URL` and `NOTIFICATIONS_HTTP_PUSH_URL`). Use whichever fits your naming convention.

### Schedule Intervals

Common interval values:
- `60` - Every 60 seconds (1 minute)
- `300` - Every 5 minutes
- `900` - Every 15 minutes
- `3600` - Every hour
- `86400` - Every day

## Notification Methods

### 1. HTTP Push (Uptime Kuma)

```yaml
notifications:
  http_push:
    url: http://192.168.2.5:3001/api/push/9TwqAsFUR0?status=up&msg=OK&OCSP=OK
```

The service will append status information to the URL parameters.

### 2. Generic Webhook

```yaml
notifications:
  webhook:
    url: https://example.com/webhook
    headers:
      Content-Type: application/json
      Authorization: Bearer your-token
```

Sends a JSON payload with certificate check results.

### 3. Microsoft Teams

1. Create an Incoming Webhook in your Teams channel
2. Configure:

```yaml
notifications:
  teams:
    url: https://outlook.office.com/webhook/your-webhook-url
```

### 4. Google Chat

1. Create a webhook in your Google Chat space
2. Configure:

```yaml
notifications:
  google_chat:
    url: https://chat.googleapis.com/v1/spaces/your-space/messages?key=your-key
```

### 5. SMS (Twilio)

```yaml
notifications:
  sms:
    account_sid: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    auth_token: your-auth-token
    from: +1234567890
    to: +0987654321
```

Or via environment variables:
```bash
-e TWILIO_ACCOUNT_SID=ACxxx \
-e TWILIO_AUTH_TOKEN=xxx \
-e TWILIO_FROM=+1234567890 \
-e TWILIO_TO=+0987654321
```

## Certificate Formats

The service supports:
- **PEM format**: `-----BEGIN CERTIFICATE-----`
- **DER format**: Binary certificate files
- **Certificate chains**: Multiple certificates in a single PEM file

## Warning System

### Certificate Expiration Warnings

Warnings are triggered when:
- Certificate expires within `cert_expiry_warning_hours` hours, OR
- Certificate expires within `cert_expiry_warning_days` days

Example:
```yaml
cert_expiry_warning_hours: 24  # Warn if < 24 hours remaining
cert_expiry_warning_days: 30   # Warn if < 30 days remaining
```

### CRL Expiration Warnings

Warnings are triggered when:
- CRL expires within `crl_expiry_warning_hours` hours, OR
- CRL expires within `crl_expiry_warning_minutes` minutes

Example:
```yaml
crl_expiry_warning_hours: 24   # Warn if < 24 hours remaining
crl_expiry_warning_minutes: 60 # Warn if < 60 minutes remaining
```

## Example Docker Compose

```yaml
version: '3.8'

services:
  cert-checker:
    build: .
    volumes:
      - ./certs:/app/certs:ro
      - ./config.yaml:/app/config.yaml:ro
    environment:
      - CERTIFICATE_PATH=/app/certs/certificate.pem
      - SCHEDULE_INTERVAL=300
      - HTTP_PUSH_URL=http://192.168.2.5:3001/api/push/9TwqAsFUR0
      - CERT_EXPIRY_WARNING_DAYS=30
    restart: unless-stopped
```

## Output Format

The service outputs JSON results with the following structure:

```json
{
  "timestamp": "2024-01-01T12:00:00",
  "certificate_path": "/app/certs/certificate.pem",
  "status": "ok|warning|error",
  "certificates": [
    {
      "subject": "CN=example.com",
      "issuer": "CN=CA",
      "valid_until": "2024-12-31T23:59:59",
      "time_until_expiry": "365 days, 0:00:00",
      "hours_until_expiry": 8760.0,
      "days_until_expiry": 365,
      "warning": null
    }
  ],
  "crls": [
    {
      "url": "http://crl.example.com/crl.crl",
      "note": "CRL expiration check requires downloading the CRL file"
    }
  ],
  "warnings": []
}
```

## Troubleshooting

### Certificate file not found
- Ensure the certificate file is mounted correctly
- Check the path in `CERTIFICATE_PATH` or `config.yaml`

### Notifications not sending
- Check network connectivity from container
- Verify webhook URLs are correct
- Check logs: `docker logs <container-id>`

### Permission errors
- Ensure certificate files are readable
- Use `:ro` (read-only) mount option

## License

MIT

