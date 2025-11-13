# Quick Start Guide

## Prerequisites

- Docker installed
- A certificate file (PEM or DER format)

## Step 1: Prepare Your Certificate

Place your certificate file in a directory, for example:
```bash
mkdir -p certs
cp your-certificate.pem certs/certificate.pem
```

## Step 2: Build the Docker Image

```bash
docker build -t certificate-checker .
```

## Step 3: Run the Container

### Option A: Using Environment Variables (Simplest)

```bash
docker run -d \
  --name cert-checker \
  -v $(pwd)/certs:/app/certs:ro \
  -e CERTIFICATE_PATH=/app/certs/certificate.pem \
  -e SCHEDULE_INTERVAL=300 \
  -e HTTP_PUSH_URL="http://192.168.2.5:3001/api/push/9TwqAsFUR0?status=up&msg=OK&OCSP=OK" \
  -e CERT_EXPIRY_WARNING_DAYS=30 \
  certificate-checker
```

### Option B: Using Configuration File

1. Copy the example config:
```bash
cp config.yaml.example config.yaml
```

2. Edit `config.yaml` with your settings

3. Run:
```bash
docker run -d \
  --name cert-checker \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  certificate-checker
```

### Option C: Using Docker Compose

1. Copy the example compose file:
```bash
cp docker-compose.yml.example docker-compose.yml
```

2. Edit `docker-compose.yml` with your settings

3. Run:
```bash
docker-compose up -d
```

## Step 4: Check Logs

```bash
docker logs -f cert-checker
```

You should see output like:
```
[2024-01-01 12:00:00] Running certificate check...
Status: ok
Notifications sent to: http_push
Scheduling checks every 5 minutes
Scheduler started. Press Ctrl+C to stop.
```

## Common Schedule Intervals

- `60` - Every 60 seconds (1 minute)
- `300` - Every 5 minutes  
- `900` - Every 15 minutes
- `3600` - Every hour
- `86400` - Every day

## Notification Setup Examples

### Uptime Kuma HTTP Push
```bash
-e HTTP_PUSH_URL="http://your-uptime-kuma:3001/api/push/YOUR_KEY?status=up&msg=OK&OCSP=OK"
```

### Microsoft Teams
1. In Teams, go to your channel → Connectors → Incoming Webhook
2. Create webhook and copy URL
3. Set: `-e TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."`

### Google Chat
1. In Google Chat, create a webhook
2. Set: `-e GOOGLE_CHAT_WEBHOOK_URL="https://chat.googleapis.com/v1/spaces/..."`

### SMS (Twilio)
```bash
-e TWILIO_ACCOUNT_SID="ACxxx" \
-e TWILIO_AUTH_TOKEN="xxx" \
-e TWILIO_FROM="+1234567890" \
-e TWILIO_TO="+0987654321"
```

## Troubleshooting

**Certificate not found:**
- Check the path in `CERTIFICATE_PATH` matches the mounted volume
- Ensure the file is readable

**Notifications not working:**
- Check network connectivity from container
- Verify webhook URLs are correct
- Check logs: `docker logs cert-checker`

**Container exits immediately:**
- Check logs: `docker logs cert-checker`
- Ensure `CERTIFICATE_PATH` is set or `config.yaml` exists

