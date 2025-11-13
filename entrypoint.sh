#!/bin/bash
set -e

# If certificate path is provided via environment variable, create config
if [ -n "$CERTIFICATE_PATH" ] && [ ! -f /app/config.yaml ]; then
    echo "Creating config.yaml from environment variables..."
    cat > /app/config.yaml <<EOF
certificate: ${CERTIFICATE_PATH}
schedule_interval: ${SCHEDULE_INTERVAL:-60}
cert_expiry_warning_hours: ${CERT_EXPIRY_WARNING_HOURS:-24}
cert_expiry_warning_days: ${CERT_EXPIRY_WARNING_DAYS:-30}
crl_expiry_warning_hours: ${CRL_EXPIRY_WARNING_HOURS:-24}
crl_expiry_warning_minutes: ${CRL_EXPIRY_WARNING_MINUTES:-60}
notifications:
EOF

    if [ -n "$HTTP_PUSH_URL" ]; then
        echo "  http_push:" >> /app/config.yaml
        echo "    url: ${HTTP_PUSH_URL}" >> /app/config.yaml
    fi

    if [ -n "$WEBHOOK_URL" ]; then
        echo "  webhook:" >> /app/config.yaml
        echo "    url: ${WEBHOOK_URL}" >> /app/config.yaml
    fi

    if [ -n "$TEAMS_WEBHOOK_URL" ]; then
        echo "  teams:" >> /app/config.yaml
        echo "    url: ${TEAMS_WEBHOOK_URL}" >> /app/config.yaml
    fi

    if [ -n "$GOOGLE_CHAT_WEBHOOK_URL" ]; then
        echo "  google_chat:" >> /app/config.yaml
        echo "    url: ${GOOGLE_CHAT_WEBHOOK_URL}" >> /app/config.yaml
    fi

    if [ -n "$TWILIO_ACCOUNT_SID" ] && [ -n "$TWILIO_AUTH_TOKEN" ] && [ -n "$TWILIO_FROM" ] && [ -n "$TWILIO_TO" ]; then
        echo "  sms:" >> /app/config.yaml
        echo "    account_sid: ${TWILIO_ACCOUNT_SID}" >> /app/config.yaml
        echo "    auth_token: ${TWILIO_AUTH_TOKEN}" >> /app/config.yaml
        echo "    from: ${TWILIO_FROM}" >> /app/config.yaml
        echo "    to: ${TWILIO_TO}" >> /app/config.yaml
    fi
fi

# Check if certificate path is set
if [ -z "$CERTIFICATE_PATH" ] && [ ! -f /app/config.yaml ]; then
    echo "Error: CERTIFICATE_PATH environment variable or config.yaml file is required"
    exit 1
fi

# Run the certificate checker
exec python3 /app/check_cert.py

