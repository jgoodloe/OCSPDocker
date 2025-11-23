#!/bin/bash
set -e

# If certificate path is provided via environment variable, create config
# Also create config if CRL_ONLY is set or CRL_URLS is provided
if ([ -n "$CERTIFICATE_PATH" ] || [ -n "$CRL_ONLY" ] || [ -n "$CRL_URLS" ]) && [ ! -f /app/config.yaml ]; then
    echo "Creating config.yaml from environment variables..."
    
    # Start config file
    cat > /app/config.yaml <<EOF
schedule_interval: ${SCHEDULE_INTERVAL:-60}
cert_expiry_warning_hours: ${CERT_EXPIRY_WARNING_HOURS:-24}
cert_expiry_warning_days: ${CERT_EXPIRY_WARNING_DAYS:-30}
crl_expiry_warning_hours: ${CRL_EXPIRY_WARNING_HOURS:-24}
crl_expiry_warning_minutes: ${CRL_EXPIRY_WARNING_MINUTES:-60}
EOF

    # Add certificate if provided
    if [ -n "$CERTIFICATE_PATH" ]; then
        echo "certificate: ${CERTIFICATE_PATH}" >> /app/config.yaml
    fi
    
    # Add CRL-only mode if set
    if [ -n "$CRL_ONLY" ]; then
        echo "crl_only: ${CRL_ONLY}" >> /app/config.yaml
    fi
    
    # Add CRL URLs if provided
    if [ -n "$CRL_URLS" ]; then
        echo "crls:" >> /app/config.yaml
        # Split comma-separated URLs
        IFS=',' read -ra URLS <<< "$CRL_URLS"
        for url in "${URLS[@]}"; do
            url=$(echo "$url" | xargs)  # Trim whitespace
            if [ -n "$url" ]; then
                echo "  - $url" >> /app/config.yaml
            fi
        done
    fi
    
    # Add notifications section
    echo "notifications:" >> /app/config.yaml

    # Support both HTTP_PUSH_URL and NOTIFICATIONS_HTTP_PUSH_URL
    HTTP_PUSH_URL_VALUE="${HTTP_PUSH_URL:-${NOTIFICATIONS_HTTP_PUSH_URL}}"
    if [ -n "$HTTP_PUSH_URL_VALUE" ]; then
        echo "  http_push:" >> /app/config.yaml
        echo "    url: ${HTTP_PUSH_URL_VALUE}" >> /app/config.yaml
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

# Check if certificate path or CRL-only mode is set
if [ -z "$CERTIFICATE_PATH" ] && [ -z "$CRL_ONLY" ] && [ -z "$CRL_URLS" ] && [ ! -f /app/config.yaml ]; then
    echo "Error: CERTIFICATE_PATH, CRL_ONLY, CRL_URLS environment variable, or config.yaml file is required"
    exit 1
fi

# Run the certificate checker
exec python3 /app/check_cert.py

