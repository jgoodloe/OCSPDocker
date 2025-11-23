# Fixing Docker Compose YAML Error

## The Problem

Docker Compose cannot parse multiline YAML strings in environment variables using the `|` syntax because it tries to parse them as part of the docker-compose.yml structure itself.

## Solution: Use JSON Format (Single Line)

The `CRL_NOTIFICATIONS` environment variable must be a **single-line JSON string**:

```yaml
- CRL_NOTIFICATIONS={"http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"},"http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK"}}
```

## Your Complete Fixed docker-compose.yml

```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  environment:
    - CERTIFICATE_PATH=/app/piv.xcloud.authentx.com.prm.crt
    - SCHEDULE_INTERVAL=300
    - CERT_EXPIRY_WARNING_DAYS=30
    - CRL_EXPIRY_WARNING_HOURS=3
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
    - CRL_NOTIFICATIONS={"http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"},"http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK"}}
```

## Alternative: Use Config File (Recommended)

For complex configurations, use a config file instead:

**docker-compose.yml:**
```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  volumes:
    - ./ocsp/config.yaml:/app/config.yaml:ro
  environment:
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
```

**./ocsp/config.yaml:**
```yaml
crl_only: true
crls:
  - http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl
  - http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl

schedule_interval: 300
crl_expiry_warning_hours: 3

notifications:
  http_push:
    url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK

crl_notifications:
  "http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":
    http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
  "http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":
    http_push_url: http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK
```

## Why the Multiline Format Doesn't Work

When you use:
```yaml
- CRL_NOTIFICATIONS=|
    "http://..."
```

Docker Compose tries to parse the indented lines as part of the YAML structure, not as a string value. This causes the "mapping values are not allowed in this context" error.

The entrypoint script will automatically parse the JSON string and convert it to YAML format in the config file.

