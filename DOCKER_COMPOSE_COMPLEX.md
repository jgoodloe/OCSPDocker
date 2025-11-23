# Using Complex Structures in Docker Compose

## The Problem

Docker Compose environment variables must be simple key-value pairs. You cannot use YAML lists or nested objects directly.

## Solution: Use JSON/YAML Strings

You can pass complex structures as JSON or YAML strings in environment variables, and the entrypoint script will parse them.

### Option 1: Using CONFIG_YAML (Full YAML String)

**docker-compose.yml:**
```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  environment:
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
    - CONFIG_YAML=|
        crl_notifications:
          "http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":
            http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
          "http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":
            http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
```

### Option 2: Using CRL_NOTIFICATIONS (JSON String)

**docker-compose.yml:**
```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  environment:
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
    - CRL_NOTIFICATIONS=|
        "http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":
          http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
        "http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":
          http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
```

### Option 3: Using JSON (Single Line)

**docker-compose.yml:**
```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  environment:
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
    - CRL_NOTIFICATIONS='{"http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"},"http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"}}'
```

## Recommended: Use Config File

For complex configurations, using a mounted config file is cleaner and more maintainable:

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
    http_push_url: http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK
```

## Summary

- **Simple values**: Use environment variables directly
- **Lists**: Use comma-separated strings (e.g., `CRL_URLS`)
- **Complex structures**: Use `CONFIG_YAML` or `CRL_NOTIFICATIONS` with YAML/JSON strings, OR use a config file (recommended)

