# Docker Compose Configuration Fix

## The Problem

Docker Compose environment variables must be simple key-value pairs. You cannot use YAML structures (lists, nested objects) directly in environment variables.

## Solution

### Option 1: Use Environment Variables for Simple Values + Config File for Complex Structures

**docker-compose.yml:**
```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  volumes:
    - ./ocsp/config.yaml:/app/config.yaml:ro  # Mount config file
  environment:
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
```

**config.yaml (in ./ocsp/ directory):**
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

### Option 2: Use Only Environment Variables (Simpler, but no per-CRL notifications)

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
```

Note: Per-CRL notifications require a config file.

## Fixed docker-compose.yml

```yaml
ocsp:
  build: ./ocsp
  ports:
    - "8678:8678"
  container_name: ocsp-service
  volumes:
    - ./ocsp/config.yaml:/app/config.yaml:ro
  environment:
    - CRL_ONLY=true
    - CRL_URLS=http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl,http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl
    - SCHEDULE_INTERVAL=300
    - CRL_EXPIRY_WARNING_HOURS=3
    - NOTIFICATIONS_HTTP_PUSH_URL=http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK
```

