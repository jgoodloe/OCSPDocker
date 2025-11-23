# Fixing CRL_NOTIFICATIONS YAML Syntax

## The Problem

Your current `CRL_NOTIFICATIONS` has syntax errors:
- Missing colons after `http_push_url`
- Incorrect quote placement
- Malformed YAML structure

## The Fix

### Option 1: Corrected YAML Format (Multiline)

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
          http_push_url: "http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"
        "http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":
          http_push_url: "http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK"
```

**Key fixes:**
- Changed `http_push_url":` to `http_push_url:` (removed extra quote, added colon)
- Proper indentation (2 spaces for nested items)
- Quotes around URLs are optional but recommended

### Option 2: JSON Format (Single Line - Easier)

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
    - CRL_NOTIFICATIONS='{"http://crl.xca.xpki.com/CRLs/XTec_PIVI_CA1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"},"http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":{"http_push_url":"http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK"}}'
```

### Option 3: Use Config File (Recommended for Complex Configs)

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

## Your Corrected docker-compose.yml

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
          http_push_url: "http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK"
        "http://crl.xcatest2.xpki.com/CRLs/XTec_PIVI_Test2_CA_1.crl":
          http_push_url: "http://192.168.2.184:3001/api/push/9TwqAsFUR0?status=up&msg=OK"
```

**Changes made:**
1. Fixed `http_push_url":` → `http_push_url:` (removed extra quote, added colon)
2. Proper indentation (2 spaces)
3. Quotes around URLs for safety

