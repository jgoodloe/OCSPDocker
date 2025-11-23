# Rebuild Instructions

## The Issue

The error you're seeing indicates the container is running an **old version** of the code. The traceback shows line 482, but the fixed code is now at line 510+, which means the Docker image needs to be rebuilt.

## Solution: Rebuild the Docker Image

### Option 1: Using Docker Compose (Recommended)

```bash
# Stop and remove the old container
docker-compose down

# Rebuild the image (no cache to ensure fresh build)
docker-compose build --no-cache

# Start the service
docker-compose up -d

# Check logs
docker-compose logs -f ocsp-service
```

### Option 2: Using Docker directly

```bash
# Stop the container
docker stop ocsp-service
docker rm ocsp-service

# Rebuild the image
docker build --no-cache -t certificate-checker .

# Run the container (adjust paths and env vars as needed)
docker run -d \
  --name ocsp-service \
  -v /path/to/cert:/app/piv.xcloud.authentx.com.prm.crt:ro \
  -e CERTIFICATE_PATH=/app/piv.xcloud.authentx.com.prm.crt \
  -e SCHEDULE_INTERVAL=300 \
  -e NOTIFICATIONS_HTTP_PUSH_URL="http://192.168.2.184:3001/api/push/ynOyE22dMh?status=up&msg=OK&OCSP=OK" \
  certificate-checker

# Check logs
docker logs -f ocsp-service
```

## What Was Fixed

1. **Multiple safety checks** to ensure `notifications` is always a dictionary, never `None`
2. **YAML parsing protection** - handles cases where YAML file has empty `notifications:`
3. **Initialization safety** - final check in `__init__` method
4. **All notification methods** now safely handle None values

## Verify the Fix

After rebuilding, you should see:
- No more `AttributeError: 'NoneType' object has no attribute 'get'` errors
- Successful certificate checks
- Notifications being sent (if configured)

If you still see errors after rebuilding, check:
1. The certificate file path is correct
2. The certificate file is readable
3. Network connectivity for notifications

