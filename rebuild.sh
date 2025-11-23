#!/bin/bash
# Rebuild script for certificate checker

echo "Stopping and removing old containers..."
docker-compose down

echo "Rebuilding Docker image (no cache)..."
docker-compose build --no-cache

echo "Starting services..."
docker-compose up -d

echo "Waiting 5 seconds for container to start..."
sleep 5

echo "Showing logs (press Ctrl+C to exit)..."
docker-compose logs -f ocsp-service

