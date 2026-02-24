#!/usr/bin/env bash
set -e
docker build -t vibecoding .
docker rm -f vibecoding >/dev/null 2>&1 || true
docker run --name vibecoding --env-file .env -p 5000:5000 vibecoding
