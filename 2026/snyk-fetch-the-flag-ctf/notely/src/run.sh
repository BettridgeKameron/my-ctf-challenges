#!/usr/bin/env bash
set -e
docker build -t notely .
docker rm -f notely >/dev/null 2>&1 || true
docker run --name notely --env-file .env -p 5000:5000 notely
