# WiGuard Nexus Deployment Guide

## Local

```bash
pip install -r requirements.txt
python app.py
```

Create the first admin from `/register`, then set `WIGUARD_DISABLE_DEMO_FALLBACK=1`.

## Docker

```bash
docker compose up --build
```

Important production variables:

- `WIGUARD_ENV=production`
- `WIGUARD_SECRET_KEY=<long random secret>`
- `WIGUARD_DISABLE_DEMO_FALLBACK=1`
- `WIGUARD_MAX_UPLOAD_BYTES=52428800`
- `WIGUARD_LOGIN_MAX_FAILURES=5`
- `WIGUARD_LOGIN_RATE_WINDOW_SECONDS=900`

## Health Check

`GET /healthz` returns database and storage status.

## Backup / Restore

Open Settings → Database Backup / Restore. A restore automatically creates a safety backup first.

## PostgreSQL Roadmap

The docker-compose file includes a commented PostgreSQL service. v5.3 keeps SQLite as the default durable store for the capstone demo while exposing the deployment scaffold for a PostgreSQL-backed enterprise release.
