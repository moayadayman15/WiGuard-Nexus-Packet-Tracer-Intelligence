# WiGuard Nexus v5.12.4 API Notes

## Authentication

Create an API token from **Settings → Create API Token**. Use the raw token once; WiGuard stores only a SHA-256 hash and token prefix.

```bash
curl -H "Authorization: Bearer wgn_xxx" http://127.0.0.1:5000/api/v1/state
```

## Event Ingestion

Requires an API token with `ingest` scope.

```bash
curl -X POST http://127.0.0.1:5000/api/v1/events \
  -H "Authorization: Bearer wgn_xxx" \
  -H "Content-Type: application/json" \
  -d '{"connector_type":"syslog_events","events":[{"timestamp":"2026-04-28T10:00:00Z","client":"aa:bb:cc:dd:ee:ff","message":"authentication fail on StaffWiFi","ssid":"StaffWiFi","ap":"AP-01"}]}'
```

## Polling Events

Browser/session users with auditor+ role can poll:

```bash
curl http://127.0.0.1:5000/api/events?since_id=0&limit=100
```

## Connector Strategy

- API-based connectors expose credential testing and safe sync preview.
- Full vendor pagination is intentionally read-only and can be expanded per deployment.
- CSV/JSON exports are normalized into the same AP/session/event model.
