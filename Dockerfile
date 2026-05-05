# WiGuard Nexus Live Ingestion

v5.12.4 supports live ingestion through a safe HTTP API by default:

```bash
curl -X POST http://127.0.0.1:5000/api/v1/events \
  -H "Authorization: Bearer wgn_xxx" \
  -H "Content-Type: application/json" \
  -d '{"connector_type":"syslog_events","events":[{"message":"authentication fail client aa:bb:cc:dd:ee:ff ssid=StaffWiFi ap=AP-01"}]}'
```

For production deployments that need raw UDP syslog, see `wiguard/services/live_ingestion.py`. It contains a stdlib-only UDP listener skeleton that parses syslog lines and forwards normalized records into the same event model. The listener is not auto-started by Flask to avoid opening network ports during demos.
