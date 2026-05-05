# Troubleshooting

## Flask is missing

Run:

```bash
python -m pip install -r requirements.txt
```

## Upload says unsupported file

Use one of: `.json`, `.xml`, `.csv`, `.txt`, `.log`, `.cfg`, `.conf`, `.zip`, `.pkt`, `.pka`.

## `.pkt` import has low topology objects

Upload a companion exported config/XML/JSON file. Native Packet Tracer binary parsing is best-effort.

## Reports show no devices

Import evidence with hostnames/device names, such as `show running-config`, Packet Tracer XML, or JSON exports.

## Run health checks

```bash
python -m wiguard.internal_tools.preflight_check
python -m wiguard.internal_tools.dependency_checker
```
