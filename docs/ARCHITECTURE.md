# WiGuard Nexus Architecture

WiGuard Nexus is a Flask-based cybersecurity/network evidence platform. Version 5.16 keeps the existing `wiguard/` application foundation and adds a professional normalization layer instead of replacing working modules.

## Runtime flow

1. `app.py` / `main.py` creates the Flask app through `wiguard.create_app()`.
2. Uploaded evidence is handled by `wiguard.routes.actions.import_file()`.
3. `PacketTracerImportService` performs safe upload storage, hashing, source decoding, Packet Tracer bridge handling, regex/config extraction, structured JSON/XML extraction, evidence registry construction, and artifact generation.
4. `wiguard.services.professional_pipeline.attach_professional_layer()` converts the extracted objects into a stable schema for UI tables, reports, APIs, and future parsers.
5. Pages render from `wiguard.routes.pages.ctx()` using normalized objects plus the existing intelligence, topology, wireless, and report models.

## Important modules

- `wiguard/services/extractor.py` — existing import/extraction engine.
- `wiguard/services/professional_pipeline.py` — new parser registry, validation, schema normalizer, risk engine, report builder, and health checker.
- `wiguard/services/intelligence.py` — topology, policy diff, diagnostics, workspace/report models.
- `wiguard/services/product_intelligence.py` — optional stack, topology brain, threat map, release gates.
- `wiguard/routes/pages.py` — UI pages and JSON health/normalized-data APIs.
- `wiguard/routes/actions.py` — uploads, exports, reports, admin/user actions.
- `wiguard/internal_tools/` — dependency checker, preflight, project cleaner, sample data generator.

## Design rules

- Backend parsing stays outside templates.
- Raw evidence is preserved but rendered through expandable/advanced views.
- Native Packet Tracer parsing is never overstated; exported TXT/XML/JSON evidence is recommended for full fidelity.
- Secrets are redacted in normalized evidence and professional reports.
- Severity is conservative: Critical is not used without strong evidence.
