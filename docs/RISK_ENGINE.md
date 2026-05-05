# Risk Engine

The professional risk engine converts normalized assets into evidence-based findings.

## Current detection coverage

- Weak/open wireless security
- Cleartext credential indicators with redaction
- Duplicate IP address candidates
- Flat network / weak segmentation indicators
- Missing ACL/firewall evidence
- Interface hygiene issues
- Exposed management service evidence when service rows exist

## Finding schema

Each finding includes:

- `title`
- `severity`
- `confidence`
- `affected_asset`
- `evidence`
- `why_it_matters`
- `recommendation`
- `source_reference`
- `category`

## Severity rules

- Critical is reserved for strong, confirmed dangerous exposure.
- High requires confirmed dangerous misconfiguration or secret exposure.
- Medium indicates likely weakness.
- Low indicates evidence gap or improvement.
