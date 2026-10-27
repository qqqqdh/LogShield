# Fly log validation contract

Route: implement and review inline. Raw operational data stays outside the repository.

Dependency order:
1. Parse Fly attributes JSONL and API-record envelopes into the shared Event.
2. Add a file audit command that runs the existing Analyzer and prints aggregate counts only.
3. Run both branches against the local source and independently reconcile JSONL with API pages.

Inputs and expected results:
- {"timestamp":"2026-10-28T10:00:00Z","message":"INFO [200] GET /?q=example (1ms)"} -> web/get/200, path "/", exact timestamp, empty IP.
- API {"attributes":{...}} envelope -> same Event.
- Fly startup/platform message -> ErrNonEvent, counted separately from malformed input.
- Missing/invalid timestamp for an HTTP request -> error; never infer a request timestamp.
- Raw request without a timestamp -> unsupported, never fabricate a time or IP.
- Audit of a request without IP -> one normalized event, one missing-IP event, zero attributed events.
- Unknown ground truth -> no accuracy, precision, or recall calculated.
- Full-file audit counts and SHA-256 must reconcile with source records independently. Keep operational traffic totals and raw samples in the local audit folder.

Run `go run ./cmd/logaudit -input <exact-file.jsonl> -output <local-report.json>` on either branch. The audit command accepts one exact file path, including `.jsonl`; directory-based live commands retain their existing file selection. It reports normalized requests, non-event records, malformed records, missing IPs, statuses and alert totals. It never computes accuracy for unlabeled data.

The LLM branch does not create IP-based sessions for events without a source IP. Its report counts these events explicitly instead of merging unrelated visitors into an empty-IP session.

No production logging configuration or live traffic is modified. A zero alert count with missing source IPs does not establish safety.
