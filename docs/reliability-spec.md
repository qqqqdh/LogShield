# Reliability and validation specification

Scope: both `main` and the LLM branch. Public website URL is context only; do not send test traffic to it or infer private server logs from the page.

## Dependency order

1. Normalize supported input into one `normalizer.Event` shape. Detectors and CLIs consume only that shape.
2. Feed events from all tailed files through one ordered analyzer worker per process. Bound input queues and surface errors.
3. Persist every detected alert to an append-only JSONL journal before presenting it in the bounded TUI. A report is a snapshot, not the complete audit trail.
4. Document supported formats and commands. Evaluate LLM against labeled external samples; do not present the built-in examples as field accuracy.

## Acceptance inputs and expected results

- Existing RFC3339 `service=auth action=login status=FAIL` remains `auth/login/FAIL`.
- OpenSSH syslog `Oct 28 10:00:00 host sshd[12]: Failed password for invalid user root from 203.0.113.1 port 22 ssh2` -> `ssh/auth/root/203.0.113.1/FAIL` with year and timezone from explicit reference time.
- OpenSSH accepted-password line -> `ssh/auth/SUCCESS`; unrelated syslog must be rejected, never fabricated as an event.
- Combined web access `203.0.113.2 - - [28/Oct/2026:10:00:00 +0900] "GET /.env?x=1 HTTP/1.1" 404 12 "-" "scanner"` -> `web`, IP `203.0.113.2`, path `/.env`, status `404`, correct offset timestamp.
- Malformed/unsupported input returns an error and cannot contribute to detection.
- Interleaved lines from two files pass through one analyzer worker; five auth failures from one IP trigger one alert with no state race.
- More than 100 alerts while paused: TUI retains its severity selection policy, while all detected alerts remain in the JSONL journal, including those absent from a later report snapshot. Journal write failures are visible.
- Old per-IP state expires without requiring the same IP to appear again. Capacity pressure must not retain stale blocking state.
- Benchmark accepts a labeled dataset supplied by the operator and reports sample count plus provenance; no claim of production detection accuracy without such data.

## Labeled LLM evaluation

The LLM branch accepts `go run ./cmd/benchmark -dataset labeled.json -output benchmark_report.json`. The JSON file must contain `reference_time` (RFC3339) and a nonempty `samples` array. Each sample needs a unique `id`, `is_attack_ground`, `ground_technique` (`None` for normal), and `events` containing raw log lines. Example:

```json
{
  "reference_time": "2026-10-28T12:00:00+09:00",
  "samples": [
    {
      "id": "normal-1",
      "is_attack_ground": false,
      "ground_technique": "None",
      "events": ["2026-10-28T10:00:00+09:00 service=web action=get ip=203.0.113.2 status=200 path=/"]
    }
  ]
}
```

The benchmark derives the LLM context from the same parsed events used by the rule baseline. Its built-in seven examples are synthetic and only check the evaluation pipeline. `llm_valid_count` and `llm_call_count` distinguish actual model responses from attempts that fell back to rules. An unavailable Ollama endpoint cannot establish model accuracy. To measure detection quality on `skueat.fly.dev`, collect representative access/authentication logs, remove secrets and personal data, label normal and attack sessions independently, and run the benchmark on those samples. A public site URL does not supply those logs.

## Verification boundary

Run focused red tests before fixes, full Go tests and race tests after. Real-site detection quality, Fly logs, Ollama behavior, and sustained load require user-supplied logs or a controlled environment and are not established by unit tests.
