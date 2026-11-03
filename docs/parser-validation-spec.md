# Parser and LLM validation changes — 2026-11-03

Scope: shared parser/batch provenance on main and LLM; LLM request schema, grounded output validation, no automatic reclassification, caller metadata, configurable timeout and visible failures on LLM only. Keep rule alerts independent. Preserve missing-IP Fly records and existing report counters. No server/model changes, new dependencies, production traffic or remote pushes.

## Dependency-ordered atomic goals

1. Parent inline: inspect status/diffs, parser/client/evaluator callers and tests; add focused failing regressions before production changes.
2. Parent inline: common post-extraction event validation. Output: valid canonical IP or explicit error, HTTP100..599, known authentication status normalization and UNKNOWN for absent/unrecognized outcomes. Missing IP remains empty. Batch records preserve source path and original line number even after sorting. Independent parent check: table cases, existing formats and actual source audit counts.
3. Parent inline: actual Ollama JSON-schema request with temperature0; strict single JSON response, no Markdown cleanup or free-text extraction; remove second inference on parse/schema failure. Output: valid / parse_error / schema_error, one attempt only. Network fallback remains explicit engine=fallback_rule and preserves timeout/unavailable status. Independent checks: httptest request capture and replay of the saved real malformed attack response.
4. Parent inline: validate supported MITRE IDs, required finding text and evidence IDs1..N without duplicates. Pass actual event count/stats to both CLI and benchmark. The legacy string-only EvaluateContext path cannot validate attack evidence without a count and must not silently approve it. Independent checks: injected edge responses, mock server through actual CLI, benchmark caller metadata.
5. Parent inline: -llm-timeout duration flag on CLI/benchmark, default120s for this CPU environment, reject nonpositive flag values. Invalid/degraded results displayed explicitly; rule alerts persist. No asynchronous worker architecture in this change.
6. Background codex gathering only: enumerate stale documentation/examples about retry behavior, 5s timeout and ungrounded EvaluateContext; no edits/builds/tests/model requests. Output: short file:line list; parent opens every cited location before editing.
7. Parent inline: focused green, full tests/race/build on both branches; installed llama3.1:8b repeated synthetic normal/auth/scanning smoke with configured120s. Save every success/failure and raw result; never repeat until pass. Tiny synthetic set is not field accuracy. Review diff, port only shared files with git cherry-pick, document results, comment/update issues.

## Regression inputs and expected results

- Project ip=not-an-ip -> error; empty IP -> parsed partial record; IPv6 alternate spellings and IPv4-mapped IPv6 -> canonical address.
- Project and combined status999/099/non-numeric -> error; HTTP100/599 valid.
- Authentication failed/failure -> FAIL, succeeded -> SUCCESS; absent/unrecognized -> UNKNOWN.
- Batch malformed line retains its original path and line number after sorting; diagnostic includes path:line and cause.
- API request contains schema required is_attack/confidence/findings, supported technique enum, finite bounds, nonstreaming and temperature0.
- Real saved attack response with explanatory prose + JSON and a later mock benign response -> first response rejected, no second inference, one attempt and parse_error.
- Missing/null fields, unknown JSON fields, duplicate JSON object keys, trailing data, code fences -> invalid, never approve normal by default.
- Valid attack with evidence0/-1/N+1/duplicates or unknown/empty technique -> schema_error; valid evidence1..N -> valid. Missing N cannot approve attack evidence.
- Mock CLI endpoint returns invalid or normal LLM JSON during rule-positive input -> rule alert remains; malformed JSON is not printed as LLM normal.
- Explicit timeout flag respected by actual request; invalid timeout rejected before opening journal/network requests.
- Existing skueat collection remains1056 read /127 HTTP /929 non-events /0 errors /127 missing IP, with no invented sessions.

## Decisions and limits

Strict schema validity is distinct from factual correctness. UNKNOWN authentication outcomes are retained as partial evidence and do not become successes/failures. Unknown extra input fields stay tolerated for compatibility; malformed recognized fields do not. LLM structured-output schema and local checks agree; neither proves the model conclusion. Existing synchronous model calls can block live consumption; queue/throughput work stays a separate issue. Source diagnostics for batch records are exact original line numbers; live tail offsets must not be invented.
