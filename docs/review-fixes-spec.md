# Review fixes — 2026-11-03

Scope: shared detector state on both branches; LLM response validation, timeout defaults and benchmark counters on the LLM branch; branch-specific README commands. No production changes or raw-log commits.

## Atomic goals and independent checks

1. Inline: add regressions before production edits. Inputs/expected below; run focused tests and observe failures.
2. Inline: reject missing/null required LLM fields; reuse the existing retry/schema-error path. Both constructors use the existing Ollama defaults. Check valid false/zero/empty-array values and retry recovery.
3. Inline: merge batch CLI files chronologically using the shared parser (O(input size) batch memory), then correct event-time cooldown and bound per-key history. Check independent old attacks, reversed inputs, exact boundaries, existing idle cleanup and capacity tests. Apply identical shared files to both branches only after local review.
4. Inline: count each technique as one-vs-rest. Check wrong technique => truth FN and predicted FP, normal => predicted FP, correct => TP, missed => FN.
5. Inline: correct branch README commands and snapshot/journal behavior. Check help and actual command source.
6. Inline verification: gofmt, focused tests, full tests, race tests, build, diff review on each branch. No delegated implementation or verification.

## Time semantics

A detector operates on a bounded event-time neighborhood. On each Add, retain only records within one configured window before/after that event; a match must fit within one window. This supports reverse arrivals within that neighborhood and drops distant future history when moving to an older independent segment. After evaluation, at most 2*(threshold-1) timestamps remain per key, because any threshold records within a window are consumed together. Keys remain capped at 10,000. Arbitrarily shuffled distant segments cannot be joined with finite state; historical inputs should be ordered by timestamp before replay. No claim of unlimited out-of-order reconstruction.

Cooldown suppresses records within one window on either side of the previous alert timestamp; a separate older cluster beyond that window must still alert. Clock-based idle cleanup remains unchanged.

## Regression inputs / expected

- LLM: {}, null, missing each required field, null required values => two attempts, engine=invalid, status=schema_error. Complete {is_attack:false,confidence:0,findings:[]} remains valid. Invalid then valid response => valid on attempt 2.
- Timeout: zero/negative config => positive 10s context deadline, responsive client succeeds; explicit timeout preserved; standard Ollama constructor applies URL/model defaults too.
- Auth threshold5/window20s: clusters t=100..104 then t=0..4 => two alerts; adjacent backward records inside cooldown do not duplicate.
- Tracker threshold6/window30s: 1,000 descending timestamps => attacks detected and retained history <=10 after every input; reverse sparse timestamps => bounded history without false alerts.
- Batch: a.log contains t=0,1,100,101,102 and b.log contains t=2,3,4,103,104 for the same auth IP => two attacks after chronological merge, on both CLI branches. Invalid and non-event records still count separately; read/scanner errors remain fatal.
- Existing late-record case t=20,21,0,1,2/window10/threshold3 => alert only for t=0..2.
- Technique truth T1595, prediction T1110 => T1595 FN1 / T1110 FP1; normal prediction T1110 => FP1; same technique => TP1; missed attack => FN1.
