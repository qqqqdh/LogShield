# LogShield — LLM 브랜치

Go 기반 규칙 탐지에 Ollama를 통한 LLM 행위 문맥 분석을 추가한 실험용 Mini IDS입니다. 프롬프트의 공격 기법 질의가 실제 탐지 성능을 보장하지는 않습니다.

## 준비

Go 1.25.1 이상이 필요합니다. 실제 LLM 평가에는 별도로 Ollama 서버와 지정한 모델이 필요합니다. 기본 엔드포인트는 `http://localhost:11434`, 모델은 `llama3.1:8b`입니다.

```powershell
go mod download
go test ./...
```

## 실행

```powershell
# 합성 테스트 로그 생성 (운영 로그 디렉터리와 분리)
go run ./cmd/loggen -out ./sample-logs -count 100

# 기존 *.log 배치 분석: 규칙만 사용
go run ./cmd/logshield -log-dir ./sample-logs -llm=false -report report.json -alerts-file alerts.jsonl

# 규칙 + LLM: 기본 LLM 활성화, -print-prompt로 생성 문맥 확인 가능
go run ./cmd/logshield -log-dir ./sample-logs -ollama-url http://localhost:11434 -llm-model llama3.1:8b -llm-timeout 120s

# 실시간 CLI: Ctrl+C로 종료 후 보고서 저장
go run ./cmd/logshield -log-dir ./logs -watch -report report.json -alerts-file alerts.jsonl

# 실시간 규칙 TUI (이 화면에는 LLM 분석이 연결되어 있지 않음)
go run ./cmd/logshield-tui -log-dir ./logs -alerts-file alerts.jsonl

# 정확한 한 파일의 파싱·출처 집계
go run ./cmd/logaudit -input ./logs/fly.jsonl -output audit.json

# 독립적으로 정답을 붙인 데이터셋으로 평가
go run ./cmd/benchmark -dataset labeled.json -output benchmark_report.json -llm-timeout 120s
```

두 브랜치에서 `loggen`은 생성기, `logshield-tui`는 실제 감시 화면입니다. 공통 감시 옵션은 `-log-dir ./logs`, `-alerts-file alerts.jsonl`입니다. 생성 옵션은 `-out ./sample-logs`, `-count 100`, `-force=false`입니다. 입력 폴더와 출력 폴더의 용도를 구분합니다.

생성 대상 auth.log·ssh.log·web.log 중 기존 파일이 하나라도 있으면 기본 실행은 중단합니다. 테스트 로그를 의도적으로 교체할 때만 `go run ./cmd/loggen -out ./sample-logs -count 100 -force`를 사용하세요. 개수는 양수여야 하며 다른 파일은 변경하지 않습니다. 기본 생성 위치는 이전 `./logs`에서 `./sample-logs`로 바뀌었습니다. `-force`는 세 파일을 하나의 트랜잭션으로 교체하지 않으므로 오류 발생 시 일부 출력만 갱신될 수 있습니다. [명령 통일 명세](docs/command-consistency-spec.md)를 참고하세요.

이전 main에서 감시용으로 쓰던 `loggen -log-dir ...`는 `logshield-tui -log-dir ...`로 바꿔야 합니다. LLM 전용 CLI 옵션과 브랜치별 TUI 세부 기능은 유지됩니다.

기존에 발견한 파일을 tail하며 새 파일 자동 발견은 지원하지 않습니다. 배치 CLI는 전체 파일을 읽어 이벤트 시간순으로 합친 후 분석하므로 메모리가 입력 크기에 비례합니다. 실시간 탐지기는 제한된 상태를 유지하며 입력 시각 전후 한 시간창의 역순 도착을 결합합니다. 서로 먼 과거 구간의 임의 혼합을 완전히 복원하지는 않습니다.

## 분석과 저장의 의미

공통 파서는 프로젝트 key=value 로그, OpenSSH 인증 syslog, combined access, 지원되는 Fly JSON HTTP 요청 메시지를 처리합니다. 지원하지 않는 플랫폼 메시지와 잘못된 입력은 각각 비이벤트와 파싱 오류로 집계합니다. IP 표기는 공통 검증 단계에서 통일하고, 잘못된 IP나 HTTP 상태값(100~599 밖)은 오류로 기록합니다. 인증 결과를 알 수 없으면 `UNKNOWN`으로 보존합니다. 배치 오류는 원본 파일과 행번호를 포함합니다. 입력에 없는 IP를 만들어내지 않으며 IP 누락 이벤트는 LLM 세션에도 넣지 않습니다.

기본 규칙은 동일 IP의 auth/login 실패 5회/20초, SSH 실패 6회/30초, 민감한 웹 경로의 HTTP 401·403·404 응답 4회/30초입니다. CLI는 이상 점수가 임계치에 도달한 세션을 LLM으로 평가합니다. 네트워크 실패 시 규칙 폴백을 구분해 반환합니다. Ollama에 JSON 스키마와 temperature=0을 전달하고 한 번만 평가합니다. 필수 필드 누락/null·알 수 없는 필드·중복 키·지원하지 않는 기법·범위 밖 또는 중복 근거 번호는 검증 실패입니다. 형식 오류 뒤 자동 재판정은 하지 않습니다. 실패는 `invalid` 또는 `fallback_rule` 엔진 및 `parse_error`/`schema_error`/`timeout`/`unavailable` 상태로 표시하며 규칙 경고는 유지합니다. 잘못된 모델 응답은 `raw_response`에 보관합니다. `-llm-timeout`은 기본 120초이며 양수여야 합니다. 긴 동기식 LLM 호출 동안 실시간 로그 소비는 지연될 수 있습니다.

CLI의 `report.json`은 종료할 때 덮어쓰는 요약 객체입니다. 주요 필드는 다음과 같습니다.

- `timestamp`, `total_logs_read`, `total_logs_analyzed`, `parse_errors`
- `non_event_records`, `missing_ip_events`, `active_sessions_count`, `watch_failures`
- `rule_based_alerts`, `llm_icl_evaluations`: 각각 최근 최대 100건
- `rule_alerts_omitted_from_report`, `llm_evaluations_omitted_from_report`: 요약에서 제외된 건수

모든 탐지 경고는 별도 `alerts.jsonl` 저널에 누적됩니다. 각 줄은 `{"recorded_at":"...","alert":{"ts":"...","rule_id":"...","severity":"...","message":"..."}}` 형태입니다. 기록 시각과 탐지를 완성한 이벤트 시각을 구분하며, 저널은 자동 회전하지 않으므로 보관·용량 관리가 필요합니다.

TUI의 `p`는 화면 반영만 일시정지합니다. 임시 경고 최대 100건을 중요도와 최신 시각 우선으로 보관하고 재개하면 시간순으로 반영합니다. 화면 이력도 최대 100건이며 전체 기록은 저널에 남습니다. 이 브랜치 TUI에는 별도 JSON 보고서 저장 키가 없습니다.

## 평가 한계

`-dataset`을 생략한 기본 7개 예시는 합성 데이터로, 운영 탐지 정확도 증거가 아닙니다. 보고서는 네 모드의 결과와 데이터 출처를 포함하며 `llm_valid_count`/`llm_call_count`로 실제 모델 응답과 시도 횟수를 구분합니다. 폴백 수치를 실제 LLM 정확도로 해석하면 안 됩니다.

제공된 skueat 로그 수집본은 HTTP 클라이언트 IP와 정답 라벨이 없어 파싱 검증에만 사용했습니다. 운영 탐지 성능 평가는 클라이언트 식별 정보와 인증 결과를 포함한 비식별 로그 및 독립 라벨이 필요합니다.

데이터셋 형식은 [신뢰성 명세](docs/reliability-spec.md), 수집본 검증은 [Fly 로그 검증](docs/fly-log-validation.md), 최신 파서·검증기 계약은 [파서 검증 명세](docs/parser-validation-spec.md), 이전 역순 처리 조건은 [수정 명세](docs/review-fixes-spec.md)를 참고하세요.
