# LogShield — main 브랜치

Go로 작성한 로그 기반 Mini IDS입니다. 공통 파서로 인증·SSH·웹 로그를 정규화하고, 로그인 실패 반복과 민감한 웹 경로 탐색을 규칙으로 탐지합니다.

## 준비

Go 1.25.1 이상이 필요합니다. 저장소 루트에서 실행합니다.

```powershell
go mod download
go test ./...
```

## 명령별 역할

| 명령 | 실제 동작 | 결과 저장 |
| --- | --- | --- |
| `go run ./cmd/logshield -log-dir ./logs` | 기존 `*.log` 파일을 이벤트 시간순으로 합쳐 일괄 분석 | 표준 출력 |
| `go run ./cmd/loggen -out ./sample-logs -count 100` | 합성 테스트 로그 생성 | auth.log, ssh.log, web.log |
| `go run ./cmd/logshield-tui -log-dir ./logs -alerts-file alerts.jsonl` | 실제 로그를 tail하는 규칙 기반 TUI | 모든 탐지 경고를 JSONL 저널에 누적 |
| `go run ./cmd/logshield-demo` | 합성 경고를 보여주는 데모 TUI | 실제 로그 분석용이 아님 |
| `go run ./cmd/logaudit -input ./logs/fly.jsonl -output audit.json` | 지정한 한 파일의 파싱·출처·상태 코드·IP 누락 집계 | 감사 요약 JSON |

두 브랜치에서 `loggen`은 생성기, `logshield-tui`는 실제 감시 화면입니다. `-out`은 생성할 폴더이고 `-log-dir`은 읽을 폴더입니다. 생성기 기본 출력은 `./sample-logs`, 기본 개수는 파일당 100건입니다. 기존 대상 파일이 하나라도 있으면 기본 실행은 중단합니다. 테스트 로그를 의도적으로 교체할 때만 `-force`를 사용하세요. `-count`는 양수여야 하며, 다른 파일은 변경하지 않습니다. `-force`는 파일별 교체이므로 오류가 발생하면 일부 출력만 갱신될 수 있습니다.

이전 main의 `go run ./cmd/loggen -log-dir ./logs -alerts-file alerts.jsonl`은 이제 `go run ./cmd/logshield-tui -log-dir ./logs -alerts-file alerts.jsonl`로 바꿔야 합니다. 이전 데모는 `go run ./cmd/logshield-demo`로 실행합니다. 생성기에 예전 감시 플래그를 주면 도움말과 함께 오류로 종료합니다.

```powershell
# 두 브랜치 공통: 테스트 전용 폴더에 생성하고 같은 폴더를 감시
go run ./cmd/loggen -out ./sample-logs -count 100
go run ./cmd/logshield-tui -log-dir ./sample-logs -alerts-file sample-alerts.jsonl
```

실제 로그를 tail하는 동안 새 줄을 분석하며, 새 파일의 자동 발견은 지원하지 않습니다. 두 브랜치의 LLM 전용 CLI 옵션과 TUI 세부 기능 차이는 유지됩니다. 명령 계약은 [명령 통일 명세](docs/command-consistency-spec.md)에 있습니다.

## 파서와 탐지 범위

- RFC3339 타임스탬프와 `service=... action=... ip=... status=...` 필드
- OpenSSH의 Failed/Accepted 인증 syslog: 연도·시간대가 없으면 실행 시각을 기준으로 추정
- Apache/Nginx combined access 로그
- Fly JSON에 포함된 지원 HTTP 요청 메시지: 기타 플랫폼 메시지는 비이벤트로 집계

모든 지원 형식에서 IP를 검증·표준화하고 HTTP 상태값은 100~599로 검사합니다. 인증 결과를 알 수 없으면 `UNKNOWN`으로 남깁니다. 배치 파싱 오류에는 원본 파일과 행번호가 포함됩니다. 입력에 없는 IP나 인증 결과는 추측하지 않습니다. 제공된 skueat 수집본의 HTTP 기록은 클라이언트 IP가 없어 IP별 규칙 탐지에 사용할 수 없습니다.

기본 규칙은 동일 IP의 auth/login 실패 5회/20초, SSH 인증 실패 6회/30초, 민감 경로의 HTTP 401·403·404 응답 4회/30초입니다. 계정 탈취나 모든 404 요청을 자동 판별하는 제품은 아닙니다.

배치 CLI는 전체 입력을 메모리에 읽어 정렬하므로 메모리가 입력 크기에 비례합니다. 실시간 탐지기는 IP 수와 IP별 이력 수를 제한합니다. 입력 시각 전후 한 시간창 안에서만 역순 이벤트를 결합하므로, 서로 멀리 떨어진 과거 구간을 임의로 섞어 실시간 입력하지 마세요. 세부 조건은 [수정 명세](docs/review-fixes-spec.md)에 있습니다.

## 일시정지와 저장

실제 TUI(`cmd/logshield-tui`)에서 `p`는 화면 경고 반영을 정지/재개합니다. 탐지와 저널 저장은 계속됩니다. 임시 경고는 최대 100건이며, 중요도가 높고 같은 중요도에서는 더 최근인 항목을 남깁니다. 재개하면 보관한 경고를 시간순으로 반영합니다.

`s`는 화면의 최근 경고와 일시정지 중 보관한 경고를 합쳐 시간순 JSON 배열로 `report.json`에 덮어씁니다. 화면과 임시 버퍼 각각 최대 100건이므로 전체 탐지 이력이 아닙니다. `c`는 화면 상태만 초기화하며 저널을 지우지 않습니다.

저널의 한 줄은 다음 구조입니다. `recorded_at`은 기록 시각, `alert.ts`는 탐지를 완성한 이벤트의 시각입니다.

```json
{"recorded_at":"2026-11-03T00:00:01Z","alert":{"ts":"2026-11-03T00:00:00Z","rule_id":"BRUTE_FORCE_LOGIN","title":"로그인 브루트포스 의심","severity":"높음","message":"...","ip":"203.0.113.1","service":"auth"}}
```

배치 `cmd/logshield`는 `report.json`이나 저널을 자동 생성하지 않습니다. 저널은 자동 회전하지 않으므로 보관·용량 관리가 필요합니다. [신뢰성 명세](docs/reliability-spec.md), [Fly 로그 검증](docs/fly-log-validation.md)을 참고하세요.
