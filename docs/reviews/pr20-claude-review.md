Work-state review received. Waiting for check.sh and the migration/REPLACE review.

`check.sh` exited 101 on one `fw_control` revocation test (expected 200, got 403), which PR #20 doesn't touch and which ran while the machine was under heavy load. I'm rerunning that test alone to see whether it's a timing flake or a reliable failure.

The failure doesn't reproduce when run alone (5 of 5 passes), and the revocation path needs a fresh-auth window. I'm treating it as an intermittent, load-related timing issue and rerunning the full `check.sh` to cover the steps after the abort.

Rerunning check.sh; waiting for it and for the migration/REPLACE review.

`check.sh` 재실행이 종료 코드 0으로 끝났고, 테스트는 Rust 800개, CLI 1개, 축소 기능 32개, UI 180개가 모두 통과했습니다. 다음으로 실행 파일 빌드, umask 테스트, smoke, F2·F3 재확인을 하겠습니다.

Three parallel reviews have come back. Before writing the final report, I'll independently reproduce the main new findings: the transition-history erasure from the rowid REPLACE, the live guard (F2), and the sqliteX (F3) case.

Two findings are now confirmed: B-1, where an `INSERT OR REPLACE` onto the retained revision-0 rowid silently erases that transition history row while all guards still pass, and F2, which is fixed so that dropping the evidence guard on a live connection is refused. I'm checking F3 with the normal binary next.

# PR #20 독립 보안·회귀 검토 — 원본 접근 요청 보존과 서명 quota 무결성

## 결론
- **Critical·High·Medium 결함은 없습니다.** Low 결함 7건을 확정했습니다(아래 표, 모두 인증 DB에 쓸 수 있는 공격자 전제).
- 이전 F1~F4는 모두 수정 효과를 확인했습니다. F3에는 `writable_schema` 경로의 잔여가 있습니다(N6).
- **다음 개발을 막는 결함은 없습니다.** 다만 N1(quota 전이 표에 REPLACE guard 누락)은 이번 PR이 다른 표에 적용한 방식과 어긋나므로 다음 작업에서 바로 고치기를 권합니다.
- 원본 접근 요청 보존은 권한이 아니라 비용 출처로만 쓰입니다. 정상 빌드에서는 서명·dispatch가 계속 닫혀 있습니다. 이번 통과 결과는 테스트용 fixture, 가상 인증기, 소프트웨어 키로 얻은 것이며 운영 발급이나 제품 완성을 뜻하지 않습니다.

## 검토 대상과 환경
- **기준:** `09ef6a866632a9a6e12e2af799cb18b8b55daca9`
- **대상:** `9e021b31171ae19ff8c9e7eba400d8dd4630a001`
  - 커밋 3개
  - 병합 커밋 `6eb68a9`와 트리 `2e2acef…`가 같은지 직접 확인했습니다.
- **변경 범위:** 43개 파일, 6,224줄 추가, 336줄 삭제
  - `schema.sql`, migration 002~008, `docs/specs`는 바뀌지 않았습니다.
  - migration 009와 010은 이번 PR에서 새로 추가됐습니다.
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude20.ja27I6`
  - 내부 병렬 검토 worktree 3개: provenance, 이관·REPLACE, work 상태기계
  - 모두 detached 상태이며, 임시 테스트를 원복해 `git status`가 비어 있음을 확인했습니다.
- **도구:** rustc·cargo 1.99.1, Python 3.13.17, Node 22.22.0, Python Playwright 1.62.0
- `pr19-claude-review.md`, CI 결과, 내부 검토는 결론의 근거로 쓰지 않았습니다.

## 실행 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` 1차 | **101** | `fw_control` 테스트 1건 실패(아래 설명) |
| `bash scripts/check.sh` 재실행 | 0 | workspace 800 통과 / 0 실패 / 1 ignored, 명시적 process test 1, 축소 기능 32, UI 180, 로케일 8개·키 229개 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 406 통과 / 1 ignored |
| `cargo build … --bins --examples` | 0 | — |
| `smoke_enrollment.py --authority-metadata` | 0 | 41(그중 metadata 18) |
| `smoke_authority_review.py` 1차 | 1 | 브라우저 실행 실패(환경) |
| `smoke_authority_review.py --browser-executable /opt/pw-browsers/chromium` | 0 | 40 |
| 내 반례 `zz20_a` | 0 | 1 통과 |
| `fw_authority_admin`으로 F3 확인 | — | 아래 F3 항목 |

내부 검토자가 실행한 결과(같은 대상 SHA, 각자 다른 worktree):
- **provenance:**
  - 원본 접근 요청 관련 통합 테스트 3종(admin·provenance·store): 10 + 15 + 15 통과
  - `--lib core_access`: 5 통과
  - 반례 6개 통과
- **work 상태기계:**
  - `store::signing_`: 64 통과 / 1 ignored
  - 반례 10개 통과(1차 3건은 프로브 오류로 수정 후 재실행)
- **이관·REPLACE:**
  - `store::migrations`: 17 통과
  - 행렬 프로브 288개 + 표적 프로브 22개 + 원본 접근 요청 표 프로브 51개
  - 정상 legacy 상태 39개 모두 이관 성공, 모순 데이터 38개 모두 거절

**환경 실패·프로브 오류:**
- **`check.sh` 1차 실패:** 원인은 `fw_control`의 `delegated_cli_access_ends_on_logout_expiry_or_credential_revocation`입니다. 철회 경로에서 200 대신 403을 받았습니다.
  - PR #20은 `fw_control`을 바꾸지 않았습니다.
  - 따로 5회 돌리면 5/5 통과했습니다.
  - 철회에는 "최근 인증" 시간 창이 필요한데, 당시 병렬 빌드 3개로 기계 부하가 컸습니다. 부하로 인한 타이밍 flake로 분류했고, 전체 재실행에서 통과했습니다.
- **`smoke_authority_review` 1차 실패:** Python Playwright 1.62가 headless shell 빌드 1234를 찾는데, 설치된 브라우저는 1243이었습니다. 스크립트의 정식 옵션으로 재실행해 통과했습니다.

**미실행:**
- `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py --skip-image-build`
  - Docker 데몬이 없습니다(`/var/run/docker.sock` 없음).
  - dockerd를 띄우면 호스트의 iptables와 bridge가 바뀌므로 띄우지 않았습니다.
  - 따라서 이 세 검사는 PASS가 아닙니다.
- base 바이너리가 직접 만든 legacy 데이터로 하는 이관 검사(이관 fixture는 head 코드로 만든 뒤 스키마를 되돌린 것)
- 다중 프로세스 경합, 크래시 주입

## 확정 결함

| ID | 심각도 | 위치 | 최소 재현 | 기대 / 실제 | 영향 |
|---|---|---|---|---|---|
| **N1** | Low | `migration_008.sql:22-23`. `authority_signing_quota_transitions`에는 no_update·no_delete만 있고, 010이 다른 표에 추가한 `no_replace` 트리거가 없음 | 아래 설명 | 기대: 식별자 충돌로 거부. 실제: 성공, 전이 이력이 `[1:0:reserved]`에서 `[1:1:released]`로 바뀜. 읽기·재개방도 통과 | 보존해야 할 quota 전이 이력이 조용히 지워지고, 읽기 경로는 revision 연속성을 확인하지 않음. 과다 승인은 정상 취소와 같은 수준까지만 가능 |
| **N2** | Low, 기존 스키마 | `authority_audit`에 rowid REPLACE를 막는 guard가 없고, `authority_audit_heads`에는 트리거가 아예 없음 | 마지막 audit 행을 rowid REPLACE로 덮은 뒤 head를 되돌림 | 기대: 거부. 실제: audit 41행이 40행이 되고 `verify_audit_chain`은 ok | 최신 감사 사건을 지워도 검출되지 않음. 이관 검토 에이전트만 재현했고 저는 재실행하지 않음 |
| **N3** | Low | 감사 기록을 강제하는 트리거가 없음 | 일반 SQL로 cancelled event·head·`released` 전이를 위조 | 기대: 감사 없는 상태 변경 거부. 실제: 성공, audit 증가 0(`zz20_a`, work 에이전트) | 미발급 작업의 무감사 취소. 같은 방식으로 `delivered`도 위조되지만 슬롯은 유지됨. 유효 claim을 가로채 dispatch를 멈추고 UNKNOWN 이력을 UI에서 가릴 수 있음 |
| **N4** | Low, fail-closed | `migration_010.sql:22`는 worker_id 길이만 확인하고 Rust는 UUID를 확인 | worker_id에 36자 비UUID를 넣거나, head 갱신 없이 event만 INSERT | 기대: 삽입 거부. 실제: 삽입 성공, 이후 해당 root/project 전체의 예약이 `Invalid`로 막힘 | DB 작성자에 의한 서비스 거부 |
| **N5** | Low | 이관 검증기에 v10 시각 규칙 3개가 빠짐: dispatch `created`=`outbox.created_at`, delivered=`recorded_at`, claim 창(`migration_010.sql:35,68,102`) | v8·v9 fixture에서 위 시각 하나를 어긋나게 만든 뒤 이관 | 기대: 이관 거부. 실제: 이관 성공 | 새 트리거라면 거부했을 시각의 기록이 들어옴. quota는 유지됨. 이관 에이전트만 재현 |
| **N6** | Low | schema digest와 실행 중 guard 검사는 `sqlite_` 접두 이름을 제외함 | `PRAGMA writable_schema=ON`으로 `sqlite_zz_hidden` 트리거를 주입 | 기대: 거부. 실제: 정상 바이너리의 같은 버전 migrate가 통과(제 재현). 에이전트는 이 트리거로 head 갱신이 무시되는 실제 효과도 확인 | 문서의 "예상하지 않은 객체를 추가하면 거부된다"는 이 경로에는 성립하지 않음. 파일 수준 변조가 필요 |
| **N7** | Low | `foreign_keys=OFF`에서 jobs·intents·reservations는 delete 트리거에만 의존 | rowid REPLACE로 delivered·held 상태의 job 행을 삭제 | 기대: 거부 또는 검출. 실제: 삭제 후에도 open·read·account가 통과 | 작업이 목록에서 사라짐. 이관 에이전트만 재현 |

**N1 재현 절차(제가 직접 실행, 모든 guard 유지, 기본 PRAGMA):**
1. 미발급 job을 signer로 claim합니다.
2. 일반 SQL로 cancelled work event를 넣고 head를 갱신합니다.
3. `INSERT OR REPLACE INTO …_transitions(rowid,…)`로 revision 0 행의 rowid에 `released` 전이를 씁니다.
4. 예약을 UPDATE합니다.

**수정 방향:**
- N1·N2·N7: 009·010과 같은 방식으로 rowid, PK, 모든 대체 unique key에 `BEFORE INSERT` 충돌 guard를 추가합니다. 대상은 transitions, reservations, usage, intents, jobs, results, outbox, audit입니다. audit head는 일치하는 audit 행으로만 전진하게 합니다.
- N3: 상태 전이 트리거에 그에 맞는 audit 행을 결합합니다.
- N4: 트리거에서도 UUID 형식을 확인합니다.
- N5: 이관 검증기에 v10 시각 규칙을 추가합니다.
- N6: 알려진 내부 객체만 허용하는 목록으로 바꿉니다(`sqlite_autoindex_*`, `sqlite_sequence`, `sqlite_stat*`).

## 이전 F1~F4 판정

| 항목 | 판정 | 근거 |
|---|---|---|
| F1 인증 없는 전달 기록으로 발급 용량 반환 | **해결** | `active`도 회계 held 인덱스에 포함됨(`migration_010.sql:6-9`). 발급 이후 실효 dispatch 슬롯은 1로 계산됨(`signing_quota.rs:181`, `:924`). 전체 위조 시퀀스 뒤에도 두 번째 예약은 `Quota`로 거절. +2초, 재개방, claim 만료, intent 만료, +24h, +72h에서 유지. 임대형 예약은 일일 비용만 정상적으로 창에서 빠지고 활성 임대·동시 배포 슬롯은 유지 |
| F2 열린 연결의 guard 검사 누락 | **해결** | 이제 `authority_signing_` 접두의 v10 트리거 전체를 실행 중에 확인함. evidence 트리거만 지우면 예약이 `quota accounting guard missing or changed`로 거절되고(`zz20_a`), 재개방은 `unexpected authority v10 schema`로 거절 |
| F3 `sqlite_` 유사 이름 누락 | **해결, 잔여 N6** | 정상 바이너리에서 `sqliteX_hidden`과 `SQLITE9x`는 `MIGRATION_REJECTED`. `Sqlite_zz`는 SQLite가 생성 자체를 거부 |
| F4 UNKNOWN 이력 소실 | **해결** | 재claim 뒤 issued·released로 되돌리는 갱신은 모두 거절. 같은 조작을 한 legacy 데이터의 이관은 `signing quota uncertainty history`로 실패. 재개방과 만료 뒤에도 유지 |

## 항목별 확인

### 1. 원본 접근 요청 보존 — 정상
- request, envelope, delegation의 해시는 입력값을 믿지 않고 직접 다시 계산합니다. 세 객체는 서로 교차 결합되고 plan과 정확히 일치해야 합니다(`access_provenance.rs:415-550`).
- 반례 17종(목적지 확장, 기간 이탈, 다른 대상·프로젝트, 다른 원칙 주체, revision 2, 임대 기간 초과, 해시 불일치 등)은 모두 `Binding`·`Time`·`Invalid`로 거절됐습니다.
- 재결합과 재시도:
  - 같은 요청의 바이트·루트·임대를 바꾸면 `Conflict`입니다.
  - 같은 조직에서 임대 ID를 재사용하면 `Conflict`입니다.
  - 정확한 재시도는 audit을 늘리지 않습니다.
  - 다른 tenant는 존재 여부를 구분할 수 없는 동일 오류를 받습니다.
- 비용은 plan의 창이 아니라 원본 요청의 전체 기간(3600초)으로 계산됩니다. 목적지는 정렬·중복 제거되고, 호출자가 비용을 지정할 경로는 없습니다.
- 만료 뒤에도 과거 기록은 읽을 수 있으며 갱신되지 않습니다.
- SQLite 보호: UPDATE·DELETE·REPLACE·rowid 충돌 시도는 FK 설정과 무관하게 모두 거절됐습니다.
- 권한 아님: `signing_allowed`·`dispatch_allowed`는 false로 고정이고, `CORE_SIGNING_PROFILE_UNAVAILABLE` 차단 사유가 항상 붙습니다.
- 문서에 이미 적힌 한계(코어 서명 출시 전 필요): service와 port 결합, CIDR과 asset 결합, 같은 요청을 공유하는 plan의 단일 절대 임대 창. 해당 공백은 재현됐지만 비용에는 영향이 없습니다.

### 3. SQLite 보호와 상태 전이 — N1·N2·N4·N7 외 정상
- 010이 guard를 추가한 work events·heads·deliveries·accounting heads는 모든 REPLACE·rowid 프로브에서 성공 0건이었습니다.
- SQL backoff 식과 Rust `retry_delay`를 1,536개 조합으로 대조해 불일치 0건이었습니다.
- 정상 프로토콜 동작 가운데 트리거가 거절한 것은 없습니다(갱신 32회, 재시도, UNKNOWN, 재claim, deadline 경계 포함).
- event 상한 192는 정상 최대치(signer 103, dispatch 171)보다 큽니다.
- NULL 투영은 조건식 전체를 `IS NOT 1`로 감싸 거절됩니다.

### 4. 구버전에서 schema 10으로 이관 — N5 외 정상
- 원본 버전 v1~v9 모두 실제 schema digest를 먼저 비교합니다. 변조 23종은 모두 거절됐습니다.
- 백업은 0600 권한과 manifest가 있고, 위험한 경로 12종을 모두 거부합니다. 같은 버전 재실행은 아무것도 만들지 않습니다.
- 정상 상태 39종은 원래 바이트를 보존한 채 이관됐고, 모순 데이터 38종은 모두 롤백됐습니다(원본 버전 유지, 백업 유효).
- 만료를 해제 근거로 쓰거나 완료 증명을 만들어 내는 동작은 없었습니다.

### 5. CLI와 UI — 정상
- CLI 입력 검사:
  - 미지·중복 필드와 128 KiB 초과 입력은 고정 진단으로 거절됩니다.
  - `/dev/full`로 출력이 실패해도 commit은 보존되고, 이후 읽기로 복구할 수 있으며, 재시도해도 audit이 늘지 않습니다.
  - 오류에 입력값·경로·식별자를 에코하지 않고, 출력에 원문 purpose·scope를 넣지 않습니다.
  - 다른 tenant의 미초기화 project도 provenance 전용 코드로 응답합니다. 문서는 tenant 오류에 별도 코드를 쓴다고 하므로 사소한 문서 불일치입니다.
- UI parser는 다음 모순 조합을 거부합니다(`signing-readiness.ts`).
  - delivered인데 `active`가 아닌 예약
  - `released`인데 held
  - ready가 아닌데 dispatch나 grant가 있는 경우
- 8개 언어 모두 delivered를 "기록됨·할당량 유지"로 표시해, 용량이 반환됐다는 뜻을 담지 않습니다.
- 관찰: 위조된 delivery가 UNKNOWN을 덮으면 UI에 과거 UNKNOWN 표시가 남지 않습니다(N3과 연관).

## 미재현 의심과 설계상 남은 작업
- `active`를 계속 held로 두는 정책 때문에, 인증된 전달 수신증이 생기기 전까지 발급 용량이 계속 쌓입니다. 동시 배포 한도만큼 전달되면 더는 서명할 수 없습니다. 문서에 적힌 보수적 설계로 봅니다.
- 계정당 회계 비용(최대 10,000행 × 약 195 이력 행)은 상한이 있지만 무겁습니다.

## 구분
- **다음 개발을 막는 결함:** 없음
  - N1과 N2는 다음 회계·감사 작업의 기반이므로 우선 수정을 권합니다.
- **운영 출시 전에 해결할 사항:**
  - N1~N7
  - provenance의 service·CIDR·단일 임대 창 결합
  - 인증된 delivery receipt와 그에 따른 용량 반환
  - 감사 체인의 외부 앵커
  - Docker 격리 lab 검사(이번에 미실행)
  - 이미 명시된 미완료: 운영 bootstrap, 보호 OS 계정, build identity, native qualification, 독립 signer, PostgreSQL, Windows·macOS 자격

반례 소스와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr20/`에 있습니다. 비밀값과 개인키는 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다.

```bash
for w in /tmp/nox-claude20.ja27I6 /tmp/nox-claude20p.4JXMsY /tmp/nox-claude20m.N4grHN /tmp/nox-claude20w.zuT96z; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```