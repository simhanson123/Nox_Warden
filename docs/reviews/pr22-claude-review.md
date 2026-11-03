I'll independently reproduce the hardening reviewer's D1 (hidden held obligation) once the smoke run frees the worktree.

모든 smoke 테스트가 통과했고, umask 테스트는 456개 통과에 2개 ignored입니다. 이제 hardening 검토자가 보고한 D1을 같은 worktree에서 독립적으로 재현하겠습니다.

# PR #22 독립 통합 검토 — 서명 이력 무결성과 프로젝트 할당량

## 결론
- **Critical·High 결함은 없습니다.** 이번 범위에서 결함 6건을 확정했습니다(D1 Low~Medium, D2~D6 Low). 가장 중요한 것은 **D1**이며, 제가 직접 재현했습니다.
  - guard를 지웠다가 원래 SQL로 정확히 복구하는 방식으로 회계 head 하나를 `released`로 바꾸면, `open`이 통과하고 추가 예약이 승인됩니다.
  - 문서는 "다음 전체 open/maintenance 검증"이 이런 손상을 잡는다고 적고 있습니다. 실제로는 maintenance만 잡습니다.
- 이전 N1~N7은 각자의 원래 재현 기준에서 모두 수정됐습니다. 원본 PR20 보고서의 private probe를 재실행하지는 않았고, 이번에 새로 만든 독립 반례로 확인했습니다.
- **다음 개발을 막는 결함:** D1. open 시점 검증이나 admission 교차 확인을 보강한 다음 다른 작업을 쌓기를 권합니다.
- 정상 빌드에서 서명과 dispatch는 계속 닫혀 있습니다. 이번 통과 결과는 테스트용 fixture, 가상 인증기, 개발용 서명 키로 얻은 것입니다. 운영 인증, 완료 증명, OS 인증을 뜻하지 않습니다.

## 검토 대상과 환경
- **기준:** `2219c9ffe64fc0f4a967f3af69e84cdcc15aaff3`
- **대상:** `2cccdb3ba1f22fd461c53bc350bb2d1bc07fffd0`
  - 단일 커밋
  - 병합 커밋 `d54021a`와 트리 `a33fa20…`이 같은지 직접 확인했습니다.
- **변경 범위:** 64개 파일, 6,676줄 추가, 921줄 삭제
  - `schema.sql`, migration 001~010, `docs/specs`는 바뀌지 않았습니다(diff 0바이트).
  - PR20 보고서의 SHA256 `abc796dc…`가 일치합니다.
- **환경:** 컨테이너가 새로 시작돼 다시 확인했습니다. rustc 1.99.1, Node 22.22.0(`package.json`은 24.19.0을 고정하므로 EBADENGINE 경고가 남), Python 3.13.17, Playwright 1.62.0이며 Docker 데몬은 없습니다.
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude22.Tbkygu`
  - 내부 병렬 검토 worktree 4개: hardening, 이관 대상, 이관용 구버전, 할당량·API
  - 모두 detached 상태이며, 임시 테스트를 원복해 `git status`가 비어 있음을 확인했습니다.

## 실행 명령과 결과 (이번에 직접 실행)

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 851 통과 / 0 실패 / 2 ignored ※ |
| — 명시적 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 190 통과(파일 10개) |
| — 로케일 | | 8개 언어, 키 229개 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 456 통과 / 2 ignored ※ |
| `cargo build … --bins --examples` | 0 | — |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` / `enrollment --browser` | 0 / 0 | 11 / 25 |
| `smoke_enrollment --authority-metadata` | 0 | 41 |
| `smoke_authority_review` | 0 | 40 |
| 내 D1 반례 `zz22_` | 0 | 1 통과(결함 재현 출력) |

- ※ 두 줄 모두 테스트가 하위 프로세스로 띄운 중첩 실행 요약 2건(각 1 통과)은 합산에서 뺐습니다.
- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드가 달라, 각 스크립트의 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 사용했습니다.

내부 검토자가 실행한 결과(같은 SHA, 각자 다른 worktree):
- **hardening:**
  - `--lib`: 169 통과 / 2 ignored
  - `--test authority_audit`: 13 통과
  - 반례 11개
  - 정적 식별자 점검: 65개 표에서 누락 0건
  - audit head 증가 계산 19,705건 대조: 불일치 0
- **이관:**
  - `store::migrations`: 23 통과 / 1 ignored
  - `rebuild_tests`: 6 통과 / 1 ignored
  - 실패 주입 8단계, 동시 실행 6회, SIGKILL 30회
- **할당량·API:**
  - `--lib signing_quota`: 62 통과(기존 53 + 반례 9)
  - 할당량 버전별 통합 테스트(`signing_readiness_versions`·`signing_admin`): 10 + 1 통과
  - `fw_authority_service`: 6 + 9 + 35 + 5 통과
  - vitest 99 통과, 로케일 PASS

**미실행:**
- `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py`는 Docker 데몬이 없어(`/var/run/docker.sock` 없음) 실행하지 못했습니다.
  - dockerd를 띄우면 호스트의 iptables와 bridge가 바뀌므로 띄우지 않았습니다.
  - 따라서 README의 Linux 66/40, signed 98/43, native 33/5 기준치는 **확인하지 못했고**, PASS로 적지 않습니다.
- 사람에 의한 번역 검수, 1만 행 경계에서 v1·v2가 섞인 회계 검사(코드 검토만), 다중 호스트 경합

## 확정 결함

### D1 [Low~Medium] guard를 정확히 복구하면 숨겨진 held 점유가 open을 통과하고 추가 예약이 승인됨 — 직접 재현
- **위치:**
  - `account`는 held 인덱스의 head만 나열합니다(`signing_quota.rs:1017-1035`).
  - `open`은 `validate_v12` → `validate_reference_graph`를 거치는데(`mod.rs:175`, `migrations.rs:428-467`, `:660-664`), head와 해당 revision의 transition·reservation을 비교하지 않습니다.
- **재현 절차:** 동시 배포 한도 1인 reserved 또는 issued 예약에서 시작합니다. 이때 다음 예약은 `Quota`로 거절됩니다.
  1. `DROP TRIGGER authority_signing_quota_transition_heads_update`
  2. `UPDATE …_transition_heads SET state='released'`
  3. 원래 트리거를 원래 SQL 그대로 다시 만듭니다.
- **기대:** open이나 admission이 거부.
- **실제(reserved, issued 모두):**
  - `AuthorityStore::open`이 `Ok`
  - 새 예약이 **ADMITTED**
  - 숨긴 예약을 직접 읽으면 `signing quota transition projection` 오류
  - 같은 버전 maintenance만 오류
- **영향:**
  - DB 작성자가 issued 용량을 회계에서 숨겨 한도를 넘길 수 있습니다.
  - 문서의 "full open/maintenance validation"(`docs/authority-store.md:650-653`) 중 open에 대한 주장은 성립하지 않습니다.
- **수정 방향:**
  - open에서 head = transition(revision) = reservation 상태를 일괄 확인합니다.
  - admission에서 reservation 쪽 held 집합과 head 쪽 held 집합을 상호 대조합니다.

### D2 [Low] `writable_schema`로 부분 인덱스를 비우면 정확한 inventory 검사와 maintenance를 모두 통과하고 과다 승인됨 — 에이전트 재현
- **재현:**
  1. `writable_schema`로 held 인덱스 SQL에 `WHERE 0 AND`를 넣습니다.
  2. `REINDEX` 합니다.
  3. 인덱스 SQL을 원래대로 되돌립니다.
- **실제:** `integrity_check`는 누락을 보고하지만, open·live 검사·같은 버전 maintenance는 `Ok`이고 예약이 승인됩니다.
- **원인:** `integrity_check`가 `apply_v12`(`migrations.rs:646`)에서만 돌고, open과 같은 버전 경로에서는 돌지 않습니다.

### D3 [Low, fail-closed] `authority_audit`에 INSERT 순서 guard가 없음 — 에이전트 재현
- `migration_011.sql:36-38`은 식별자 충돌만 확인합니다. 그래서 head+2 위치의 audit 행이 들어갑니다.
- 그 상태에서도 open은 통과하지만, 체인 검증과 이후 모든 감사 추가는 실패합니다(해당 tenant의 서비스 거부).

### D4 [Low] FK OFF에서 event 없이 binding만 커밋할 수 있음 — 에이전트 재현
- `migration_011_work_bindings.sql:13`은 지연 FK에만 의존합니다.
- 이 상태에서 open은 `foreign key graph`로 거절되고, 정상 claim은 `binding count`로 실패합니다.
- 이 binding은 나중에 event가 소비할 수 있습니다. event 삽입 시 audit가 그 시점의 head였는지는 다시 확인하지 않습니다.

### D5 [Low] intent 없는 reservation은 open을 통과하고 maintenance에서만 잡힘 — 에이전트 재현
- admission은 fail-closed로 막힙니다. D1과 같은 "open 검증 범위" 문제입니다.

### D6 [Low, 가용성] 같은 초에 일어난 정상 v10 갱신 두 번을 schema 12로 이관할 수 없음 — 에이전트 재현
- 기존 `renew_in_tx`가 정상적으로 만들 수 있는 이력입니다. 그런데 `backfill_work_audits`(`signing_jobs.rs:381-389`)는 audit를 resource·kind·time만으로 대응시키므로 후보가 2개가 되어 거절합니다.
- 원본과 백업은 보존됩니다. 이는 의도된 fail-closed 정책(`signing_work_audit_tests.rs:436`)이지만, `pr20-follow-up.md:100`의 "갱신을 포함한 정상 v10 상태는 이관 가능"과 충돌합니다. 같은 job·phase 안에서 event 순서와 audit 순서를 맞추면 안전하게 해소할 수 있습니다.

## 이전 N1~N7 판정 (이번 독립 반례 기준)

| 항목 | 판정 | 근거 |
|---|---|---|
| N1 quota 전이 교체 | 수정 | rowid·PK·`UPDATE OR REPLACE`·`SET rowid`·삭제·과거 witness 재사용 10종 × FK on/off × recursive on/off = 40회 모두 거부, 행 불변 |
| N2 audit 꼬리 제거 | 수정 | 꼬리 재작성, head 삭제·되감기, 교체 14종 × 4조합 모두 거부. unsigned64 경계(2⁶³, 2⁶⁴−1)도 정확 |
| N3 감사 없는 작업 변경 | 수정 | binding 없는 event 거부, audit 하나를 두 event에 재사용하면 거부, event와 head 투영이 원자적. issued 작업은 audit까지 함께 위조해도 거부 |
| N4 UUID SQL/Rust 동등성 | 수정 | 유사 문자열 19종에서 SQL과 Rust 판정 불일치 0 |
| N5 시각 결합 | 수정 | dispatch created·delivered·직전 claim 창이 실행 경로와 이관 검증 양쪽에서 같은 규칙으로 확인됨 |
| N6 `sqlite_` 위장 객체 | 수정, 잔여 D2 | 정상 바이너리의 open·같은 버전 migrate가 trigger·view·table·가짜 autoindex·잘못된 `sqlite_stat`·`sqlite_sequence` 위장을 모두 거부. ANALYZE·STAT4는 허용 |
| N7 FK OFF 교체 | 수정, 잔여 D4·D5 | 표 65개 정적 점검 누락 0, 고아 행은 open이나 maintenance에서 거부 |

- 임시 예외 `initializing_job`은 prepare 트랜잭션 안의 Rust 인자일 뿐입니다. 저장되지 않으므로 일반 조회나 발급으로 퍼지지 않습니다.
- 참고 관찰: 미발급 작업에 대해 문법적으로 유효한 audit까지 함께 위조하면 취소가 성공합니다. 문서가 밝히듯 로컬 감사는 인증 수단이 아니므로 결함으로 세지 않았습니다.

## schema 11·12 이관 — 정상 (D6 제외)
- **실제 구버전 바이너리로 만든 DB(재구성 fixture 아님):** base `2219c9f` 바이너리로 schema 10 DB를 만들었습니다(project, target pin, quota pin 등 43행, audit 13건).
  - 새 바이너리로 migrate하자 43행의 rowid·`typeof`·BLOB hex가 모두 같았습니다.
  - migration 기록은 기존 10행을 그대로 앞에 두고 늘었습니다.
  - 백업은 0600 권한이고 manifest 해시가 일치합니다.
  - 다시 migrate하면 아무것도 바뀌지 않습니다.
  - 한계: 구버전 CLI로는 서명 작업을 만들 수 없어서, 서명 이력은 재구성 fixture로만 검증했습니다(5개 상태, 바이트와 held 상태 보존).
- **실패 경로:**
  - 실패 주입 8단계, 감사 기록의 늦은 손상, 모호한 audit 대응: 모두 원본 v10 유지, 신규 객체 없음, 백업 유효, FK 복구(1).
  - 동시 이관 6회: 백업 1개, 결과 동일.
  - SIGKILL 30회: 모두 재이관 성공. 백업 생성 중 종료된 1회는 빈 manifest를 가진 고아 백업을 남겼습니다(원본은 무사). 문서에 이 경우의 처리가 없습니다.
- 감사·작업·완료 증거를 만들거나 발급 슬롯을 환급하는 동작은 없었습니다.

## 프로젝트 할당량 — 정상
- **v2 codec:** 잘못된 pin 8종과 snapshot 변조 7종을 모두 거부합니다. v1 바이트는 그대로 왕복합니다. 임대형 비용은 root 없이 만들 수 없습니다(3중 차단).
- **root 결합:**
  - A → None → A는 CAS로 가능합니다.
  - B는 A가 철회·만료됐거나 재개방한 뒤에도 거부됩니다.
  - 처음부터 rootless로 만든 project는 root를 얻을 수 없습니다.
  - 두 연결이 동시에 CAS를 보내는 10회 경합에서 매번 1건만 성공했습니다.
  - 다른 조직의 같은 root ID는 별도 예산입니다.
- **회계:**
  - project 범위는 v1과 v2 행을 함께 셉니다(`LIMIT 10001`, 목적지 200,000건 상한 공유).
  - root 범위는 정확히 그 root만 셉니다.
  - issued·UNKNOWN·미인증 delivered는 만료·재개방·24시간 경과 뒤에도 유지되고, rolling 비용은 환급되지 않습니다.
- **설정 변경 뒤 과거 작업:**
  - 기존 rooted 작업은 원래 root와 root 시계를 유지합니다.
  - 기존 rootless 작업은 root A를 복원한 뒤에도 project 범위만 씁니다. 실제 UNKNOWN·delivery·cancel 수명주기로 확인했습니다.
- 코어 접근(`add_access_lease`)은 여전히 root와 provenance를 요구합니다.

## API·CLI·UI — 정상 (관찰 3건)
- **CLI:**
  - v2는 명시 버전이 필요합니다. null·부분·미지 버전, 중복 키, 대문자 버전 문자열은 `INPUT_REJECTED`입니다.
  - rootless anchor 상태에서 v1으로 내리는 시도는 거부됩니다.
  - `/dev/full`로 출력이 실패해도 commit은 보존됩니다. 정확한 재시도는 `Conflict`를 받고, 현재 revision으로 재시도하면 그 revision을 반환하며, 둘 다 audit을 늘리지 않습니다. 이는 문서 66행과 같습니다.
  - 시각은 명령마다 한 번 샘플링합니다.
- **HTTP v2 readiness:**
  - 세션 없음 401, CSRF·외부 Origin·cross-site 403
  - 다른 tenant 409, 비정규 UUID는 균일한 409·400
  - v1 경로는 rootless 설정을 거부합니다.
- **UI:**
  - parser 24개 사례에서 모순 조합을 모두 거부합니다.
  - 과거 UNKNOWN은 이후 전달 뒤에도 표시됩니다.
  - 브라우저 언어가 ko·ja여도 기본은 영어이고, 저장한 `zh-Hant`는 유지됩니다.
  - 8개 언어에 새 키 4개가 있고 의미가 일치합니다(사소한 표현 차이만 있음).
- **관찰(Low):**
  - (a) UI는 현재 scope만 보여 줍니다. 그래서 root A로 계속 집계되는 과거 작업이 있어도 "project quota"로만 보입니다. 문서상 계약(scope는 현재 설정)과는 일치합니다.
  - (b) 출력이 유실된 뒤 현재 project-pin revision을 읽는 CLI 명령이 없습니다.
  - (c) `trim_start_matches` 때문에 v2 경로 접두사를 두 번 반복해도 200을 반환합니다. 권한 영향은 없고 v1도 같습니다.

## 인증·실행 경계 — 정상
- `fw_control`의 변경은 `cli_auth.rs` 테스트 모듈(353행 이후)에만 있습니다. 운영 freshness 조건은 그대로이고, 1초 불일치 시 403을 확인하는 테스트가 추가됐습니다.
- 운영 경로의 `protected_authority`는 항상 거절합니다. `signing_allowed`·`dispatch_allowed`는 false로 고정이며, 새 feature나 환경변수 분기가 없습니다.
- authority smoke 스크립트는 v2 응답을 더 엄격하게 확인하도록 바뀌었습니다.
- Linux 실행기와 lab 스크립트는 바뀌지 않았습니다. AI 자기 승인 경로도 추가되지 않았습니다.

## 남은 범위
- **다음 개발 전:** D1, 그리고 함께 고칠 D5(open 검증 범위 확대).
- **운영 출시 전:**
  - D2~D6
  - 출력 유실 뒤 현재 revision을 조회하는 수단
  - Docker 격리 Linux·native 재검증
  - 이미 명시된 미완료: Linux 운영 연결·설치·복구, Windows WFP/callout, macOS Network Extension, 보호 signer·bootstrap, 인증된 완료 증명, 외부 감사 앵커
- 로컬 감사 결합은 외부 인증이나 앵커를 대신하지 못합니다.

반례 소스와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr22/`에 있습니다. 비밀값과 원시 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다.

```bash
for w in /tmp/nox-claude22.Tbkygu /tmp/nox-claude22h.5jj1va /tmp/nox-claude22m.ug4fn3 /tmp/nox-claude22o.bOckH3 /tmp/nox-claude22q.kHAieb; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```
