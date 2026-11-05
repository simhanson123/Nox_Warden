죄송합니다. 앞으로는 한국어로만 쓰겠습니다.

PR #25 검토를 진행 중입니다. 같은 프롬프트를 다시 보내 주셨는데, 이미 진행하던 그 검토를 그대로 이어서 하고 있습니다.

**지금까지 확인한 것**
- 대상 `89684e0`은 기준 `59c70ac`의 자손이고, 기준 트리는 PR24 head와 같습니다.
- SQL 001~013, specs, 기존 검토 원문은 바뀌지 않았습니다. PR24 보고서의 SHA256도 일치합니다.
- **I1(초기 job 선택):** 코드를 읽어 확인했습니다. prepare, read, readiness 모두 검증된 스냅샷 안에서 job을 고르고, 최종 트랜잭션에서 같은 결합인지 다시 확인해 다르면 `Conflict`를 냅니다.
- **T2·T3·native 정정:** 병렬 검토자가 결함 없음을 확인했습니다. 다만 문서 표현 과장이 몇 개 있습니다.
  - "13개 새 실패 조건"은 실제로는 새 실패 지점 약 11개입니다.
  - "선행 SQL을 기록한다"고 했지만 실제로는 SQL 원문이 아니라 테이블과 동작만 기록합니다.
- 받으신 프롬프트의 focused 필터 `signing_transition_atomicity_tests`는 **0개 테스트에 일치합니다**. 올바른 필터는 `transition_atomicity`입니다. 저장소 문서에는 이 잘못된 이름이 없습니다.
- Docker 데몬이 없어서 Linux lab 3종은 이번에도 미실행(NOT_RUN)으로 처리합니다.

**지금 진행 중인 것**
- `check.sh` 전체 검사가 workspace 테스트 단계에서 돌고 있습니다(약 12분 경과).
- 끝나면 같은 worktree에서 순서대로 실행합니다.
  - focused 테스트 7종(0개 일치 필터는 PASS로 세지 않음)
  - umask 테스트
  - workspace 빌드
  - smoke 11종

끝나는 대로 한국어 최종 보고서로 정리해 드리겠습니다.

`check.sh`가 끝나기를 기다리고 있습니다. 끝나면 바로 다음 단계로 넘어가겠습니다.

`check.sh`가 종료 코드 0으로 끝났고, 테스트 전체가 통과했습니다. 이제 focused 테스트, umask, workspace 빌드, smoke를 차례로 실행하겠습니다.

다음 작업을 백그라운드에서 순서대로 실행하고 있습니다.
- focused 필터 10개: 받으신 7개와 올바른 대체 필터 `transition_atomicity`, 그리고 `work_audit`, `projection_integrity`
- umask 테스트
- workspace 전체 빌드
- smoke 11종

끝나면 결과를 모아 한국어 최종 보고서를 드리겠습니다.

이 알림은 앞서 확인한 `check.sh`의 완료 알림입니다(종료 코드 0). 지금은 focused 테스트·umask·빌드·smoke 순차 실행이 끝나기를 기다리고 있습니다.

# PR #25 독립 통합 검토 — I1·T1~T3 후속 수정

## 결론
- **확정된 보안 결함은 없습니다.** I1과 T1~T3은 각각 의도한 대로 수정되거나 보강됐습니다.
- 남은 것은 문서·실행 명령의 사소한 부정확함뿐입니다(아래 "문서·명령 관련 지적").
- **다음 개발을 막는 사항은 없습니다.**
- 운영 서명과 dispatch는 계속 차단돼 있습니다. 이번 통과 결과는 테스트용 fixture, 가상 인증기, 개발용 서명 키로 얻은 것입니다. 운영 인증, 완료 증명, OS 자격을 뜻하지 않습니다.

## 검토 대상과 환경
- **기준:** `59c70ac32fd10e4d5ef6b63cc7f54f4eb5759fe8`(트리 `66f60c5`, PR24 head 트리와 동일)
- **대상:** `89684e055f01a1c87113e4ea4a713ebbff77afe1`(트리 `880986d`, 기준의 자손, 단일 커밋)
- **변경 범위:** 18개 파일, 1,922줄 추가, 266줄 삭제
  - 운영 코드 변경은 `signing_intents.rs`, `signing_quota.rs`(테스트 모듈 연결), `live_integrity.rs`(검증 없는 `query_row` 삭제)뿐입니다.
  - SQL 001~013, specs, 기존 검토 원문은 바뀌지 않았습니다. 새로 추가된 PR24 보고서의 SHA256 `ac296f87…`이 일치합니다.
- **환경:** rustc 1.99.1, Node 22.22.0(`package.json`이 24.19.0을 지정해 EBADENGINE 경고), Python Playwright 1.62.0이며 Docker 데몬은 없습니다.
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude25.zHWgh0`
  - T2·T3 병렬 검토자 worktree: `/tmp/nox-claude25t.rIZWJY`
  - 둘 다 detached 상태이고 원복을 확인했습니다. 시작 전에 아무 작업도 돌고 있지 않음을 확인한 뒤, 이전 PR24 때 제 target만 지웠습니다.

## 직접 실행한 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 905 통과 / 0 실패 / 3 ignored(중첩 migration 요약 2건 제외) |
| — 별도 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 190 통과(파일 10개) |
| — 로케일 | | 8개 언어, 키 229개 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 510 통과 / 3 ignored(중첩 2건 제외) |
| `cargo build --locked --workspace --bins --examples` | 0 | — |
| focused `signing_clock_integrity` | 0 | 2 |
| focused `signing_intents::tests` | 0 | 10 |
| focused `live_integrity` | 0 | 6 |
| focused `rootless_lifecycle` | 0 | 6 |
| focused `audit_atomicity_tests` | 0 | 4 |
| focused `signing_transition_atomicity_tests` | 0 | **0개 실행. PASS 아님** |
| focused `transition_atomicity`(올바른 필터) | 0 | 1 |
| focused `native_authority_atomicity_tests` | 0 | 7 |
| focused `work_audit` | 0 | 18 |
| focused `projection_integrity` | 0 | 7 |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_enrollment` API / 브라우저 / authority-metadata | 0 / 0 / 0 | 23 / 25 / 41 |
| `smoke_catalogue_navigation` | 0 | 11 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_authority_review` | 0 | 40 |

- focused 결과에는 테스트 바이너리 안에서 실행되는 중첩 worker 요약(1 통과)이 섞여 있어서, 위 표에서는 주 요약 수만 적었습니다.
- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드 번호가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 썼습니다.
- `--report`로 지정한 보고서 파일은 worktree의 ignore 경로에 생성됐고, 커밋 대상이 아닙니다.
- **NOT_RUN:** `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py --skip-image-build`
  - 관리 Docker 소켓이 없습니다(`/var/run/docker.sock` 없음, `DOCKER_HOST` 미설정).
  - 호스트에서 dockerd를 띄우거나 방화벽을 바꾸지 않았습니다.
  - 따라서 패킷 40/43건과 커널 캡처 5건은 이번에 **확인하지 못했습니다**. 구현자가 보고한 수치를 이번 실행 결과로 쓰지 않습니다.

## 항목별 판정

### 1. I1 검증된 스냅샷 안에서의 초기 선택 — 정상(소스 확인 + 테스트 실행)
- `prepare_signing_intent`(`signing_intents.rs:426-456`), `read_signing_intent`(`:464-`), readiness v1·v2(`:527-640`) 모두 같은 구조입니다.
  - 처음 intent·job을 고를 때 검증된 deferred 트랜잭션에서 고릅니다(`request_job`·`intent_job`·`latest_plan_job`, `:676-708`).
  - 최종 IMMEDIATE 트랜잭션에서 다시 읽어 다르면 `Conflict`를 반환합니다(`:449`, readiness는 `:634`).
  - 검증 없이 읽던 `IntegrityConnection::query_row`는 삭제됐습니다.
- 과거 job의 root 시계는 `observe_signing_job_quota_time`이 검증된 IMMEDIATE 트랜잭션에서 그 job의 실제 reservation root로 전진시킵니다(`signing_quota.rs:446-463`). 현재 project 설정은 별도로 관측합니다. 이 관측은 이후 거절이 나도 독립적으로 commit됩니다(설계상 허용).
- `signing_clock_integrity` 테스트 2개가 통과했습니다.
  - 위조된 job 결합이 시계를 전진시키기 전에 거절되는지 확인합니다.
  - 선택 중에 외부 commit을 주입했을 때 다음 writer 검증이 거절하는지 확인합니다.
- `rootless_lifecycle` 테스트 6개도 통과했습니다.
- PR24 보고서의 "시간 의존 wrong-clock" 가능성은 당시에도 재현하지 못한 가설이었습니다. 이번에 재현하지 않았고, 원인 경로(검증 없는 읽기)는 제거됐습니다.

### 2. T1 정확한 검증기 도달 — 정상(테스트 소스 확인 + 실행)
- **서명 손상 사례:** 외부 연결에서 result와 outbox를 일관되게 바꿉니다. 변경 후 guard SQL을 정확히 복원하고 `validate_live_schema` 통과까지 확인합니다. 그러면 실행 중 handle과 재개방이 모두 `AuthorityError::Signature`로 거절합니다. 이는 taint나 schema 오류가 아닙니다. 원복하면 정상 조회가 처음과 같고, 재개방 뒤에도 같습니다.
- **현재 generation 사례:** 서명은 유효한 채로 target head만 2로 바꿉니다. readiness는 `Invalid("signing target head")`로 거절하지만, 과거 intent 조회는 계속 grant를 반환합니다. 즉 과거 서명 조회와 현재 자격을 별개 계약으로 다룹니다. 원복하면 generation 1로 정상이고 `signing_allowed`·`dispatch_allowed`는 false입니다.
- 두 테스트는 `signing_intents::tests`(10 통과)에 포함됩니다.

### 3. T2 transition INSERT 실패 롤백 — 정상(병렬 검토자, 실행·반례 포함)
- 기존 trigger 기반 테스트는 이름이 `schema_trigger_addition_is_refused_before_cancellation_or_issuance`로 바뀌었고, 조기 schema 거절만 확인합니다.
- 새 테스트는 schema를 바꾸지 않습니다. 테스트 전용 authorizer가 `authority_signing_quota_transitions`에 대한 직접 INSERT(accessor 없음)를 정확히 1회 거부합니다.
- update hook으로 실패 시점의 실제 선행 쓰기를 증명합니다. 취소 경로는 audit, audit head, work event·head·audit binding, quota 시계이고, 발급 경로는 여기에 result, outbox, usage가 더해집니다.
- 실패 뒤 상태:
  - `SQLITE_AUTH`(코드 23)가 반환됩니다.
  - 전체 테이블의 rowid·type·BLOB과 schema가 재개방 전후 모두 같습니다(허용된 독립 quota 시계 commit만 차이).
  - 발급분 점유가 유지되고, 재시도는 정확히 1회만 성공하며, replay는 변화가 없습니다.
- **필터 주의:** `signing_transition_atomicity_tests`는 0개에 일치합니다. 올바른 필터는 `transition_atomicity`(1개)입니다.

### 4. T3 승인 경로 중간 실패 — 정상(병렬 검토자)
- 13개 조건이 정렬된 선행 쓰기 목록과 정확히 대조됩니다(`audit_atomicity_tests.rs:317-436`).
- 초기 credential UPDATE는 선행 쓰기 0개로 정확히 기술돼 있습니다.
- **두 독립 인간 사례:** 두 번째 member INSERT 거부 직전에 첫 member INSERT가 실제로 실행됐음을 hook으로 확인했습니다. 이어서 전체가 롤백되고 challenge는 미사용 상태로 남습니다. 재개방 뒤 같은 정상 서명 assertion으로 재시도하면 member 위치 `[0,1]`로 성공합니다. 이미 사용된 challenge를 재사용하면 `Conflict`입니다.
- authorizer는 statement 준비 단계에서 거부하므로, 거부된 statement 자체는 아무것도 쓰지 않았습니다. 테스트도 그렇게 해석합니다.

### 5. T3 native 정정 — 정상(병렬 검토자)
- `NativeReferencePin.not_after += 1`은 정확히 두 retry 사례에만 들어갔습니다.
  - `tests/native_evidence.rs:778-779`
  - private suite `native_authority_atomicity_tests.rs:408-412`(observer가 아닌 경우)
- review-evidence INSERT를 포함한 12단계는 기준(`59c70ac`)에 이미 있었습니다.
- 새 observation 손상 검사는 추가되지 않았습니다.

### 6. 기존 회귀와 경계 — 정상
- authorizer·update_hook·commit_hook 설치는 모두 테스트 코드에만 있습니다. 운영 경로에서는 raw connection에 접근할 수 없습니다(`Deref`는 `cfg(test)` 전용).
- `work_audit` 18개, `projection_integrity` 7개, `live_integrity` 6개를 포함한 전체 회귀가 통과했습니다.
- `protected_authority`는 항상 거절하고, 인증·freshness·웹 코드는 바뀌지 않았습니다. 증거를 만들거나 슬롯을 환급하는 경로는 추가되지 않았습니다.

## 문서·명령 관련 지적 (Low, 보안 영향 없음)
1. 받으신 검토 프롬프트의 focused 필터 `signing_transition_atomicity_tests`는 **0개 테스트**를 실행하고 종료 코드 0으로 끝납니다. `transition_atomicity`로 고쳐야 합니다. 저장소 문서에는 이 이름이 없습니다.
2. `reports/README.md:27`의 "13 new fault conditions"는 실제로는 두 인간 흐름의 13조건이고, 새 실패 지점은 약 11개입니다. 단일 인간 흐름의 audit INSERT 1·2번째 실패는 기존에도 있었습니다.
3. `reports/README.md:21-22`의 "preceding SQL" 기록은 실제로는 SQL 원문이 아니라 테이블·동작 목록입니다. T3 스냅샷은 schema를 비교하지 않습니다(T2는 비교함).
4. 실패 주입용 authorizer를 설치하면 운영 schema 보호 authorizer가 그동안 대체됩니다(SQLite는 연결당 하나만 허용). 그동안 일어나는 쓰기는 일반 데이터뿐이고 재시도는 재개방 뒤라 결과에는 영향이 없습니다. T3 주석에는 이 점이 있지만 T2 주석과 follow-up 문서에는 없습니다.

## 미실행·남은 범위
- **미실행:** Docker 격리 Linux·signed Linux·native evidence(패킷과 캡처 수 미확인), 다중 프로세스 실제 경합, SQLite를 거치지 않는 파일 직접 변조.
- **별도 미완료 제품 범위:** Linux 설치·복구·운영 연결, Windows WFP/callout, macOS Network Extension, 보호 bootstrap·signer, 인증된 완료 증명, 외부 감사 앵커.
- 로컬 감사 체인과 `data_version` 변경 감지는 외부 인증이 아닙니다.

로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr25/`에 있습니다. 비밀값과 원시 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다(다른 작업이 쓰지 않는지 먼저 확인하세요).

```bash
for w in /tmp/nox-claude25.zHWgh0 /tmp/nox-claude25t.rIZWJY; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```