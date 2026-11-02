# User-supplied PR #18 external reviews

These are the three reports supplied by the user in the resumed-work handoff on
2026-11-02. Reviewer names are user-supplied attribution; the reports were not
executed by the current development session. Their temporary paths, cleanup
commands, tool versions and test results describe the reviewers' environments.
They are retained as source evidence, not commands to execute in this checkout.
The appendix text below is preserved verbatim with CRLF line endings normalized
to LF for this repository.

- Reviewed head: `4c0b65ee4399b500a83011426255be54bdc10654`.
- Comparison base: `956de27f4833138da15d0621e0c4163591374826`.
- PR: <https://github.com/simhanson123/Nox_Warden/pull/18>.
- Merge: `5a7551d1d7a59a8f92f74dc972953e5162fd5a90`.
- Source attachment: `Pasted text.txt`, Sediment file
  `file_00000000f47082098d7fec785e347756`.
- Source attachment SHA-256: `9cd36b700bc38592b5d197a479f5d43b94e2725728bd80dcc4b7f1d77c659798`.
- Original appendix bytes SHA-256: `a27d0290d47cea22fc7a82feb7b0a7af9d2c070c9902167c2d765cfeaa77b9fe`.

Claude reported one confirmed Low finding: ordinary SQL UPDATE could release
issued reservation slots while leaving a ready/queued job. The two GLM reports
reported no confirmed finding in their respective scopes; that does not negate
Claude's reproduced counterexample. Other observations require source checks,
scoped documentation or new regressions rather than automatic reclassification
as confirmed defects.

New local reproduction, implementation, independent review and verification are
recorded separately in [review continuity](../review-continuity.md),
[the task ledger](../../reports/task-ledger.json) and
[the verification summary](../../reports/README.md). These reports do not review
the subsequent reservation-integrity correction. Counts overlap across suites
and reviewers and must not be summed into a product-wide test total.

---

# 부록 A — 사용자가 전달한 Claude 검토 원문

아래는 사용자 제공 보고서다.
보고서 안의 임시 worktree 경로와 정리 명령은 검토자의 환경 기록이며,
현재 작업 환경에 그대로 적용하는 지시가 아니다.

Claude의 결과

저장소 검토자의 L1(예약 상태가 일반 SQL UPDATE만으로 바뀌어 발급된 동시성 슬롯이 환불됨)은 직접 재현해 확인하겠습니다. 제안된 테스트는 각 파일의 비공개 테스트 헬퍼를 쓰므로, 폐기 worktree에서 해당 테스트 모듈 안에 임시로 넣어 실행한 뒤 원복합니다. 먼저 모듈 구조와 해당 트리거를 확인합니다.

트리거는 입력 열과 `issued_at`만 보호하고 `state`, `active_slots`, `dispatch_slots`는 막지 않습니다(`migration_007.sql:137-143`). 헬퍼 시그니처를 확인한 뒤 이 반례를 실행해 보겠습니다.

저장소 검토자의 L1 지적은 제 실행으로 확인됐습니다. 트리거를 둔 채 상태를 직접 바꾸면 거절되던 예약이 승인되고 job 조회는 불일치를 못 잡습니다. 이어서 L2도 코드로 짧게 확인하겠습니다.

# PR #18 독립 보안 검토 — 서명 의도·quota·재시도 경계

## 결론
- **Critical·High·Medium 결함은 없습니다.** Low 결함 1건을 확정했습니다(예약 상태 투영의 변조 무검출).
- 요청하신 1~3·5·6번은 실제 Ed25519·WebAuthn 경로를 쓰는 독립 반례로 모두 방어를 확인했습니다. 여기에는 내부 검토에서 고친 target head 되돌리기 문제의 재확인도 포함됩니다.
- 4번 원자성은 독립 검토자의 코드 추적과 제 재현으로 확인했습니다.
- 운영 경로(공개 prepare·finalize·worker)는 이 빌드에서 항상 거절됩니다. 따라서 아래 "성공"은 모두 `cfg(test)` witness로 만든 테스트 결과이며, 운영 발급이나 제품 완성을 뜻하지 않습니다.

## SHA와 환경
- **대상:** `4c0b65ee4399b500a83011426255be54bdc10654`
  - 기준 `956de27f4833138da15d0621e0c4163591374826`의 자손이며 단일 커밋입니다.
  - 병합 커밋 `5a7551d`(현재 `origin/main`)와 트리가 같습니다.
- **변경:** 41개 파일, 8,364줄 추가, 196줄 삭제
- **작업 폴더:** `/tmp/nox-claude18.34Zb3T`(독립 detached worktree)
- **도구:** 고정 toolchain rustc 1.99.1, cargo 1.99.1, Python 3.13.17

## 실행한 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `cargo test --locked -p fw_authority --test signing_contract --test signing_intents` | 0 | 11 통과(9 + 2), 0 실패 |
| `cargo test --locked -p fw_authority --lib store::signing_intents::tests` | 0 | 9 통과, 0 실패 |
| 임시 반례 모듈 1차(`signing_intents.rs`, 5개) | 101 | 4 통과, 1 **반례 코드 오류**(아래 설명) |
| 임시 반례 2차(서명 결합 변조 수정판) | 0 | 1 통과 |
| 임시 반례(`signing_quota`·`signing_jobs` 예약 상태 변조, 2개) | 0 | 2 통과(결함 재현 출력 확인) |

- 모든 임시 반례는 폐기 worktree 안에서만 넣었고, 실행 직후 `git checkout`으로 원복했습니다. worktree의 소스는 깨끗합니다.
- **프로브 오류:** 1차 서명 변조 반례가 panic한 것은 반례 코드 쪽 문제였습니다. `not_after`만 바꾸자 서명 라이브러리 `sign_grant`가 확인 창 불일치(`invalid dispatch or confirm window`)로 서명 자체를 거부했습니다. `confirm_not_after`를 함께 조정한 2차 실행으로 대체했습니다. 제품 결함이 아닙니다.

## 확정 결함

### [Low] 예약 상태가 일반 SQL UPDATE로 바뀌어 발급된 동시성 슬롯이 환불되고, 읽기 경로가 이를 감지하지 못함
- **위치:**
  - 트리거가 입력 열과 `issued_at`만 보호: `crates/fw_authority/src/store/migration_007.sql:137-143`
  - 보호되지 않는 열: `state`, `active_slots`, `dispatch_slots`
  - 회계 쿼리: `signing_quota.rs:672` 부근
  - 상태 조회: `signing_jobs.rs` `lifecycle_status`, `signing_intents.rs:697-769`
- **전제:** 인증 DB에 쓸 수 있어야 합니다. 문서상 이는 authority 손상에 해당하는 신뢰 경계입니다. 다만 **트리거를 지울 필요가 없습니다.**
- **최소 재현:**
  1. 동시 배포 한도를 1로 고정합니다.
  2. 예약 후 finalize로 발급합니다. 이때 다음 예약은 거절됩니다.
  3. `UPDATE authority_signing_quota_reservations SET state='released',active_slots=0,dispatch_slots=0 WHERE reservation_id=…`
- **기대 결과:** 갱신 거부, 또는 이후 읽기에서 불일치 오류.
- **실제 결과:** 갱신 성공, 새 예약 **승인(ADMITTED)**. 같은 상태에서 ready job의 `lifecycle_status`는 `Ok(state=ready, dispatch=queued)`를 반환합니다.
- **위반 기준:** F_03의 "발급·전송 가능·UNKNOWN 작업의 슬롯은 검증된 증거 없이 반환하지 않는다".
- **영향:** 발급된 작업의 동시성·quota 슬롯이 환불되어 한도를 넘는 준비가 가능해집니다. 같은 변경 안의 다른 가변 투영(target head, 작업 head)은 불변 기록과 대조해 막는데, 이 투영만 예외입니다.
- **수정 제안:**
  - `BEFORE UPDATE OF state,active_slots,dispatch_slots` 트리거로 허용 전이만 남깁니다.
    - `reserved→issued`(같은 문장에서 `issued_at` 설정)
    - `reserved→released`(`issued_at IS NULL`일 때만)
    - `→unknown`
    - `→active`
  - `released`에서 나가는 전이와 발급된 행이 `released`로 가는 전이를 금지합니다.
  - `lifecycle_status`·`status_in_tx`에서 결과·outbox 존재와 예약 상태를 교차 검사합니다.
- **회귀 테스트:** 위 재현을 그대로 씁니다. 갱신이 실패하거나, 새 예약이 거절되거나, 상태 조회가 오류여야 합니다.

## 항목별 확인 (독립 반례 결과)

### 1. Ed25519와 payload·job·intent 결합
- 응답은 job·intent·payload 해시와 **정확한 canonical payload 바이트**가 같아야 하고, 이어서 실제 DSSE Ed25519 검증을 거칩니다(`signing.rs:210-232`).
- 변조 반례 결과:
  - generation, 예약 ID, 유효기간을 바꿔 **실제 키로 다시 서명하고 payload 해시까지 재계산**해도 모두 `Binding`으로 거절
  - 같은 keyid의 다른 키는 `Signature`로 거절
  - job·intent 바꿔치기는 `Binding`으로 거절
  - 각 경우 결과·outbox·사용량 행이 0으로 유지됨

### 2. prepare·finalize의 재검증과 두 단계 사이 변경
- 두 단계 모두 같은 IMMEDIATE 트랜잭션 안에서 다음을 다시 확인합니다(`signing_intents.rs:333-399`).
  - plan, 의미 검토
  - 현재 승인 집합(원본 WebAuthn 재검증)
  - 메타데이터, 컴파일, Baseline 관측
- finalize는 보안 revision이 포함된 `inputs_hash`, target head, 서명자 키 동일성도 확인합니다(`:858-872`).
- 반례 결과(정상 대조군은 성공):

  | 두 단계 사이 변경 | 결과 |
  |---|---|
  | 역할 철회 | `Binding` |
  | plan 은퇴 | `Binding` |
  | project quota 철회 | `Conflict` |
  | 만료 | `Time` |

  모든 경우에 부분 쓰기가 없었습니다. 기존 테스트는 자격증명·메타데이터·관측자 철회를 다룹니다.

### 3. candidate와 baseline, 관측 generation
- 관측은 `artifact_role == Baseline`, `comparison == "match"`이고 관측 해시가 plan의 `baseline_hash`와 같아야 합니다(`:358-370`). 기존 테스트 `candidate_match_is_not_accepted…`가 통과했습니다.
- generation은 관측값이 아니라 plan의 `target_generation`이며, 서명 head+1과 같아야 합니다(`:596-598`).
- 완전히 유효한 상태에서도 **공개** `prepare_signing_intent`와 `finalize_signing_intent`는 `protected signing authority unavailable`로 거절했고, 행을 만들지 않았습니다.

### 4. 원자성과 재시도
- 준비 단계: intent, job, head CAS, 예약, 작업 head, audit가 하나의 트랜잭션입니다.
- 완료 단계: quota, 결과, outbox, audit가 하나의 트랜잭션입니다.
- 스키마가 intent당 결과·outbox·사용량을 하나로 제한합니다. 이는 저장소 검토자의 추적과 기존 테스트로 확인했습니다.
- 제 반례에서 정상 완료 후 재시도는 +2초 시점과 만료 뒤 +400초 시점 모두 `replayed=true, gen=1`만 반환했습니다. 결과·outbox·사용량은 `[1,1,1]`에서 변하지 않았습니다.

### 5. 최신 불변 intent와 target head 대조 — **해결 확인**
- 내부 테스트는 `readiness` 오류만 확인합니다. 저는 권한을 만드는 연산을 직접 시험했습니다.
- gen1 생성 뒤 head를 다음처럼 바꾸고 **다른 plan으로 generation 1을 재사용**하는 prepare를 시도했습니다.
  - gen0/NULL 초기화
  - head 삭제
  - 삭제 후 gen0 재시드

  세 경우 모두 `signing target head history` 또는 `missing signing target head`로 거절됐습니다.
- gen2 생성 뒤의 동작:
  - 변조하지 않아도 gen1 finalize는 거절됩니다(`Binding`).
  - 유효한 과거 gen1 head로 되돌린 뒤 gen2 재사용 prepare와 gen1 finalize도 모두 거절됐습니다.
  - intent는 2개뿐이고 결과·outbox·사용량은 0이었습니다.

### 6. 성공 witness의 격리
- `ProtectedSigningAuthority` 생성, head 시드, `signing_test_support`는 모두 `cfg(test)` 안에만 있습니다(`mod.rs:21-22`, `signing_intents.rs:908-1090`).
- 운영 경로(prepare, finalize, claim·renew·retry·dispatch)는 모두 항상 거절하는 `protected_authority`를 거칩니다.
- signing 코드에 환경변수, cargo feature, 헤더 기반 분기는 없습니다.
- readiness·상태 응답의 `signing_allowed`·`dispatch_allowed`·`current_eligible`은 고정 `false`입니다.

## 재현하지 않은 관찰과 설계상 남은 작업
1. **[Info] 과거 서명 검증의 신뢰 기준이 같은 DB의 키 사본입니다.**
   - 과거 결과 검증은 intent canonical 바이트에 들어 있는 `signer_key`로 합니다(`signing_intents.rs:734-739`). intent 행에는 canonical 해시 열이 없고, finalize 재시도 경로는 이 키를 현재 authority 키와 비교하지 않습니다.
   - 따라서 트리거를 지운 DB 작성자는 키와 서명을 함께 바꿔, 조회에서 "검증된" 것처럼 보이게 할 수 있습니다.
   - 문서 문장 "rewriting a projection and its hash cannot create a valid signature"는 이 경우까지는 성립하지 않으므로 범위를 좁혀야 합니다. 재현은 하지 않았습니다.
2. **[Low, 설계·가용성] 만료된 미발급 예약이 계속 계산됩니다.**
   - 회계 쿼리가 `reserved_until`과 무관하게 `state='reserved'`를 계산합니다.
   - 해제 수단인 `cancel_signing_job`은 라이브러리에만 있고 관리자 CLI나 HTTP에는 없습니다.
   - 현재 운영 prepare가 닫혀 있어 영향은 없습니다(코드로 확인, 재현 안 함).
3. **[Info]** 그 밖에 저장소 검토자가 보고했지만 재현하지 않은 항목입니다.
   - 서명자 claim 진행 중에도 취소가 허용됩니다. finalize는 막히므로 심층 방어 문제입니다.
   - dispatch claim에서 서명을 다시 검증하지 않습니다.
   - claim 갱신 횟수에 상한이 없습니다.
   - v7 DB를 열 때 지워진 트리거를 감지하지 않습니다(v6과 같음).
   - root quota를 같은 조직의 다른 project에서 바꿀 수 있습니다.
4. **[명시된 미완료]** 운영 signer, 보호된 bootstrap과 OS 계정, 신뢰할 수 있는 generation 초기화, native qualification, core request resolver, dispatch·전달 증거, PostgreSQL.

## 실행하지 않은 범위
- `fw_authority` 전체, `fw_authority_service` HTTP, `signing_admin` CLI 테스트, 웹 UI 테스트, `smoke_authority_review.py`(브라우저)는 요청 범위 밖이라 실행하지 않았습니다.
- 다중 프로세스 실제 경합, 정전·크래시 주입, 퍼징도 하지 않았습니다.
- 비밀값과 개인키는 출력하지 않았습니다. 반례 서명에는 저장소의 공개 테스트용 고정 시드를 썼습니다.
- 필요하면 아래 명령으로 worktree를 정리할 수 있습니다.

```bash
git -C /home/user/Nox_Warden worktree remove --force /tmp/nox-claude18.34Zb3T
```

---

# 부록 B — 사용자가 전달한 GLM 5.3 Flash 검토 원문

GLM-5.3-Flash의 결과
worktree `/tmp/nox-flash.FzQYQF` 생성(HEAD 4c0b65e, 41파일 +8364/−196, 단일 커밋). 빌드+테스트 시퀀스를 먼저 백그라운드로 걸고, 대기 중에 문서와 diff를 읽습니다.

CLI에 signing 하위 명령 추가 + `--approval-origin` 필수 옵션 확인. 새 문서 두 개를 읽습니다.

문서 확인. 이제 admin CLI의 main 출력 경로(PR17 진단 유지 여부)와 signing 서브커맨드 구현을 봅니다.

PR17의 출력 수정이 유지됨을 코드로 확인(fd 복제로 LineWriter 우회 + checked flush, help 포함, stderr 파손 시에도 panic 없음). signing 서브커맨드 구현을 읽습니다.

`prepare_signing_intent`의 정상 빌드 거절 게이트는 `target_head` 부재(Binding) + authority basis 부재로 확인 — reasons는 readiness 스냅샷용. 이제 HTTP 측(service lib diff + http 테스트)을 봅니다.

UI 파서와 컴포넌트 검토 완료 — exact key set, `signing_allowed=true` 거절, context 바인딩(이전 계획 응답 폐기), 지연/시계 역행 보정 remaining(), UNKNOWN 예약 유지. Authority.tsx 마운트와 smoke 확장을 확인합니다.

cargo 테스트 대기 중에 locale parity를 재검산하고, 빌드 완료 후 자동으로 이어지는 smoke 러너를 준비합니다.

`metadata_admin` 10 + `signing_admin` 5 = 관리 CLI 15 (기준치 일치), EXIT=0. CLI 실측 프로브를 작성합니다(서비스 미기동, 포트 무충돌).

service 테스트 통과(http 33 + startup 5), cargo build 완료. smoke 러너가 자동 시작될 것이고, 그와 병렬로 CLI 프로브를 실행합니다(포트 미사용).

프로브가 stderr를 캡처 안 하고 있을 뿐, 콘솔에 출력된 코드는 전부 정상 동작입니다. 캡처를 수정합니다.

정확 재시도는 `"expected_revision":"1"`을 제공해야 합니다(문서: 생성 후 null은 conflict). 프로브 수정.

프로젝트 quota pin이 거절됐습니다. stderr 캡처 + 구조체 정의 확인.

프로젝트 pin은 성공했고, `check()`의 detail 인자가 성공 시에도 즉시 평가되어 `r.stderr=None` 크래시가 발생한 프로브 버그입니다. 수정 후 재실행합니다.

동일한 프로브 버그(성공 시 eager detail) + readiness 출력이 상속되어 콘솔로 나간 것. 남은 호출 전부를 캡처로 수정합니다. 참고로 방금 콘솔에 찍힌 readiness 응답이 중요한 증거입니다: `quota_configured=true`(OUTPUT_FAILED 후에도 root pin 보존 확인), 영구 차단 사유 4종 + 미비 사유, `signing_allowed=false`。

CLI 프로브 19/19. 그러나 smoke 러너에서 실패가 있습니다 — 전체 로그 확인.

원인 2가지: (1) authority-smoke는 환경적 ACL 0646 — 이번 버전은 smoke 자체가 `startup_stage=ui_assets startup_code=AUTHORITY_UI_ASSETS_REJECTED`를 실패 줄에 보존합니다(PR15 권고 반영 확인). (2) passkey/enrollment 3종은 `FileNotFoundError` — 내 러너가 명령 목록대로 fw_authority_service만 빌드해 `fw_control` 등 바이너리가 없었음(준비 실패, 제품 결함 아님). 전체 빌드 후 재실행합니다.

라운드 2 진행 중. 대기하며 npm 테스트 총계와 http.rs의 readiness 테스트 본문을 확인합니다.

UI 156 확인. 테스트의 꼬리(POST 차단 등)와 tenant/revoked 테스트를 마저 확인합니다.

라운드 2 대기 중 남은 stdout 실패 케이스(읽기 전용 fd, 파손된 stderr, /dev/null)를 보강 실측합니다.

보강 실측 완료: 읽기 전용 fd→OUTPUT_FAILED, /dev/null→성공, stdout+stderr 동시 파손→rc=1 무panic, /dev/full→OUTPUT_FAILED. 실행 직전 닫힌 stdout의 rc=0은 문서가 명시한 Rust 런타임 /dev/null 복원 동작(설계 문서화됨)으로 예외 정당. 라운드 2 진행 확인.

authority-smoke **40검사 PASS** (기준치 일치). 대기 중 컨트롤러 i18n 프로브를 이번 워크트리로 재실행합니다(포트 18995, 무충돌).

모든 smoke 통과. authority smoke의 신규 signing 관련 검사명을 추출해 보고서에 반영합니다.

모든 검증 완료. 최종 보고서를 작성합니다.

**GLM 5.3 Flash — PR #18 독립 검토 보고 (CLI·HTTP·브라우저·다국어 경계 담당)**

## 1. 대상 · 기준 · 환경 · 변경 통계

- **대상 SHA**: `4c0b65ee4399b500a83011426255be54bdc10654` (단일 커밋 "Persist signing intents with atomic quota and fenced retries")
- **기준 SHA**: `956de27f4833138da15d0621e0c4163591374826` (PR #17 병합 — 내가 검토한 적 없는 구간; 내 마지막 검토 지점은 PR15의 43146fd)
- **작업 폴더**: `/tmp/nox-flash.FzQYQF` (독립 worktree, 제품 수정·커밋·푸시·병합 없음)
- **변경**: 41파일 +8,364/−196 — `signing_intents.rs`(1,597행)·`signing_jobs.rs`(1,336)·`signing_quota.rs`(1,491)·migration_007(203)·`signing.rs`(233)·admin CLI 확장(587행)·`SigningReadiness.tsx`(102)+파서(83)+테스트(182)·authority-locales +464행·smoke +60행
- **환경**: Node 24.22.2 / npm 11.19.1 / Python 3.14.2 / Chrome for Testing 151.0.7922.34 (CDP 가상 CTAP2) / rustc 1.99.1 고정

## 2. 명령별 종료 코드와 실측 수 (기준치 대조)

| 명령 | 종료 코드 | 실측 수 | 기준치 |
|---|---|---|---|
| `npm ci` / `npm run check` / `npm run build` / `build:authority` | 0 / 0 / 0 / 0 | — | — |
| `npm test -- --run` | 0 | **156 passed (10파일)** | UI156 ✓ |
| `cargo test -p fw_authority --test metadata_admin --test signing_admin` | 0 | **10 + 5 = 15** | 관리 CLI15 ✓ |
| `cargo test -p fw_authority_service --test http --test startup` | 0 | **33 + 5** | — |
| `cargo build -p fw_authority_service --bins --examples` | 0 | — | — |
| 전체 빌드(fw_control/fw_cli/fw_agent/fw_authority 포함) | 0 | — | smoke 사전 요건 |
| `smoke_authority_review.py` | 0 | **40** | browser40 ✓ |
| `smoke_passkeys.py` | 0 | **76** | 기존 유지 ✓ |
| `smoke_enrollment.py --authority-metadata` | 0 | **41** (23+18) | ✓ |
| `smoke_enrollment.py --browser` | 0 | **25** | ✓ |
| 자체 CLI 프로브 / 컨트롤러 i18n 프로브 | 0 / 0 | **19/19** / **8/8** | — |

## 3. 집중 검토 결과

**① 새 CLI 경계** — `read-signing-readiness`·`request-signing`은 옵션 목록 자체에 `--approval-origin` 4개째 필수(`fw_authority_admin.rs:62-67`): 누락·과다·중복 모두 `ARGUMENTS_REJECTED`(실측). 기본 origin 없음, JSON 본문에 `approval_origin` 필드 주입 → `INPUT_REJECTED`(closed shape `deny_unknown_fields`, 실측). stdin 128 KiB+1 → `INPUT_REJECTED`, 비-UTF8 인자 → 고정 코드 무에코(실측). **PR17의 stdout 실패 진단 유지 확인**: `write_stdout`(`fw_authority_admin.rs:533-562`)이 stdout fd를 복제해 LineWriter 버퍼링을 우회하고 `write_all+flush`를 검사 — `/dev/full`·닫힌 파이프·읽기 전용 fd 전부 실측으로 `rc=1 AUTHORITY_ADMIN code=OUTPUT_FAILED`, `--help`도 동일, stdout+stderr 동시 파손에도 panic 없이 rc=1(코드 주석 명시), `/dev/null`은 문서대로 정상 성공. 실행 직전 닫힌 stdout만 rc=0인데 이는 `docs/target-metadata.md` "Command output and retained state"가 명시한 Rust 런타임 /dev/null 복원 동작으로 설계 문서화된 예외입니다. **참고: PR15에서 내가 보고한 admin CLI "조용한 rc=0" 결함은 PR17에서 수정됐고 PR18에서 유지됨을 실측으로 확인했습니다.**

**② 공개 request-signing 거절** — `prepare_signing_intent`(`signing_intents.rs:414`)는 정상 빌드에서 보호 부트스트랩·빌드 신원·네이티브 자격이 없어 `target_head` 부재로 `SIGNING_REQUEST_REJECTED`(문서화된 고정 거절). 실측: review_fixture 상태에 root+project quota pin까지 완료한 뒤 request-signing → rc=1 고정 코드, **SQLite read-only 조회로 `authority_signing_intents`/`signing_jobs`/`signing_reservations`/`dispatch_outbox`/`target_heads` 전부 0행** — generation·예약·job·outbox 미생성. `read-signing-intent`는 존재하지 않는 intent를 `null`로 반환(조작하지 않음). **출력 실패 후 pin 보존 실측**: root quota pin을 깨진 파이프로 출력 → `OUTPUT_FAILED` 후 exact retry(revision "1") → 동일 revision 1 반환, readiness가 `quota_configured=true`로 보존 확인.

**③ signing-readiness GET** — 서비스 라우트(`fw_authority_service/src/lib.rs:554-567`)는 기존 reviewer·origin·proof·tenant 검사 안에 배치. http.rs 테스트 3종이 401(익명)·403(CSRF 누락)·403(Origin 불일치)·200(정상), `cache-control: no-store`, 응답 raw <4096B, 정확히 15키, plan 바인딩, `signing_allowed/dispatch_allowed=false`, 비밀 후보 문자열(`private_key`/`signed_grant`/`assertion`/`claim_token`) 미노출, **POST → 404**, 쿼리로 타 project 선택 → 400, 타 tenant·폐기된 reviewer 키 → 거절을 단언. 읽기 전용이라 readiness는 승인·발급·예약을 만들지 않음(시간 펜스만 갱신 — 문서 명시).

**④ UI 경계** — `signing-readiness.ts` 파서가 exact 키 검사(15/19키), `signing_allowed=true`·`dispatch_allowed=true` 거절, 사유 열거형 닫힘+불변식(APPROVAL_SET_MISSING⟺hash null 등), intent의 epoch/generation이 **현재** plan과 일치해야 통과, `current_eligible=false` 강제. `SigningReadiness.tsx`의 context 바인딩(plan_hash·tenant·target·aggregation·현재 승인 세트 해시)으로 **이전 계획 응답 폐기**, `remaining()`이 요청 지연과 벽시계 역행을 보정(`observedWall` 단조 하한 + 단조 델타 2중). UI 테스트 8종: 만료된 UNKNOWN이 예약 보유와 역사적 결과를 유지, 새로고침이 미확인 실패 응답을 끌고 가지 않음, 앞선 시계 점프 이후 롤백 불가, 지연 응답이 신선도 재시작 불가, 변경된 승인 맥락이 결정 없이 재검사 등 — UNKNOWN은 만료 후에도 `reservation_held` 표시 유지 확인. 브라우저 smoke의 신규 3검사(readiness 바인딩·새로고침이 assertion 소모 없음·재시작+서명된 dissent가 signing job 만들지 않음) 포함 40/40.

**⑤ 다국어·회귀** — authority 카탈로그 **152키×8 locale**(58→152), controller 229×8, placeholder 불일치 0, 닫힌 열거형 키(`signing.job/delivery/quota/reason.*` 25종) 전 언어 존재, wire 토큰(`sha256:`·`fw.*`·사유 코드) 미번역 전수 확인. 한국어 브라우저 첫 방문 영어(실측 8/8), 저장 언어(de) 유지. passkey 76(CLI 위임 제한 32종 포함), enrollment 41/25 회귀 통과.

## 4. 확정 결함

**검토 범위 내 발견 없음.** (확정 결함, 미재현 의심 모두 없음. 관찰: 실행 직전 닫힌 stdout rc=0은 문서화된 설계 예외이며 결함으로 계산하지 않았습니다.)

## 5. 환경 실패와 프로브 실패 (교정 전후)

- **authority smoke 1차 실패(환경)**: 이 환경의 상속 기본 ACL로 `dist-authority` 0646 생성 → 서비스 거절. **이번 버전의 smoke가 실패 줄에 stage를 직접 보존했습니다**: `FAIL: 1 authority browser checks; stage=service_ready code=AUTHORITY_SMOKE_SERVICE_FAILED startup_stage=ui_assets startup_code=AUTHORITY_UI_ASSETS_REJECTED` — PR15 때 내가 권고했던 "첫 실패 stage 보존"이 반영된 것으로 확인. chmod 644/755 정상화(문서 절차, 검사 완화 없음) 후 **40/40**.
- **passkey/enrollment 1차 실패(내 준비 실패)**: 지정 명령 목록은 `fw_authority_service`만 빌드하여 `fw_control` 등 바이너리 부재(`FileNotFoundError`) — 제품 결함 아님. 저장소 지침(reports/README.md)의 전체 build 후 재실행 → 76/41/25 전부 통과.
- **내 프로브 수정 이력**(최초 실패와 구분): stderr 미캡처 3회, exact retry에 null revision 사용(문서대로 conflict — "1"로 수정), `check()` detail 즉시 평가 크래시 2회. 전부 프로브 결함이며 제품은 관측된 모든 코드에서 올바르게 동작. 최종 19/19 + 보강 stdout 실패 실측.

## 6. 미실행 · 한계

- **미실행**: 통합 `check.sh`(전체 Rust 워크스페이스·Clippy·포맷), Linux Docker lab(타 검토자 담당). HTTP 인증 흐름의 수작업 라이브 재현은 하지 않았으며 이는 http.rs 33종+브라우저 smoke 40종이 커버(미실행으로 명시).
- **한계**: signing 트랜잭션의 성공 경로(generation 진행·예약·서명·발급)는 정상 빌드에서 의도적으로 불가능하고 `cfg(test)` witness로만 테스트됩니다(문서 명시) — 내 실측은 거절·보존 경로입니다. **가상 CTAP2 통과는 물리 보안키 호환, 실제 사람의 동의, 운영 signing/dispatch 발급 검증이 아니며**, 본 검토는 검토 범위 내 결과일 뿐 제품 전체의 안전이나 완성을 선언하지 않습니다. 비밀값·개인키·토큰은 보고서에 포함하지 않았습니다(모든 smoke 리포트 `credential_values_recorded=false`, `native_firewall_changed=false` 실측).

---

# 부록 C — 사용자가 전달한 GLM 5.3 검토 원문

GLM-5.3의 결과
모든 측정 완료. 최종 상태 확인:

저는 **GLM-5.3**입니다. PR #18 독립 검토를 완료했으므로 최종 보고합니다.

---

# Nox_Warden PR #18 독립 검토 보고 — GLM-5.3

## 1. 대상·환경·변경 통계

| 항목 | 값 |
|---|---|
| 검토 대상 | `4c0b65ee4399b500a83011426255be54bdc10654` (단일 커밋 "Persist signing intents with atomic quota and fenced retries") |
| 비교 기준 | `956de27f4833138da15d0621e0c4163591374826` (PR #17 병합) |
| 독립 worktree | `/tmp/nox-glm53-pr18.KbrdFS` (mktemp, detached, 타 검토자와 미공유) |
| 변경 통계 | **41파일 +8,364/−196** — `signing_quota.rs`(1,491), `signing_jobs.rs`(1,336), `signing_intents.rs`(1,597), `signing.rs`(233), `migration_007.sql`(203), 테스트 1,865행, 서비스 readiness 엔드포인트, CLI·UI(8개 로케일)·문서 |
| 도구 | rustc/cargo 1.99.1, Node 24.22.2, npm 11.19.1, Python 3.14.2, Docker 29.9.2 |
| 사용자 main | `82bf8dc` 미변경, 워크트리 추적 파일 미변경(비추적 로그/프로브뿐), 잔여 컨테이너 없음 |

## 2. 실행 명령과 실측 수

| 명령 | 종료 코드 | 실측 (중복 합산 없음) |
|---|---|---|
| `source scripts/dev-env.sh; npm ci --prefix web; bash scripts/check.sh` | **0** | **작업공간 Rust 713 통과 + no-default-features 32 통과 = 745, 실패 0** (주어진 기준치 713+32와 정확히 일치); 설계 27·계약 52+28·runner 9·카탈로그 진단 6·권위/네이티브 진단·vendored 검증 통과; **UI 156/156** (기준치 156 일치); fmt·Clippy·tsc·프로덕션 빌드 2종 통과 |
| `(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)` | **0** | **319 통과 / 0 실패** (기준치 319 일치) |
| `python scripts/linux-lab.py` | **0 — PASS** | 일반 단언 66개, **실제 패킷 40개** (호스트 방화벽 미변경, 컨테이너 정리) |
| `python scripts/signed-linux-lab.py` | **0 — PASS** | 일반 단언 98개, **실제 패킷 43개** |
| **프로브 E** (신규 작성, 공개 API+SQL 관찰 39항목) | **0** | **39/39 통과** |

이전 외부 프로브는 받지 않았으므로 재실행했다고 주장하지 않는다. 프로브 E는 이번 검토용 신규 작성이다.

## 3. 확정 결함

**검토 범위 내 확정 결함 없음.** (PR #15 검토에서 내가 보고한 `fw_authority_admin` stdout 무음 성공 결함은 중간 `fix/command-output-and-review-diagnostics` 변경에서 이미 수정되어 이번 대상에 포함됨 — `write_stdout`이 fd 복제 후 비버퍼 직접 쓰기로 오류를 전파하고, `/dev/full`에서 `OUTPUT_FAILED`·exit 1을 실증하는 테스트 `lost_quota_pin_output_keeps_revision_and_never_grants_signing`이 존재한다. `--help` 경로도 동일 경유.)

## 4. 집중 항목별 결론 (소스 정독 + 저장소 테스트 실행 + 프로브 E)

**1) Schema 1–6→7 마이그레이션 — 결함 없음.** `apply_v7`은 정확한 v6 digest 게이트 → 15개 빈 테이블·불변 트리거 → 전체 DB `pragma_foreign_key_check` → `user_version=7`을 한 트랜잭션으로. 기존 DB는 `MigrationRequired{required:7}`; v1–v5 회귀테스트도 `required:7`로 갱신. 저장소 테스트 `schema_six_requires_private_explicit_backup_and_creates_no_signing_trust`가 v6 백업(백업은 v6 유지)·기존 native 영수증 원본 보존·서명 테이블 0행을 검증. **프로브 E**: 유니코드 부모 경로 v6→v7 성공, 재실행 시 신규 백업 없음, 백업/-journal/-wal/manifest/dangling-symlink 사전 존재 시 open 전 거부+원본 v6 보존, hardlink(source==backup) 거부 — 모두 통과. signer·generation·quota 권한의 자동 생성 경로 없음(빈 테이블만 생성).

**2) signing_quota.rs pin CAS·철회·root 연결 — 결함 없음.** 프로젝트 pin은 대응 root pin 존재+현재성 요구(프로브 E: root 없으면 `Binding`); 프로젝트의 root 연결은 영구(`root_id` 변경 → `Binding`, 저장소 테스트+프로브). 멱등 재시도는 동일 내용+`expected==current`+미철회일 때만 개정 유지(감사 이벤트·행 추가 없음 — 프로브 E로 실증). 철회는 개정 단위 CAS이며 영구 row; 철회된 개정의 멱등 재시도는 거부, 명시적 신규 개정(rot)은 허용(프로브 E). **양쪽 한도는 `reserve`에서 root·project 산정을 모두 마친 후에만 행을 쓰며**(저장소 테스트 `both_buckets_are_checked_before_any_reservation_rows_are_written`), 조직 root는 타 프로젝트와 경쟁한다(8연결 스레드 경합으로 정확히 1건 — 저장소 테스트). **호출자 비용/한도 조작 불가**: `SigningQuotaCost` 필드는 private, 공개 API는 pin/철회/관측뿐이고 비용은 `cost_for_plan`이 보존 plan+검증된 리뷰 증거에서만 도출(lease 비용 산식은 private 테스트로 커버; 루트리스 policy 경로·실제 lease 원본 연결은 미구현으로 문서·코드 주석에 명시 — `CORE_REQUEST_BINDING_UNAVAILABLE` 고정 거부).

**3) 24시간 이력·중복 제거·UNKNOWN — 결함 없음.** `account()`는 두 개의 부분 인덱스 스캔(held: reserved/issued/unknown+active-with-lease, accounting: released+lease+`issued_at∈(now−86400, now]`)으로 정확히 F_03의 배타-시작/포함-종료 창을 구현. 발급 시각은 `usage.issued_at`에서 시작(예약 시각 아님 — 테스트가 발급+86400/86400+250 경계를 실증). 목적지는 BTreeSet 합집합, 재시도는 동일 reservation 멱등 반환으로 이중 차감 없음, 취소된 미발급 예약은 예상 비용만 해제하고 발급 이력은 환급 불가. **UNKNOWN은 만료·재시작 후에도 슬롯·비용 유지, 취소·finalize 거부**(테스트 2건). **이력 조회 상한은 조용한 절삭 금지**: 관련 행 >10,000 또는 목적지 방문 >200,000이면 전체 트랜잭션이 `Quota` 실패하고, 무관한 10,002행의 zero-cost 이력은 부분 인덱스로 스캔 예산을 소진하지 않는다(1,000-명령 progress handler로 유한 작업 실증). 감사 실패 주입 시 pin·reserve·finalize가 전부 롤백(실트리거 테스트). 오염된 cost/destination/issuance projection이 **신용(credit)을 만들 수 없음**(불변 트리거 우회 후에도 전 재검증 거부 테스트).

**4) signing_jobs.rs fencing·heartbeat·상한 — 결함 없음.** claim은 불투명 32바이트 토큰(저장은 해시, 상수시간 비교)·worker·phase·generation 결합; 만료·재시작·토큰/worker/tenant 위조·구세대 claim의 finalize 전부 거부(테스트). heartbeat는 원래 intent 마감 이하로만(≤900s, 단축 거부), 세대 불변. **signer 3회·dispatch 5회 상한은 재시작으로 초기화되지 않고**(재개장 후 `Quota` 실증), backoff는 `2^attempts+결정론적 jitter` 상한 60초로 available 이전 claim 거부. 같은 세대 2연결 경합은 정확히 1승자. 공개 worker 경로는 `protected_job_eligibility`로 폐쇄(프로브 E: claim 실패 시 work 테이블 0행).

**5) 취소/finalize 경쟁·환급 금지·재전송 — 결함 없음.** 취소는 results/outbox/ready/dispatch-head 부재를 **증명할 때만** 예약을 해제하고, 경합은 단일 writer 트랜잭션으로 정확히 한 결과(실스레드 barrier 테스트: results/outbox/보유슬롯/lifecycle이 어느 쪽이 이겼는지와 정합). 이미 발급된 grant/outbox의 환급 경로 없음(`cancel_unissued`는 `reserved`+미발급만; issued/unknown/active 거부). 응답 유실은 UNKNOWN 유지, dispatch 재시도는 **동일 signed bytes**(outbox 등식 테스트), 구세대 sender의 ack/unknown 보고는 거부, `VerifiedDelivery` 목격자는 공개 생성자 없음(문서 명시대로). 확정 재시도는 원 결과 승인만 하고 outbox·세대·유효성을 갱신하지 않는다.

**6) mutable head vs immutable history — 결함 없음.** work head는 항상 최신 불변 event와 전등비교(불일치·오염 거부, 테스트); target generation head는 최신 불변 intent(`ORDER BY epoch DESC, generation DESC`)과의 정합 + 참조 intent와의 epoch/generation/시각 재검증. 내부 3자 검토가 재현했던 **세대 head 리셋·삭제·과거 유효 intent로의 롤백 세 반례가 모두 테스트로 막혀 있고**(reset/delete는 `Invalid`, 과거 intent 롤백은 최신 정합 위반), 세대 CAS UPDATE는 낙관적 조건+변경 1행 검사. 시간 역행은 모든 경로에서 `Time`이며 quota clock 단조 트리거가 직접 재작성을 거부한다. 별도 연결 경쟁은 quota(8스레드)·jobs(2연결)·intents(별도 연결 세대 경합) 테스트로 커버.

**공개 경계·UI·서비스**: `protected_authority()`는 빌드에서 무조건 거부 — 설정·브라우저 승인·CLI·랩 영수증으로 우회 불가(프로브 E: quota가 완전히 구성돼도 공개 `prepare`/`claim`/`readiness`가 실패하고 동적 서명 테이블이 0행 유지, 감사 증가 없음). readiness 엔드포인트는 기존 live reviewer·origin·proof 검사를 재사용하는 읽기 전용(서비스 테스트 3건: 다른 tenant·철회 키·no-signing-work 단언). UI 파서는 닫힌 형태·60초 상한·필수 차단 사유 상존·UNKNOWN↔held 정합을 검증한다. `signing_allowed`/`dispatch_allowed`는 항상 `false`.

## 5. 환경 실패·프로브 결함·미실행 구분

- **환경 실패**: 없음 (모든 기본 검사·lab·umask가 이번 세션에서 1회 통과; 첫 시도 재시도 없음).
- **프로브 결함(제 것, 제품 아님)**: 프로브 E 초기 3회 실패 — (a) clock이 전진된 뒤 과거 시각으로 project pin을 시도해 제품이 올바르게 `Time` 거부(프로브 시퀀스 수정), (b) `signing_tables_empty`가 합법적인 quota pin 구성 행까지 포함해 오검출(동적 테이블 검사로 분리), (c) E6 readiness 단언 결합 오류. 수정 후 39/39.
- **미실행**: 브라우저 스위트 전체(이번 프롬프트 범위 외, ledger의 authority browser 40은 원격 CI 기록), 실제 운영 signer/dispatch 배포·전달 증명·PostgreSQL 트랜잭션·물리 전원 장애 주입(제품 미구현 영역), 대량 장기 포화. `>10,000` 관련 행 초과 시 `Quota` 오류 경로는 코드 정독으로 확인(외부 크레이트에서 `reserve`가 `pub(super)`라 직접 실행 불가; 무관 10,002행 유한성은 저장소 테스트로 실행 확인).

## 6. 문서화된 미완료 (결함 아님, 문서와 일치)

보호 bootstrap·OS 신원·신뢰 빌드 정체성·자격있는 native 증거·보호 signer 배포·인증 전달·backup/restore epoch·PostgreSQL 미구현; `cfg(test)` 목격자는 프로덕션 자격이 아님을 코드·문서가 반복 명시; rootless policy·실제 lease 원본 연결 미구현 명시; retention/archival maintenance 미구현.

## 결론

검토 범위(저장소·동시성·복구 경계)에서 **확정 결함 없음**. 실측 기준치는 주어진 값과 정확히 일치했다(Rust 713+32, UI 156, umask 319, 패킷 40+43은 일반 단언 66/98과 별도). 신규 프로브 E 39/39로 마이그레이션 배터리·공개 quota CAS·공개 서명 경계 폐쇄를 독립 반례로 확인했다. 이 결과는 격리 Docker lab·가상 목격자의 범위이며, 운영 signer/dispatch 부재 상태를 임의 스위치로 열거나 제품 완성으로 선언하지 않는다.
