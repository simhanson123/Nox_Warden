D3, D4 and D6 review from the earlier context arrived. That reviewer also confirms that its first build was broken by my target deletion; I'll record this as my own operator error. After the quiet `check.sh` completes, I'll probe the new `read-signing-project-quota` CLI and the repeated-prefix HTTP fix myself.

Waiting for the quiet `check.sh` rerun to finish.

`check.sh`를 다시 돌려 종료 코드 0으로 통과했고, 테스트 수치는 Rust 873개, CLI 1개, 축소 기능 32개, UI 190개가 통과했습니다. 이제 새 `read-signing-project-quota` CLI를 정상 바이너리로 직접 시험하겠습니다.

The read command checks out: strict input, no DB changes, correct diagnostics, and unknown projects are rejected. My v2 pin input was malformed, so there was nothing to read back; I'm fixing the input to match the repo's test format.

Output-loss recovery works: after a lost write, the read shows revision 2, and retrying with that revision returns 2 with no extra audit. Quick revoked-pin read, then umask, builds and smokes.

Expired and revoked pins both read back correctly, with revision 1 retained and nothing written. I'm running the umask suite, builds and smokes next; Docker is unavailable, so the Linux, signed and native lab checks will be NOT_RUN.

Waiting for umask tests, builds and smokes to finish.

# PR #23 독립 통합 검토 — PR22 후속(D1~D6) 수정

## 결론
- **Critical·High·Medium 결함은 없습니다.** D1~D6은 원래 재현 기준에서 모두 수정됐습니다.
- 새로 확정한 사항은 Low 4건입니다(R1~R4).
  - R1·R2는 실행 중인 연결의 admission만 겨냥한 협조 변조에서 아직 한도를 넘는 승인이 가능하다는 내용입니다. 다음 open에서는 거절됩니다.
  - R4는 가용성 문제입니다. 전체 open 검증 비용이 누적 이력에 비례해 커집니다.
- **다음 개발을 막는 결함은 없습니다.** 다만 운영처럼 오래 실행되는 서비스에 쓰기 전에는 R1·R2·R4를 해결하거나 문서로 범위를 명시해야 합니다.
- 서명·dispatch 보호 게이트는 계속 닫혀 있습니다. 이번 통과 결과는 테스트용 fixture, 가상 인증기, 개발용 서명 키로 얻은 것이며 운영 인증이나 완료 증명이 아닙니다.

## 검토 대상과 환경
- **기준:** `d54021a9df32c0a041c52002b05a0e9d64058c0f`
- **대상:** `8b9c3ef71f30b21de9ecfd2d6118f99da32b2f4f`(단일 커밋, 트리 `d43669c…`, 기준의 자손)
- **변경 범위:** 42개 파일, 2,882줄 추가, 284줄 삭제
  - SQL 변경은 새 `migration_013.sql` 하나뿐입니다.
  - `schema.sql`, migration 001~012, `docs/specs`, PR20 보고서는 바뀌지 않았습니다(diff 0).
  - `docs/reviews/pr22-claude-review.md`의 SHA256은 `174db04e…`로 일치합니다. 이는 저장소에 보존된 사본의 해시이며, 외부 원본 바이트를 확인한 것은 아닙니다.
- **환경 재확인:** rustc 1.99.1, Node 22.22.0(`package.json`은 24.19.0을 고정해 EBADENGINE 경고), Python Playwright 1.62.0이며 Docker 데몬은 없습니다.
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude23.vI6QND`
  - 이전 컨텍스트에서 시작한 병렬 검토 worktree: `/tmp/nox-claude23a…`(D1·D2·D5), `/tmp/nox-claude23b…`·`/tmp/nox-claude23o…`(D3·D4·D6, 구버전 바이너리)
  - 제 반례용: `/tmp/nox-claude23.WaoEVA`
  - 모두 detached 상태이며, 임시 코드를 원복해 `git status`가 비어 있음을 확인했습니다.

**운영 실수(제 책임):** 이번 요청 직후 디스크를 확보하려고 `/tmp/nox-claude*/target`을 일괄 삭제했습니다. 그런데 이전 컨텍스트에서 시작한 `check.sh`와 병렬 검토자 빌드가 아직 돌고 있었습니다. 그 결과 다음 두 실패가 생겼고, 둘 다 제품과 무관합니다.
- 해당 `check.sh`가 dep-info 오류로 실패(exit 101)
- 검토자의 첫 빌드 실패

해당 실행은 결과로 세지 않았고, 모두 새로 다시 실행했습니다.

## 실행 명령과 결과 (이번에 직접 실행)

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` 1차 | **101** | `--lib` 187 통과 / 1 실패: `competing_maintenance_processes…`(SQLITE_BUSY), 아래 R4 |
| 해당 테스트만 단독 재실행 ×3 | 0 | 3/3 통과(각 실행마다 부모 1개 + 경쟁 worker 2개 요약 출력) |
| `bash scripts/check.sh` 2차(부하 없는 상태) | 0 | workspace 873 통과 / 0 실패 / 2 ignored(중첩 요약 2건 제외), 명시적 process test 1, 축소 기능 32, UI 190, 로케일 8개·키 229개 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 478 통과 / 2 ignored(중첩 2건 제외) |
| `cargo build … --bins --examples` | 0 | — |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` / `enrollment --browser` | 0 / 0 | 11 / 25 |
| `smoke_enrollment --authority-metadata --report …` | 0 | 41 |
| `smoke_authority_review` | 0 | 40 |
| 내 반례: D1 재검(`zz22_` 확장), D2 이중 인덱스(`zz23_both`) | 0 / 0 | 각 1 통과(동작 출력) |
| `read-signing-project-quota` 정상 바이너리 프로브 | — | 아래 6번 항목 |

- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 사용했습니다.
- **NOT_RUN:** `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py`
  - Docker 데몬이 없습니다(`/var/run/docker.sock` 없음).
  - dockerd를 띄우면 호스트의 iptables와 bridge가 바뀌므로 띄우지 않았습니다.

이전 컨텍스트에서 시작한 병렬 검토자의 실행 결과(같은 SHA, 새로 작성한 fixture이며 다른 사람의 private probe가 아님):
- **D1·D2·D5 검토자:** `--lib` 188 통과 / 2 ignored, 반례 다수, 정상 바이너리 `migrate` 대조
- **D3·D4·D6 검토자:**
  - `--lib signing_`: 111 통과 / 1 ignored
  - `--test authority_audit`: 13 통과
  - `rebuild_tests`: 13 통과(반례 4개 포함) / 1 ignored
  - SQL 대조 24,360건, pragma 조합 216건
  - SIGKILL 25회

## D1~D6 판정

| 항목 | 판정 | 근거 |
|---|---|---|
| D1 guard 복구 후 숨은 held head | **수정**(직접 재현) | reserved·issued·UNKNOWN 모두에서 같은 연결의 admission이 `signing quota accounting membership`으로 거절됨. 이어서 open과 같은 버전 maintenance도 `signing quota transition projection`으로 거절. 병렬 검토자가 rooted·project-only, unsigned active까지 확인 |
| D2 물리 인덱스 손상 | **open·maintenance에서 수정, 실행 중 연결 잔여는 R2** | open·maintenance는 `authority retained physical integrity`로 거절하고 자동 복구하지 않음. v12 원본(재구성 fixture)과 실제 구버전 v12 DB의 손상도 백업 전에 거절, 원본 바이트 불변 |
| D3 audit head+2 | **수정** | 모든 자리올림, 2⁶³ 경계, 2⁶⁴−1 소진을 big-integer와 대조해 불일치 0. 7·9바이트·TEXT·INT 입력 거부. FK·recursive 4조합 216건 모두 거부. audit 추가와 head 투영이 한 문장 |
| D4 고아 binding | **수정** | event 없는 binding, 재사용, 중간에 끼어든 audit, kind·time 불일치를 FK OFF 포함 모두 거부. 실패 시 event·binding·head가 함께 롤백 |
| D5 intent 없는 예약 | **수정** | 일반 조회·admission·open·maintenance·정상 바이너리 모두 `signing reservation intent identity`로 거부. 초기화 예외(`BeforeJob`·`InitializingJob`)는 prepare 경로 안에만 있음. primitive fixture 예외는 `cfg(test)` 전용 |
| D6 같은 초 갱신 이관 | **수정** | 재구성 fixture에서 갱신 2·3회를 v10·v11·v12에서 이관 성공(바이트·rowid 보존). 누락·초과·순서·kind·time·tenant 변조 11종은 모두 거절, 원본·백업 보존. 실제 구버전 CLI로는 서명 이력을 만들 수 없어 그 경우는 재구성 fixture로만 검증 |

## 확정 결함

### R1 [Low] reservation과 head 투영을 함께 숨기면 실행 중 admission이 한도를 넘겨 승인함 — 병렬 검토자 재현
- **위치:** `account()`의 membership 비교(`signing_quota.rs:1095-1114`)는 변경 가능한 투영 두 개(reservation 쪽, head 쪽)만 비교합니다.
- **재현:** 별도 연결에서 다음을 실행합니다.
  1. reservation과 transition head의 트리거를 지웁니다.
  2. reservation을 `released`, 슬롯 0, `issued_at` NULL로 바꾸고 head도 `released`로 바꿉니다.
  3. 트리거를 원래 SQL로 정확히 복구합니다.
- **기대:** 거절.
- **실제:** rooted·project-only 4개 상태 모두에서 실행 중 연결의 예약이 **ADMITTED**. 다음 open과 maintenance는 거절합니다.
- **영향:** 오래 실행되는 서비스가 재시작 전까지 한도를 넘겨 승인할 수 있고, 재시작하면 DB 전체가 열리지 않습니다.
- **문서:** `authority-store.md:673-678`은 admission이 "independent indexes"로 교차 확인한다고 적어, 협조 변조에 대한 한계가 분명하지 않습니다.

### R2 [Low] 두 membership 인덱스를 함께 비우면 실행 중 admission이 한도를 넘겨 승인함 — 직접 재현, 병렬 검토자도 확인
- **재현:** 두 번째 연결에서 다음을 실행합니다.
  1. `writable_schema`로 `quota_{project,root}_states`와 `transition_{project,root}_held` 인덱스 SQL에 `WHERE 0`을 넣습니다.
  2. `REINDEX` 합니다.
  3. SQL을 원래대로 복구합니다.
- **기대:** 거절.
- **실제(issued·UNKNOWN):** `integrity_check`는 오류를 보고하지만, 이미 열린 연결의 예약이 **ADMITTED**됩니다. 이후 open은 거절합니다.
- 병렬 검토자에 따르면 project-only는 `project_states` + `transition_project_held` 두 개만 비워도 같은 결과입니다.
- **수정 방향:** admission 시 해당 범위에 `PRAGMA quick_check(테이블)`를 돌리거나, 인덱스를 거치지 않는 상한 있는 대조를 추가하고, 문서 표현을 범위에 맞게 고칩니다.

### R3 [Low] v13이 event에 묶이지 않은 signing work audit를 받아들임 — 병렬 검토자 재현
- **재현:** prepared 상태 job에 `signing_signer_cancelled` audit만 정상 체인으로 추가합니다.
- **실제:** `read-signing-intent`와 같은 버전 `migrate`가 모두 통과합니다.
- **원인:** v13 검증은 binding 수와 event 수만 비교합니다(`signing_jobs.rs:329`). 반면 legacy 이관은 초과 audit를 거절합니다(`:419`).
- **영향:** 거짓 감사 기록(예: 가짜 취소)이 남습니다. quota와 권한 상태는 바뀌지 않습니다.

### R4 [Low, 가용성] 전체 open 검증 비용이 누적 예약 수에 비례하고, 그동안 write lock을 잡음
- **실측(병렬 검토자, primitive fixture 하한):** 취소된 예약 20,000건에서 open이 release 빌드 23.4초, debug 78.6초. 예약당 약 1.2ms입니다.
- open은 `BEGIN IMMEDIATE`로 검증하는 동안 쓰기를 막고, 다른 연결은 최대 5초만 기다립니다.
- 제 1차 `check.sh`에서 경쟁 이관 테스트가 부하 상태에서 SQLITE_BUSY로 실패한 것도 이와 같은 성질입니다. 부하가 없을 때는 3/3 통과합니다.
- **영향:** 이력이 길어지면 CLI가 느려지고 동시 작업자가 busy 실패를 겪습니다(fail-closed).

### 참고(Info)
- v12에 남아 있던 "고아 binding이 나중에 소비된" 이력은 v13으로 이관되면 정상 이력과 구별되지 않습니다.
- 백업 도중 종료되면 빈 manifest를 가진 쌍이 남고, 같은 이름으로 재시도하면 거부됩니다. 문서(`authority-store.md:342-349`)대로 새 대상 경로가 필요합니다.

## 회귀 확인 (5~7번 항목)

### 5. 보존과 회귀 — 정상
- migration 001~012, specs, 이전 검토 원문은 바뀌지 않았습니다.
- 실제 구버전(d54021a) 바이너리로 만든 v12 DB(65개 표, 44행)를 v13으로 이관했습니다. rowid·`typeof`·BLOB이 모두 같았고, 백업은 0600 권한에 manifest 해시가 일치했습니다. 다시 migrate하면 no-op입니다.
- 할당량 쪽 회귀(rootless, A→None→A, 공유 한도, 실효 점유)는 `--lib` 전체와 `check.sh`에서 통과했습니다. 이번 diff는 해당 로직을 바꾸지 않았습니다.

### 6. `read-signing-project-quota` — 정상(직접 실행)
- 입력이 `{}`(공백 포함)일 때만 받아들입니다. 빈 입력, `{"a":1}`, `{}{}`, `[]`, `null`, `{"":1}`은 `INPUT_REJECTED`입니다.
- 미초기화 project는 `SIGNING_QUOTA_REJECTED`, 추가 옵션은 `ARGUMENTS_REJECTED`, `/dev/full`은 `OUTPUT_FAILED`입니다.
- 읽기 전후로 DB 전체 행 해시와 audit 수가 그대로였습니다.
- 출력 유실 복구: 쓰기 결과를 `/dev/full`로 잃은 뒤 read로 revision 2를 확인하고, 그 revision으로 재시도하면 revision 2를 반환하며 audit이 늘지 않습니다.
- 만료된 pin과 철회된 pin도 revision 1과 `revoked` 표시로 정확히 조회됩니다.
- HTTP 경로는 `strip_prefix`로 바뀌어 v1·v2 모두 접두사 반복을 거부합니다(service 테스트 통과). 웹 UI와 로케일은 이번 PR에서 바뀌지 않았습니다.

### 7. 인증·실행 경계 — 정상
- metadata 시간 테스트는 이제 자식 프로세스가 stdin 읽기에 도달한 뒤 8초짜리 pin과 challenge를 만듭니다. 이 proof는 명령 시작 시각 기준으로는 유효하므로, CLI가 stdin 이전 시각을 썼다면 수락하게 됩니다. 따라서 유효한 반례입니다.
- 이번 PR의 운영 코드 변경은 관리자 CLI 읽기 명령, 서비스 경로 접두사, 저장소 검증뿐입니다. 인증과 freshness 로직은 바뀌지 않았습니다.
- `signing_intents.rs`는 바뀌지 않았고, 보호 signer·dispatch 거절과 AI 자기 승인 차단이 그대로 유지됩니다.

## 남은 범위
- **다음 개발 전 권장:** R1·R2를 고치거나, 적어도 문서에 실행 중 연결의 한계를 명시합니다. R3은 v13 검증에 "모든 signing audit가 bound"인지 확인하는 조건을 추가하면 됩니다.
- **운영 출시 전:**
  - R4(검증 비용과 lock 정책)
  - Docker 격리 Linux·signed·native 재검증(이번 NOT_RUN)
  - 이미 명시된 미완료: Linux 설치·복구·운영 연결, Windows WFP/callout, macOS Network Extension, 보호 bootstrap·signer, 인증된 완료 증명, 외부 감사 앵커
- 로컬 감사 체인은 외부 인증이나 앵커를 대신하지 못합니다.

반례 소스와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr23b/`에 있습니다. 비밀값과 원시 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다.

```bash
for w in /tmp/nox-claude23.vI6QND /tmp/nox-claude23.WaoEVA /tmp/nox-claude23a.HFOnc1 /tmp/nox-claude23b.kVE2ej /tmp/nox-claude23o.O03J6Z; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```