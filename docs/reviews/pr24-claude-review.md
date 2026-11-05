The R3/R4 reviewer has reported. The `signing_work_audit` filter was also my own brief's mistake (the correct filter is `work_audit`, which ran 18 tests).

Once the smokes finish, I'll rerun my PR23 R2 counterexample (both membership indexes emptied on a live connection) against PR24, in an idle worktree.

Waiting for smokes to finish.

umask 테스트(505 통과, 3 무시)와 smoke 10종이 모두 통과했고, 이제 PR23의 R2·D1 반례를 PR24에 그대로 다시 실행합니다.

Both panics come from my test harness unwrapping a transaction that the product now rejects at start, which is intended. I'm converting those calls into recorded outcomes and adding a peer-connection variant for the D1 case.

The counterexample that previously got through, emptying both indexes on a live connection, is now refused at transaction start, and the peer-connection variant is refused too. I'm restoring the worktree next.

# PR #24 독립 통합 검토 — PR23 후속 R1~R4 수정

## 결론
- **보안 결함은 확정되지 않았습니다.** R1~R4는 각자의 원래 재현 기준에서 모두 수정됐습니다.
  - 제가 PR23에서 승인을 받아냈던 R2 반례(실행 중 연결에서 두 membership 인덱스 동시 비우기)를 그대로 다시 실행했습니다. 이번에는 트랜잭션 시작 단계에서 거절됩니다.
  - 병렬 검토자의 R1·R2 변조 40건 가운데 승인된 경우는 0건입니다.
- 남은 사항은 Low와 Info뿐입니다. 테스트 범위가 약해진 부분, 검증을 거치지 않는 읽기 1곳, 같은 연결 안의 로컬 쓰기에 대한 신뢰 한계입니다.
- **다음 개발을 막는 결함은 없습니다.**
- 서명·dispatch 보호 게이트는 계속 닫혀 있습니다. 이번 통과 결과는 테스트용 fixture, 가상 인증기, 개발용 서명 키로 얻은 것이며 운영 인증이나 완료 증명이 아닙니다.

## 검토 대상과 환경
- **기준:** `4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`
- **대상:** `ac027412c88eade8d3674c75c2ba6203df023ee6`(단일 커밋, 트리 `66f60c5…`, 기준의 자손이며 기준은 PR23을 포함)
- **변경 범위:** 46개 파일, 4,706줄 추가, 709줄 삭제
  - SQL 변경이 없습니다(새 migration 없음). `schema.sql`, migration 001~013, specs, PR20·PR22 검토 원문은 바뀌지 않았습니다.
  - `fw_control`, `fw_authority_service`, `web/`, CLI, 에이전트, Linux 실행기, `scripts/`도 바뀌지 않았습니다.
  - PR23 보존 원본은 15,349바이트(CR 포함)이고 SHA256 `9a3f3072…`가 일치합니다.
- **환경 재확인:** rustc 1.99.1, 내장 SQLite 3.50.2, Node 22.22.0(EBADENGINE 경고), Python Playwright 1.62.0이며 Docker 데몬은 없습니다.
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude24.HTT5cL`
  - 병렬 검토 worktree: `24l`(실시간 무결성·경합), `24r`·`24b`(R3·R4·테스트 예외, 기준 비교)
  - 모두 detached 상태이며 임시 코드를 원복했습니다.
  - 시작 전에 다른 작업이 돌고 있지 않음을 확인한 뒤, PR23 때의 제 target만 지웠습니다.

## 실행 명령과 결과 (이번에 직접 실행)

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 900 통과 / 0 실패 / 3 ignored(수동 벤치마크 포함, 중첩 worker 요약 2건 제외) |
| — 명시적 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 190 통과 |
| — 로케일 | | 8개 언어, 키 229개 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 505 통과 / 3 ignored(중첩 2건 제외) |
| `cargo build … --bins --examples` | 0 | — |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` / `enrollment --browser` | 0 / 0 | 11 / 25 |
| `smoke_enrollment --authority-metadata --report …` | 0 | 41 |
| `smoke_authority_review` | 0 | 40 |
| PR23 시절 내 반례 재실행 1차 | 101 | **하네스 오류**(아래 설명) |
| 같은 반례, 수정 후 재실행 | 0 | 2 통과, 아래 R1·R2 결과 |

- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 사용했습니다.
- **하네스 오류:** 1차 재실행에서 제 반례 코드가 `transaction().unwrap()`을 썼습니다. 그런데 제품이 이제 트랜잭션 시작 단계에서 거절하므로 그 거절이 panic으로 나타났습니다. 이는 의도된 동작이므로, 결과를 기록하도록 바꿔 다시 실행했습니다.
- **NOT_RUN:** `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py`
  - Docker 데몬이 없습니다(`/var/run/docker.sock` 없음, `dockerd` 바이너리만 존재).
  - dockerd를 띄우면 호스트의 iptables와 bridge가 바뀌므로 띄우지 않았습니다.

**병렬 검토자 실행 결과(같은 SHA, 새로 작성한 fixture이며 이전 private probe가 아님):**
- **실시간 무결성 검토자:**
  - `--lib live_integrity`: 6 통과
  - `--lib projection_integrity`: 7 통과
  - 반례: R1 8건, R2 32건, 경합 5건
- **R3·R4 검토자:**
  - `--lib work_audit`: 18 통과
  - `--lib open_validation`: 4 통과 / 1 ignored
  - 직렬화 테스트 3종 통과
  - 반례 4개 모듈
- 참고: 제 brief가 지정한 필터 `signing_quota_projection_integrity`와 `signing_work_audit`는 0건에 일치하는데도 종료 코드는 0입니다. 둘 다 제 brief의 실수이며 저장소 문서의 문제가 아닙니다. 위 수치는 올바른 필터로 다시 실행한 결과입니다.

## 항목별 판정

### 1. R1·R2 실행 중 연결 변조 — 수정
- **제 재현:**
  - 이전에 ADMITTED였던 "두 인덱스 동시 비우기"(issued·UNKNOWN)는 이제 트랜잭션 시작에서 `authority retained physical integrity`로 거절됩니다.
  - 별도 연결로 head를 숨긴 D1 변형(reserved·issued·UNKNOWN)은 실행 중 연결, open, maintenance 모두 `signing quota transition projection`으로 거절됩니다.
- **병렬 검토자:**
  - R1(rooted·project-only × 4개 상태)과 R2(인덱스 각각, 전부 함께; 32건) 모두에서 연속 3회 거절됐습니다.
  - 무해한 외부 커밋 뒤에도 계속 거절했습니다.
  - 정확히 복구하면 다시 `Quota`로 정상 동작했고, 다시 손상시키면 다시 거절했습니다.
- **검사 방식:** `quick_check`가 아니라 `integrity_check(1)`를 씁니다(`migrations.rs:704-713`).
  - 부분 인덱스(`transition_*_held`)를 비우면 `quick_check`는 ok를 내지만 `integrity_check`는 누락을 잡아 거절합니다.
  - 비부분 인덱스(`*_states`)를 비우면 두 검사 모두 잡습니다.

### 2. `data_version` 검증 캐시와 writer 획득 — 정상
- **재검증 횟수:** 자기 커밋 3회와 롤백에서는 0회, 외부 커밋 1회 뒤에는 1회입니다. 검증 없는 `query_row`는 token을 갱신하지 않습니다.
- **검증 후 IMMEDIATE 획득 전에 외부 커밋이 끼어든 경우**(busy handler로 순서를 확인): 정상 커밋이면 자동 재시도 후 `Ok`, 손상 커밋이면 `Invalid`이고 token은 `None`이 됩니다.
- **검증 중 손상 커밋:** 이후 5번 호출할 때마다 매번 전체 재검증 후 거절합니다. 실패한 검증은 쓸 수 있는 token을 남기지 않습니다.
- **재시도 상한:** 매 검증마다 외부 커밋이 일어나면 정확히 3회 시도 후 typed `Conflict`를 반환합니다. 시도 사이에 다른 연결이 즉시 `BEGIN IMMEDIATE`를 얻으므로 writer lock은 매번 해제됩니다.
- **저장소 오류(lock 대기 초과):** 재시도 없이 1회 만에 오류를 반환하고, token은 바뀌지 않은 snapshot에 그대로 묶여 있습니다.
- token은 COMMIT 이후에 갱신되지 않습니다. `live_integrity.rs:149`의 snapshot 내 첫 읽기에서만 설정됩니다.
- **taint:** DDL, `REINDEX`, `writable_schema`, `ANALYZE`, TEMP trigger는 연결을 영구적으로 오염 상태로 만들고, 재개방 시 전체 검증으로만 해제됩니다. 트랜잭션 안의 `SAVEPOINT`·`RELEASE`가 이 판정을 풀지 않습니다.
- 운영 빌드에는 raw handle이 없습니다(`Deref`는 `cfg(test)` 전용).
- 변경 감지는 외부 인증이 아닙니다. SQLite를 거치지 않고 DB·WAL 바이트를 직접 고치는 경우는 시험하지 않았습니다.

### 3. R3 묶이지 않은 work audit — 수정(병렬 검토자)
- **시험:** 16종의 `signing_{signer,dispatch}_*` audit를 제품의 audit writer로 추가했습니다(guard 유지). 대상은 기존 job(외부·같은 연결), 존재하지 않는 job(외부), 다른 tenant입니다.
- **결과:** 실행 중 읽기, open, maintenance가 모두 거절했고 백업은 만들어지지 않았습니다.
- binding의 hash·kind·time 변조, 중복 audit로 재지정, 단계 간 교체도 모두 거절됐습니다.
- **정상 대조군:** intent·result·budget·quota pin·provisioning 등 work 외 audit와 비슷한 철자의 비정상 kind는 요구 대상이 아닙니다. 따라서 open과 체인 검증이 정상 통과했습니다.
- audit-first/event-second 순서와 롤백도 정상입니다.

### 4. R4 성능과 재사용 — 정상
- **측정 조건:** 실제 lifecycle fixture(정상 prepare 후 공개 cancel)로 측정했습니다. 기준과 대상 모두 release 빌드이고, load 4 이상인 환경이라 수치에 잡음이 있습니다.

  | 취소된 작업 | open (기준 → 대상) | 같은 버전 maintenance (기준 → 대상) |
  |---|---|---|
  | 100 | 약 0.47s → 0.16s | 0.47s → 0.21s |
  | 500 | 2.3s → 0.9s | 2.76s → 0.97s |

- 비용은 여전히 이력 크기에 비례합니다. primitive 하한 측정과는 직접 비교할 수 없습니다.
- **writer 대기:** 500건 open 중 외부 writer의 대기 시간이 기준 2~3초(open 전체 동안 lock 보유)에서 대상 62~165µs로 줄었습니다.
- **검증 중 손상 커밋:** open은 직전 snapshot 기준으로 `Ok`를 반환할 수 있지만(snapshot 의미상 정상), 그 handle을 처음 쓰는 순간 거절됩니다. 쓰기 결과도 남지 않습니다.
- 빈 DB 초기화와 실제 구버전 이관은 여전히 IMMEDIATE 직렬화와 버전 재확인을 거칩니다(`mod.rs:148-183`, `migrations.rs:1336-1366`).
- **캐시·재사용 반례:** 캐시를 공유하는 두 job 가운데 하나를 손상시키고 다른 job을 읽었습니다. 손상 대상은 intent bytes, reservation snapshot, 서명(재해시), transition 시각, audit hash였고, 양방향 10건 모두 거절됐습니다. 기준 코드와 같은 오류였습니다.

### 5. cfg(test) 예외와 테스트 약화 — Low 3건
- 정상 바이너리에서 forensic·primitive·hook 관련 문자열은 0건입니다. 예외는 모두 `cfg(test)` 전용이고, 실제 lifecycle fixture에는 적용되지 않습니다.
- 공개 SQL, v1/v2 바이트, 과거 root 시계, 영구 실효 점유 관련 회귀 테스트는 모두 통과했습니다(`check.sh`).

**T1 [Low, 테스트 범위]** `signing_intents.rs:1653` `stored_signature_and_generation_projection_corruption_is_refused`
- 이제 같은 연결의 taint 때문에 먼저 거절되므로, 이름과 달리 서명과 generation 검사까지 도달하지 않습니다.
- 서명 검증 자체는 `signing_jobs` 테스트가 별도 연결로 확인하고 있습니다.

**T2 [Low, 테스트 범위]** `signing_quota.rs:1808` `failed_transition_rolls_back…`
- 주입한 트리거가 트랜잭션 시작에서 거절되므로, 이름이 말하는 "늦은 transition 삽입 롤백"은 실행되지 않습니다.

**T3 [Low, 테스트 범위]** 기존 late-fault 통합 테스트 11개가 "early refusal" 테스트로 이름이 바뀌었습니다(정직한 변경). 진짜 늦은 장애는 `audit_atomicity_tests.rs`와 `native_authority_atomicity_tests.rs`에서 audit INSERT 지점에만 주입합니다.
- 해당 위치: `authority_store.rs:1118,1367`, `authority_quorum.rs:1056,1472`, `core_access_store.rs:364`, `plan_review_evidence.rs:402`, `review_login_replay.rs:237`, `native_evidence.rs:294,742`, `target_metadata.rs:272,690`
- 다음 지점의 중간 장애 주입이 사라졌습니다: credential·challenge UPDATE, approval set·member INSERT, review evidence INSERT.
- `native_evidence.rs:742`에서는 `not_after += 1` 변형도 빠졌습니다.

이 밖에 새 `#[ignore]`는 수동 벤치마크 하나뿐입니다. 추가된 `Conflict => return` 분기는 기존보다 엄격합니다(다른 오류는 panic).

### 6. 인증·실행·UI — 정상
- 이 PR은 인증, freshness, 웹, 로케일 코드를 바꾸지 않았습니다.
- `protected_authority`는 항상 거절하고, `signing_allowed`·`dispatch_allowed`·`current_eligible`은 false로 고정입니다. 새 feature는 없습니다.
- 브라우저 smoke(영어 기본, 저장 선택, authority UI 포함)와 로케일 8개를 확인했습니다.

## 미확정·정보성 관찰
- **I1 [Low/Info]** `IntegrityConnection::query_row`(`live_integrity.rs:217-223`)는 검증 없이 읽습니다.
  - `signing_intents.rs:435,462,521`에서 job의 quota 시계를 고를 때 씁니다.
  - 바로 다음 단계인 IMMEDIATE 검증이 지속적인 변조는 거절합니다. 다만 변조와 복구를 정확히 그 순간에 맞추면 시계 관측 1회가 엇나갈 수 있습니다. 해당 읽기를 검증된 트랜잭션 안으로 옮기기를 권합니다.
- **I2 [Info]** 같은 연결이 로컬로 커밋한 쓰기(예: 존재하지 않는 job의 work audit)는 다음 open, maintenance, 외부 변경 때까지 검출되지 않습니다.
  - 운영 경로에서는 raw handle이 없어 도달할 수 없습니다. 문서의 "로컬 쓰기 신뢰" 설계와 같습니다.
  - `SAVEPOINT`로 시작한 트랜잭션은 거부가 아니라 taint만 됩니다. 이 역시 운영 경로에서는 도달할 수 없습니다.
- **I3 [Info, 가용성]** 한 tenant의 손상이 모든 tenant의 audit 체인 검증을 거절하게 만듭니다(설계상 trade-off).

## 남은 범위
- **다음 개발 전 권장:** T1·T2 테스트의 대상을 다시 지정하고, I1 읽기를 검증 경로로 옮깁니다.
- **운영 출시 전:**
  - 이력 크기에 비례하는 검증 비용, 동시 변경 시 거절·재시도의 운영 정책
  - Docker 격리 Linux·signed·native 재검증(이번 NOT_RUN)
  - 별도 미완료 범위: Linux 운영 연결·설치·복구, Windows WFP/callout, macOS Network Extension, 보호 bootstrap·signer, 인증된 완료 증명, 외부 감사 앵커
- `data_version` 변경 감지와 로컬 감사 체인은 외부 인증이나 앵커가 아닙니다.

반례 소스와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr24/`에 있습니다. 비밀값과 원시 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다(다른 작업이 쓰지 않는지 먼저 확인하세요).

```bash
for w in /tmp/nox-claude24.HTT5cL /tmp/nox-claude24l.u96h6v /tmp/nox-claude24r.exOFXO /tmp/nox-claude24b.1M8h9T; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```