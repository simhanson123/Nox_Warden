registry·schema15 담당 검토자의 보고가 들어왔습니다. Low 확정 결함이 1건 있습니다. 철회된 trust key를 다시 pin하면 `"status":"pinned"`로 성공처럼 보고됩니다. 다만 권한이 되살아나지는 않습니다.

충돌 legacy14 DB 거절과 실제 구버전 DB의 이관은 정상임을 확인했습니다. 이제 `check.sh`만 남았습니다.

세 검토자 모두 완료됐습니다. `check.sh`가 끝나면 나머지 직접 실행으로 넘어가겠습니다.

`check.sh`가 종료 코드 0으로 통과했고, workspace Rust 1,016개, 취소 CLI 1개, 축소 기능 Rust 32개, UI 211개, Python 진단 36/6/14/3이 확인되었습니다. 이어서 umask 테스트와 workspace 빌드, focused 테스트, Python runner 테스트, `smoke_protected_signer`(Docker 필요 여부 확인), 나머지 smoke를 차례로 실행하겠습니다.

백그라운드에서 순차 실행 중입니다. 끝나면 결과를 모아 한국어 최종 보고서를 드리겠습니다.

이 알림은 이미 확인한 `check.sh` 완료 알림입니다(종료 코드 0). 순차 실행이 끝나기를 기다리고 있습니다.

# PR #27 독립 검토 — 보호 bootstrap과 독립 signer 통합 묶음

## 결론
- **High 확정 결함이 1건 있습니다(S-1).** 새 독립 signer `fw_signer`가 요청마다 DB 파일을 열었다 닫으면서, 같은 프로세스의 SQLite 잠금을 모두 풀어 버립니다.
  - 병렬 검토자가 실제 signer로 재현한 결과는 다음과 같습니다.
    - 외부의 짧은 읽기 한 번 뒤에 commit이 사라졌습니다.
    - signer를 재시작하자 **같은 manifest에 서로 다른 유효한 DSSE bootstrap 승인이 두 번 발급**됐습니다.
    - 읽기 전용 리더가 DB를 폴링하면 signer가 SIGBUS로 죽었습니다.
  - 저는 실제 저장소로 잠금이 풀리는 메커니즘을 직접 재현했습니다.
- 그 밖에는 Low 3건(R-1, L1, L2)과 정보성 항목들이 있습니다.
- **다음 개발 blocker:** S-1입니다. 이 signer의 핵심 계약인 "반환 전 보존, 정확한 재시도, 중복 없음"이 깨지므로, 이 위에 기능을 더 쌓기 전에 고쳐야 합니다.
- **현재 운영 영향은 제한적입니다.** 운영 policy 서명과 dispatch는 계속 차단돼 있고, bootstrap 결과는 `authorized_pending_target_confirmation` 상태일 뿐 운영 grant가 아닙니다.
- **원격 상태(이번에 다시 확인):**
  - PR #27은 미병합(open)이며 head `5fc576f`, base `dded7e9`(PR26, 미병합)입니다. main은 `a624a1e`입니다.
  - CI 42216796210은 attempt 1이 `failure`로 끝났는데, billing lock으로 실행 전에 실패한 것입니다(steps·artifacts 0). 이는 로컬 테스트 실패도, 원격 PASS도 아닙니다.

## 검토 대상과 환경
- **기준:** `dded7e94e84ef0e59a0552e961c5c57eaaabdd81`(트리 `9108060`)
- **대상:** `5fc576f672c2e0671164b73a667e3452b99ea82a`
  - 트리가 `719b80f88255921711ede7b4f4da81876568f7e3`로 일치합니다.
  - 단일 커밋이고, 기준의 자손입니다.
- **변경 범위:** 69개 파일, 10,482줄 추가, 223줄 삭제
  - SQL 001~014, `schema.sql`, specs, 기존 검토 원문은 바뀌지 않았습니다. 새 SQL은 `migration_015.sql`이고, 검토 원문은 PR26 후속 보고서 1개가 추가됐습니다.
- **환경:** rustc 1.99.1, Node 22.22.0(`package.json`이 24.19.0을 지정해 EBADENGINE 경고), Python Playwright 1.62.0. root로 실행했고 관리 Docker는 없습니다(`/var/run/docker.sock` 없음, `DOCKER_HOST` 미설정).
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude27.ygMw1W`
  - 병렬 검토자: `27r`·`27o`(registry·schema15·이관, `27o`는 3866cea로 옮겨 남겨 둠), `27w`(owner·bootstrap·adapter, 내 잠금 재현에도 사용), `27s`(signer·D6, 정리됨)
  - 모두 원복했고 `git status`가 비어 있습니다. 시작 전에 실행 중인 작업이 없음을 확인한 뒤, 이전 PR26 때 제 target만 지웠습니다.

## 직접 실행한 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 1,016 통과 / 0 실패 / 3 ignored(중첩 요약 2건 제외) |
| — 별도 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 211 통과(파일 11개) |
| — 로케일 | | 8개 언어, 키 229개 |
| — Python 진단 | | 36 / 6 / 14 / 3 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 593 통과 / 3 ignored(중첩 2건 제외) |
| `cargo build --locked --workspace --bins --examples` | 0 | — |
| `--test authority_registry_{contracts,store,integrity,admin,matrix}` | 0 | 14 / 13 / 7 / 8 / 2 |
| `--lib schema15_` | 0 | 2 |
| `cargo test --locked -p fw_signer` | 0 | lib 5 + startup 2(main·doc는 0개) |
| `python native/linux/test_core_snapshot_runner.py` | 0 | 21 |
| `python native/linux/test_signed_runner.py` | 0 | 11 |
| `python scripts/smoke_protected_signer.py --report …` | **2** | 스크립트 자체가 `NOT_RUN`, checks 0(Docker 필요) |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` | 0 | 11 |
| `smoke_enrollment` API / 브라우저 / authority-metadata | 0 / 0 / 0 | 23 / 25 / 41 |
| `smoke_authority_review` | 0 | 43 |
| 내 잠금 해제 재현 프로브 | 0 | 1 통과(1차는 `-shm`이 없던 프로브 조건 오류로 무효) |

- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드 번호가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 썼습니다.
- **NOT_RUN(관리 Docker 없음):** `smoke_protected_signer.py`(실제 operator CLI·서로 다른 UID 시나리오), Linux·signed·core-access·native evidence lab
  - 호스트에서 dockerd나 iptables를 켜지 않았습니다.
  - 실제 패킷과 capture 수는 이번에 측정하지 못했습니다. PR 본문의 수치(47 checks, 66/40 등)는 새 검증 결과가 아닙니다.

**병렬 검토자 실행 결과(같은 SHA, 새로 작성한 반례):**
- **registry:**
  - `--lib registry_clock_race` 1 통과
  - 계약 프로브 72건
  - 늦은 장애 주입 5경로
  - 9개 테이블 추가 충돌 모드
  - 실제 dded7e9 바이너리·라이브러리로 만든 v14 DB 2개의 이관
  - 3866cea 코드로 만든 충돌 DB 거절
- **owner·adapter:**
  - `--lib signer_adapter` 5 통과
  - `signing_admin` 12, `signing_intents` 2 통과
  - 반례 9+1개(초기 2회 실패는 프로브 오류)
- **signer·D6:**
  - root에서 숫자 UID 65531~65533으로 실제 signer를 띄워 프로브했습니다(OS 계정은 만들지 않았고 정리함).
  - D6 구성 입력 39건(1건 불일치는 프로브 오류로 정정)

## 확정 결함

### S-1 [High] fw_signer의 DB 검사가 SQLite POSIX 잠금을 해제함
- **위치:** `crates/fw_signer/src/linux.rs:162-183`의 `check_database`
  - `private_file()`로 DB, `-wal`, `-shm`의 `File`을 열고 곧바로 버립니다.
  - 이 검사는 `AuthorityStore::open` 직후(`:322-323`)와 요청마다 `recheck()`(`:357`)에서 실행됩니다.
- **원인:** POSIX `fcntl` 잠금은 프로세스 단위입니다. 같은 파일의 아무 descriptor라도 닫으면 그 프로세스의 잠금이 모두 풀립니다(SQLite "howtocorrupt" §2.2). 저장소는 WAL 모드입니다.
- **직접 재현(메커니즘):**
  1. 실제 `AuthorityStore`를 열고 읽기를 수행합니다.
  2. 이때 다른 프로세스가 `-shm`의 DMS 바이트(128)에 배타 잠금을 시도하면 **BLOCKED**입니다.
  3. 같은 프로세스에서 `check_database`처럼 세 파일을 열었다 닫습니다.
  4. 같은 시도가 **ACQUIRED**가 됩니다.
- **병렬 검토자 재현(실제 signer):**
  1. status, 외부 짧은 읽기(문서의 출력 유실 복구 절차와 같은 동작), `authorize_bootstrap` 순으로 실행합니다.
     - 외부 연결이 "마지막 연결"로 닫히면서 `-wal`·`-shm`을 지우고, signer는 지워진 WAL에 계속 commit합니다.
  2. SIGTERM을 보내면 durable 승인 행은 0개입니다.
  3. 재시작 후 다시 `authorize_bootstrap`을 호출하면, 첫 승인과 다른 두 번째 승인이 발급됩니다(`issued_at`과 해시가 다름).
  4. clock floor 갱신도 사라졌습니다.
  5. 읽기 전용 리더가 폴링하면 5회 중 4회 SIGBUS로 종료했습니다.
- **기대:** 잠금이 유지되고, 반환 전에 durable하게 보존되며, 재시도는 정확히 같은 승인을 돌려줘야 합니다.
- **영향:**
  - 같은 manifest에 유효한 bootstrap 승인 2개가 생깁니다.
  - 감사·clock floor 기록이 유실됩니다.
  - signer 가용성이 떨어집니다.
  - 같은 메커니즘이 `sign_job`의 내구성도 위협합니다.
  - 기존 lab은 리더가 WAL checkpoint를 해서 통과할 뿐, 이 문제를 검출하지 못합니다.
- **수정 방향:**
  - SQLite가 연 뒤에는 같은 파일을 프로세스 안에서 open·close하지 않습니다.
  - 대신 부모 디렉터리 fd에 대한 `fstatat(..., AT_SYMLINK_NOFOLLOW)`로 dev, ino, uid, mode, nlink를 확인하거나, 검사용 fd를 프로세스 수명 동안 열어 둡니다.
  - 회귀 테스트를 추가합니다.
    - (a) signer 요청 뒤 외부 DMS 잠금이 BLOCKED여야 합니다.
    - (b) 외부 읽기 → authorize → SIGTERM → 재시작 후 바이트가 같은 승인과 floor가 유지돼야 합니다.

### R-1 [Low, 검토자 재현] 철회된 trust key를 다시 pin하면 성공으로 보고함
- **위치:** `crates/fw_authority/src/store/authority_registry.rs:426-433`
- **재현:** CLI로 pin → revoke → 같은 pin을 실행하면 종료 코드 0, `"status":"pinned"`가 나옵니다(key 1개, 철회 1개).
- **영향:** 권한은 되살아나지 않지만(binding `current=false`), 운영자를 오도합니다.
- **수정 방향:** `Conflict`나 철회 상태를 반환하고 테스트를 추가합니다.

### L1 [Low, 검토자 재현] 승인 origin이 project 단위로 고정되지 않음
- **위치:** `authority_registry.rs:917-932`, `:1858-1868`, `:1628`
- **내용:** status와 import가 보존된 challenge의 origin이나 관리자가 준 `--approval-origin`으로 verifier를 만듭니다. 그래서 다른 localhost 포트에서 발급·승인한 challenge로도 manifest가 `owner_approved`가 됩니다.
- signer는 설정된 origin이 아니므로 거절합니다(`Binding`). 서명이나 dispatch는 열리지 않습니다.
- **수정 방향:** tenant별로 origin을 고정합니다.

### L2 [Low/정보성] gate 이름 목록 불일치
- `CoreRegistryStatus`에는 `BUILD_IDENTITY_REQUIRED`가 없습니다.
- readiness는 포괄 코드만 씁니다.
- signer status는 2개 코드만 나열합니다.
- 모든 flag가 false이므로 진단·문서 일관성 문제입니다.

## 정보성·미재현
- **I-2(코드 추론, 미재현):** `verify_dsse`는 신뢰 key ID의 서명만 검증하고, 다른 서명 최대 7개를 검증 없이 canonical bytes에 남깁니다. 이 때문에 서명을 덧붙인 사본이 먼저 등록되면 원본이 `Conflict`가 될 수 있습니다.
- **L3:** 연쇄 rotation(`old=N→new=N+1`)이 target head의 epoch와 대조되지 않습니다. 초기화되는 것은 없지만, 향후 target 확인 작업에서 조정이 필요합니다.
- **I-1:** `asset_ids`와 `asset_revision_hashes`의 길이가 같아야 한다는 조건은 spec보다 엄격합니다. 인덱스로 대응시키지는 않습니다.
- **signer:**
  - `accept()` 오류가 나면 서비스가 종료됩니다(`linux.rs:439`).
  - 연결을 하나씩 순차 처리해서 느린 controller 클라이언트가 최대 약 6초 동안 다른 요청을 지연시킵니다.
- **D6:** ±1000ms 허용치에 여유가 거의 없어 드물게 오거절할 수 있습니다(이론적, 미재현).

## 항목별 판정
1. **registry 계약 — 정상.**
   - 닫힌 JSON, 필수 nullable 필드, 크기 제한, base64 정규형, DSSE PAE를 확인했습니다.
   - 64바이트 위조 서명은 서명 검증까지 도달해 `Signature`로 거절됩니다.
   - 범위 결합, 배타적 만료, 문자열 uint64 epoch(최대값 포함)를 확인했습니다.
   - asset 배열을 인덱스로 대응시키지 않고, envelope·delegation·service ID 의미를 보존합니다.
2. **schema15 — 정상, R-1 제외.**
   - pin, 승인, proof, revocation의 늦은 장애 5경로에서 원자적 롤백 후 재시도가 성공했습니다.
   - 9개 테이블의 충돌 거절은 롤백되는 양성 대조로 guard 도달을 증명했습니다.
   - 비정규 바이트는 open에서 거절됩니다.
   - 다른 연결이 만료를 관측한 뒤에는 최종 트랜잭션이 `Time`으로 거절됩니다(되살아나지 않음).
3. **owner WebAuthn — 정상, L1 제외.**
   - manifest, origin, challenge 재사용, counter, 다른 principal, 미활성·철회 credential, 다른 역할은 모두 거절됩니다.
   - proof hash만으로는 owner 동의가 만들어지지 않고, controller 세션도 가져오지 못합니다.
   - 단일 owner Lab 초기 profile을 Team bootstrap governance로 과장하지 않습니다.
4. **fw_signer — S-1 결함, 나머지는 정상.**
   - 닫힌 요청 형식이고, payload·actor·`PASS` 입력 경로가 없으며, 키가 노출되지 않습니다.
   - SO_PEERCRED로 UID를 확인하고, `O_NOFOLLOW`·전용 경로·단일 링크를 강제하며, DB 교체를 검출합니다.
   - 3초 절대 deadline, 4096바이트 상한, EOF 처리, 키 유실과 재시작 거절을 확인했습니다.
5. **bootstrap root — 정상.**
   - 독립 pin hash와 정확히 일치해야 합니다.
   - 기존 target epoch·generation·서명 상태를 초기화하지 못합니다(재생성은 `Conflict`, 관련 테이블 불변).
   - 결과는 `authorized_pending_target_confirmation`입니다.
   - management baseline B와 전체 StateIR baseline은 서로 다른 값으로 구분됩니다.
6. **core adapter·운영 차단 — 정상.**
   - 실제 typed payload, 원래 `[S,E)`, 원래 기간 비용, 현재 승인·quota·claim·generation을 확인합니다.
   - 테스트 witness는 `cfg(test)` 전용입니다. 운영 `protected_authority`는 항상 거절하고, `prepare`와 `sign_retained_job`도 거절합니다.
   - `signing_allowed`·`dispatch_allowed`는 false이고, 미인증 delivery로는 환급되지 않습니다.
7. **D6a·D6b — 수정(단위 테스트·구성 입력 수준).**
   - 내부·외부 검사기 모두 정수 타입으로 U=1, e=0, C=5, 차감값 6, 정확한 E−8, ±1초를 강제합니다.
   - 잘못된 형식은 StageFailure로 처리합니다.
   - 이전 불안정 사례는 이제 통과합니다.
   - 5초 예산, 2초 reserve, 복구 기한은 바뀌지 않았습니다.
   - 실제 패킷과 capture는 NOT_RUN입니다.
8. **legacy14 거절 — 정상.**
   - 충돌 DB는 모든 tenant에 대해 다음과 같이 거절됩니다.
     - 현재 open: `MigrationRequired{14,15}` 또는 CLI `DATABASE_REJECTED`
     - 명시적 migrate: `Binding` 또는 `MIGRATION_REJECTED`
   - 새 백업은 생기지 않고, 원본과 기존 백업의 SHA가 바뀌지 않습니다.
   - 정상 v14 DB는 행·rowid·BLOB을 보존한 채 이관되고 재실행은 no-op입니다.
   - 자동 복구나 운영 restore를 주장하지 않습니다.

## blocker 구분
- **다음 개발 blocker:** S-1. signer의 내구성·중복 방지 계약을 복구하고 회귀 테스트를 추가해야 합니다.
- **production·release blocker(이번 PR 범위):** S-1, R-1, L1(origin 고정), Docker 격리 lab과 보호 signer smoke의 실제 실행, 원격 CI 실행(billing 해소 후)
- **production·release blocker(문서상 미완성):**
  - build identity, native qualification, target epoch 확인, policy signer key, workload source attestation
  - 인증된 완료 증명, 외부 감사 앵커
  - Linux 운영 설치·복구, Windows WFP/callout, macOS Network Extension
  - Team bootstrap governance
- 가상 인증기, 실험 UID, Linux lab의 결과는 실제 사람 동의나 설치형 3개 OS 자격이 아닙니다.

반례와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr27/`에 있습니다. 비밀값, 키, 원시 assertion은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다(다른 작업이 쓰지 않는지 먼저 확인하세요).

```bash
for w in /tmp/nox-claude27.ygMw1W /tmp/nox-claude27r.vzdkME /tmp/nox-claude27o.94LXHX /tmp/nox-claude27w.u7MIew; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```