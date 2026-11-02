Verifying the migration reviewer's schema-filter finding independently with the real binary.

The schema-filter finding reproduces on the standard binary: a `sqliteX_hidden` trigger passes a same-version migrate with exit 0, while the same trigger under an ordinary name is rejected. I'm checking the smoke and focused results next.

Environment error: the Python Playwright 1.62 package looks for headless shell build 1234, but the pre-installed browser is build 1243. Checking whether the scripts accept an explicit browser path.

Browser smokes (rerun with explicit Chromium) and the umask 0002 test run are in progress.

The disk ran out of space (84MB free) and the linker crashed with a bus error, which is an environment problem rather than a product bug. I'm deleting the build outputs from my own probe worktrees to free space, then I'll rerun the umask test.

# PR #19 독립 보안 검토 — 서명 quota 예약 무결성

## 결론
- **원래 L1과 내부 반례 A·B는 해결됐습니다. C는 문서에 적힌 10개 guard 범위에서는 해결됐지만, 핵심 evidence 트리거가 그 목록에서 빠져 있습니다.**
- **Critical·High·Medium 결함은 없습니다.** Low 결함 3건(F1~F3)을 직접 재현해 확정했습니다. 그 밖의 Low 1건(F4)은 이관 검토 에이전트만 재현했습니다.
- F1은 PR #18 L1과 같은 공격 계층입니다. **트리거를 지우지 않고 일반 SQL만으로** 발급된 슬롯이 다시 반환됩니다. 그 원인 가운데 하나는 문서에 미완료로 적힌 "운영용 전달 증명 없음"입니다.
- 공개 서명·dispatch 경로가 정상 빌드에서 계속 닫혀 있습니다. 그래서 지금 당장 악용할 수 있는 경로는 아닙니다. 다만 전달 기록을 근거로 슬롯을 반환하는 설계를 실제 운영에 쓰기 전에는 F1을 반드시 해소해야 합니다.

## 검토 대상과 환경
- **base:** `5a7551d1d7a59a8f92f74dc972953e5162fd5a90`
- **head:** `2ef3aecec27fee6a5c89a63c3b975057bef2e598`
  - 커밋 2개: `ecab551`, `2ef3aec`
  - 병합 커밋 `09ef6a8`과 트리 `3424806…`이 같은지 직접 확인했습니다.
- **변경 범위:** 27개 파일, 2,234줄 추가, 211줄 삭제
  - `migration_007.sql`과 `docs/specs`는 바뀌지 않았습니다(diff 0바이트).
  - 서비스와 웹 코드는 바뀌지 않았습니다.
- **직접 읽은 경계:**
  - `migration_008.sql` 전체
  - `migrations.rs`의 `apply_v8`·`validate_v8`·schema digest
  - `signing_quota.rs`의 전이 기록·legacy 검증·회계 guard
  - `signing_jobs.rs`의 `outbox`·`lifecycle_status`·`renew`·`cancel`
  - 관리자 CLI 변경분, `check.sh`, 관련 문서
- **작업 폴더:**
  - 전체 검사용 worktree: `/tmp/nox-claude19.bWyATG`
  - 반례용 worktree: `/tmp/nox-claude19r.lSiCT8`
  - 내부 병렬 에이전트 2개: 이관 담당 `/tmp/nox-claude19m.abvIDK`, CLI·claim 담당 `/tmp/nox-claude19c.xH7Kjf`
  - 모든 worktree는 detached 상태이고 원복을 확인했습니다(`git status` 출력 없음).
- **도구:** rustc·cargo 1.99.1, Python 3.13.17, Node 22.22.0, Python Playwright 1.62.0
- CI 성공과 기존 보고서는 결론의 근거로 쓰지 않았습니다.

## 명령별 결과 (직접 실행)

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 728 통과 / 0 실패 / 1 ignored(process test) |
| — 명시적 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 156 통과(파일 10개) |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 334 통과 / 1 ignored ※ 1차는 디스크 부족으로 실패 |
| `cargo build … --bins --examples` | 0 | — |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 ※ |
| `smoke_catalogue_navigation` / `enrollment --browser` | 0 / 0 | 11 / 25 ※ |
| `smoke_enrollment --authority-metadata` | 0 | 41 |
| `smoke_authority_review` | 0 | 40 ※ |
| `--lib store::signing_` | 0 | 44 통과 / 1 ignored |
| `--lib store::migrations::tests` | 0 | 5 통과 |
| `--test signing_contract --test signing_intents --test signing_admin` | 0 | 9 + 2 + 7 |
| `cargo test -p fw_authority_service` | 0 | 6 + 9 + 33 + 5 |
| 반례 모듈 `zz_review19` (7개) | 0 | 7 통과(수정 후) |

- 위 수치는 모두 보고된 기준치와 같습니다.
- 위 표에서는 1 ignored를 통과로 세지 않았습니다. 대신 `check.sh`가 그 테스트를 실제로 빌드한 정상 실행 파일로 따로 돌려 통과했습니다.
- 집중 검사와 전체 검사의 중복은 합산하지 않았습니다.

**환경 실패와 프로브 오류 (수정 후 재실행):**
- **※ 브라우저 smoke 6종(1차):** 모두 실패했습니다. Python Playwright 1.62가 headless shell 빌드 1234를 찾는데, 설치된 브라우저는 빌드 1243이었습니다. 각 스크립트의 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`으로 재실행해 모두 통과했습니다.
- **umask 1차:** 디스크가 가득 차서(84MB) 링커가 Bus error로 죽었습니다(exit 101). 제 probe worktree들의 `target` 폴더만 지워 공간을 확보하고 재실행해 통과했습니다.
- **제 반례 1차(exit 101):** 두 건은 프로브 결함이었습니다.
  - D: v7의 `issued_at` 불변 트리거를 함께 우회하지 않았습니다.
  - F: 위조 뒤에 서명 helper를 호출했습니다.
  - UNKNOWN 픽스처의 예약 시각도 앞서 있어 `Time` 오류가 났습니다.
  - G에는 컴파일 오류가 있었습니다.
  - 모두 같은 반례로 고쳐 재실행했습니다.
- 에이전트의 하네스 오류(unwrap, 셸의 `$?`, 경쟁 지연)도 수정 후 재실행했습니다. 두 에이전트의 최종 실행 결과: 이관 6/6 통과, CLI·claim 15/15 통과.

**미실행:**
- `linux-lab.py`, `signed-linux-lab.py`, `smoke_native_evidence.py`는 Docker 데몬이 없어 실행하지 못했습니다(`/var/run/docker.sock` 없음). dockerd를 띄우면 호스트의 iptables와 bridge가 바뀌므로 띄우지 않았습니다.
- 따라서 Linux 66/40, signed 98/43, native 33/5 기준치는 **확인하지 못했습니다**.

## 확정 결함

### F1 [Low] 모든 guard가 유지된 상태에서도 일반 SQL로 전달 증거를 위조하면 발급된 dispatch 슬롯이 반환됨
- **위치:**
  - v7의 work head에는 트리거가 없습니다. work event와 delivery는 INSERT를 검증하지 않습니다(`migration_007.sql:149-203`).
  - `active` 증거는 delivery 행의 존재만 요구합니다(`migration_008.sql:76,83`).
  - `lifecycle_status`는 이를 정상으로 받아들입니다(`signing_jobs.rs:573,580-596`).
- **재현:** 반례 `zz19_e`. 실제 Ed25519 서명 픽스처로 동시 배포 한도 1, issued 상태를 만듭니다. 이때 다음 예약은 거절됩니다(`Quota`). 이어서 트리거를 하나도 지우지 않고 다음을 실행합니다.
  1. dispatch work event INSERT(`delivered`, revision+1, claimed 단계는 건너뜀)
  2. work head UPDATE
  3. delivery INSERT(outbox의 `grant_hash` 복사, 임의 결과 바이트와 그 해시)
  4. `kind=active` 전이 INSERT
  5. 예약 `state='active', dispatch_slots=0`
- **기대:** 거부, 또는 회계·조회에서 모순 검출.
- **실제:**
  - 다섯 문장이 모두 성공했습니다.
  - 새 예약이 **ADMITTED**됐고, 재개방 뒤에도 ADMITTED였습니다.
  - `lifecycle_status`는 `Ok(ready, delivered, held=false)`로 모순 없이 표시했습니다.
- **같은 원인의 다른 사례:** 미발급 작업에서 cancelled event와 head를 함께 위조하면 감사 기록 없는 취소·해제가 됩니다. 이 경우 진행 중이던 finalize는 거절되고 발급된 슬롯은 환급되지 않으므로 Info로 봅니다.
- **영향:**
  - 원래 L1과 같은 신뢰 경계(DB 작성자)와 같은 효과(발급 슬롯 환불)입니다.
  - 문서의 "unsupported slot refunds guard"와 "A confirmed delivery returns the dispatch slot"은 위조 가능한 행으로 충족됩니다.
- **수정 방향:**
  - work event 삽입 순서 guard를 둡니다(revision = head+1, 허용 상태기계, claim 식별 일치).
  - head 갱신은 최신 event와 같을 때만 허용합니다.
  - delivery INSERT는 claimed dispatch head일 때만 허용합니다.
  - 근본적으로는 인증된 전달 수신증이 생길 때까지 delivery를 근거로 한 슬롯 반환을 금지하거나, 서명된 receipt에 결합해야 합니다.

### F2 [Low] 열린 연결에서 하는 회계 guard 검사 목록에 핵심 `transitions_evidence` 트리거가 빠짐
- **위치:** `signing_quota.rs:812-837`의 10개 목록. `migration_008.sql:50`의 evidence 트리거는 목록에 없습니다.
- **재현:** 반례 `zz19_b`. issued 상태로 한도가 차 있습니다(다음 예약 `Quota`).
  1. `DROP TRIGGER authority_signing_quota_transitions_evidence`
  2. 증거 없는 `active` 전이 INSERT
  3. 예약 UPDATE
- **실제 결과:**

  | 시점 | 새 예약 | 비고 |
  |---|---|---|
  | 트리거 삭제 직후 | **ADMITTED** | |
  | 트리거를 정확히 복구한 뒤 | ADMITTED | |
  | 재개방 뒤 | ADMITTED | |
  | 대조군: 트리거를 지운 채 재개방 | — | 재개방이 `unexpected authority v8 schema`로 거절됨 |

  해당 job의 `lifecycle_status`만 `signing quota lifecycle` 오류를 냈고, 회계는 그대로 승인했습니다.
- **영향:** 내부 반례 C와 같은 계층(열린 연결의 guard 제거)인데, 가장 중요한 증거 guard가 빠져 있습니다.
- **수정 방향:**
  - evidence 트리거를 목록에 넣습니다.
  - 회계가 의존하는 v7 guard도 함께 넣습니다(reservation immutable, issuance, usage).

### F3 [Low] schema digest의 제외 조건 `NOT LIKE 'sqlite_%'`가 지나치게 넓어, 검사 밖의 트리거가 open·migrate를 통과함
- **위치:** `migrations.rs:139`. 이전 버전부터 있던 코드이지만, v8 문서의 보장이 이 검사에 의존합니다.
- **원인:** LIKE에서 `_`는 임의의 한 글자와 맞고 대소문자를 구분하지 않습니다. SQLite가 실제로 예약하는 것은 `sqlite_` 접두사뿐입니다. 따라서 `sqliteX_…` 같은 이름은 만들 수 있으면서 digest에서는 빠집니다.
- **재현(정상 바이너리):**
  - `init` → `migrate`: 0
  - `CREATE TRIGGER sqliteX_hidden BEFORE INSERT ON authority_audit … RAISE(IGNORE)` 추가 → 같은 버전 `migrate`: **0(통과)**
  - 같은 트리거를 일반 이름으로 만들면 → `MIGRATION_REJECTED`(1)
  - 대조: `sqlite_x`는 SQLite가 직접 거부합니다.
  - 이관 에이전트는 이 트리거가 v7→v8 이관에서도 살아남고, 실제로 동작한다는 것도 확인했습니다. 실행 중인 audit 체인이 fail-closed로 막아서 quota 우회까지는 확인하지 못했습니다.
- **수정 방향:** `lower(substr(name,1,7))<>'sqlite_'`, 또는 예상되는 내부 이름만 허용하는 목록으로 바꿉니다.

### F4 [Low, 에이전트만 재현] v7의 UNKNOWN 예약을 `issued`로 되돌리면 이관이 통과해 UNKNOWN 표시가 사라짐
- **위치:** `signing_quota.rs:757-759`. `issued`를 판정할 때 dispatch 이력에 unknown event가 있는지 확인하지 않습니다.
- 슬롯과 비용은 그대로 유지되므로 환급은 없습니다. 이 항목은 제가 직접 다시 실행하지 않았습니다.

## 요청 항목별 판정

### 원래 L1 — 해결
- 다음 시도는 모두 거절됐습니다(`zz19_a`, reserved·issued·unknown 각각).
  - L1의 UPDATE와 슬롯 열만 바꾸는 UPDATE
  - 상태 초기화와 `issued_at` 변경·삭제
  - 예약·head·전이 삭제와 head의 과거 revision 복귀
  - 증거 없는 released·active 전이
  - 다른 상태의 event를 증거로 쓰는 시도
  - 과거 전이(revision 0) 값의 재사용
- 거절 뒤에도 예약 가능 여부는 계속 `Quota`였고, `lifecycle`과 `held`는 그대로 유지됐습니다.

### 내부 반례 A·B·C

| 반례 | 판정 | 근거 |
|---|---|---|
| A. orphan 취소 | 해결 | 최신 cancelled event만 넣고 head는 이전 상태로 두면 전이·UPDATE가 거절되고, finalize와 lifecycle은 `work head mismatch`(`zz19_f`). 단, head까지 함께 위조하면 F1 계층이 됨 |
| B. 손상된 legacy delivery | 해결 | `result_bytes`만 바꾸면 이관 실패(`signing delivery projection`). `outbox.created_at`을 바꾸면 이관 실패(grant context 불일치). 실패 후 `user_version` 7 유지, transitions 테이블 없음, 원본과 백업이 v7 바이트 그대로 |
| C. 열린 연결의 guard 제거 | 목록 범위에서 해결 | head no-delete를 지우거나 다른 내용으로 바꾸면 `quota accounting guard missing or changed`. 단, F2 누락이 있음 |

- C의 경계: guard를 지운 뒤 **정확히 복구**하면, 지워진 head는 회계에서 계속 빠집니다(ADMITTED, `zz19_c`). 문서는 이를 전체 DB 교체 공격에 해당하는 보장 밖 경계로 다루므로, 결함이 아니라 경계 관찰로 기록합니다.
- 반면 예약 projection의 guard를 우회한 뒤 복구한 경우에는 transition head를 통해 3가지 변형(released, active, reserved-null) 모두 거절됐습니다(`zz19_d`).

### schema 8 이관 — 대체로 정상 (F3·F4 제외)
- 실제 schema를 v7·v8의 알려진 digest와 비교합니다. 트리거 삭제·교체와 부분 인덱스 WHERE 제거는 open과 같은 버전 migrate에서 모두 거절됐습니다.
- 백업은 명시적 경로가 필요하고, 권한 0600과 manifest가 있으며, 이미 있거나 원본과 겹치면 거절합니다. v8에서 다시 migrate하면 백업을 만들지 않습니다.
- 다음 정상 legacy 상태는 모두 바이트를 보존한 채 이관됐습니다.
  - reserved, released, issued, unknown(재claim되어 dispatch head가 `claimed`인 경우 포함), active
  - 만료됐지만 발급되지 않은 reserved는 **held로 유지**됩니다(만료를 환급 근거로 쓰지 않음).
- 이관 뒤 일반 SQL로 `imported` 전이를 넣는 시도는 모두 거절됐습니다.

### 서명·dispatch·조회 — 정상
dispatch를 꺼낼 때마다 실제 Ed25519 서명과 정확한 payload를 다시 검증합니다(`signing_jobs.rs:517-533`). `zz19_g`와 기존 테스트에서 다음은 모두 `lifecycle` 또는 dispatch claim 단계에서 거절됐습니다.
- delivery 바이트만 변경, 바이트와 해시 동시 변경, `grant_hash` 변경
- 발급보다 이른 시각이나 미래 시각
- delivery 삭제, head 없이 들어간 delivery 행
- outbox 시각·바이트 변경
- result의 `job_id` 재바인딩
- 서명 손상, 같은 신뢰 키로 서명한 다른 payload

과거 서명 신뢰에 관한 PR #18의 문서 과장은 해소됐습니다. 문서가 이제 같은 DB의 키 사본까지 바꾼 공격은 보장 밖이라고 명시합니다.

### quota·claim·heartbeat — 정상 (에이전트 실행, 근거 확인)
- signer 최대 3회, dispatch 최대 5회 시도 상한과 backoff가 재개방 뒤에도 유지됩니다. 재전송은 같은 서명 바이트를 씁니다.
- heartbeat:
  - 같은 deadline을 반복하면 event·audit이 늘지 않습니다.
  - claim generation마다 엄격한 연장은 32회까지이며, 재개방해도 초기화되지 않습니다.
  - stale claim으로 no-op 갱신을 시도해도 거절됩니다.
- 취소와 finalize 경쟁 12회에서 매번 정합한 결과 하나만 남았습니다.
- 감사·전이·event 삽입 실패를 주입하면 모든 테이블이 원상태로 롤백됐습니다.
- UNKNOWN은 만료와 재개방 뒤에도 슬롯을 유지했습니다.

### 관리자 CLI — 정상
- unknown 필드, 중복 키, 입력 상한 초과, 잘못된 식별자, 예상하지 않은 옵션은 모두 고정된 진단 문자열로 거절됩니다. 입력값과 경로는 에코하지 않습니다.
- 다른 tenant의 작업 취소는 거절됩니다.
- 출력 실패(`/dev/full`) 뒤에도 commit은 보존되고, 정확히 같은 재시도는 기록을 늘리지 않습니다.
- issued와 UNKNOWN은 취소할 수 없습니다.
- 성공 fixture는 `cfg(test)`에만 있습니다. 정상 바이너리에는 fixture 문자열이 0건이고, 운영 resolver를 여는 feature도 없습니다.

### API/UI — 회귀 없음 (코드 변경 없음)
- HTTP 33·admission·startup 테스트, authority browser 40, 로케일 검사, UI 156이 통과했습니다.
- readiness의 UNKNOWN 표시는 별도 반례로 확인하지 않았습니다.

## 재현하지 않았거나 경계로 분류한 관찰 (Info)
- **delivery replay 경로:** 기존 delivery와 같은 receipt가 다시 오면 claim 확인 전에 `Ok`를 반환합니다(`signing_jobs.rs:790`). 아무것도 바뀌지 않지만, 앞으로 receipt adapter가 생기면 stale worker에게 "성공"을 알려 줄 수 있습니다.
- **진행 중 signer claim 취소:** DB 안에 결과가 없다는 것만 증명할 수 있습니다. DB 밖에서 이미 만들어진 서명은 generation fence에 의존합니다. 서명자를 설계할 때 명시해야 합니다.
- **bounded query 테스트:** 오래된 0비용 이력 10,002건 회귀 테스트는 통과했습니다. 그러나 행 10,000개와 목적지 방문 200,000건 상한을 직접 넘기는 전용 회귀 테스트는 없습니다. 코드상 상한(`LIMIT 10001`, 초과 시 `Quota`)과 부분 인덱스는 유지됩니다.

## 검토 범위 안에서 남은 차단 사항
- 정상 빌드에서는 서명·dispatch가 닫혀 있습니다. 그래서 F1~F4는 현재 운영 경로에서 직접 악용할 수 없습니다.
- 다만 delivery를 근거로 슬롯을 반환하는 경로를 실제 운영에 쓰기 전에는 **F1을 해소해야 합니다**. F2와 F3은 PR이 내세운 "열린 연결 guard 검사"와 "실제 schema 검증" 보장을 완성하려면 함께 고쳐야 합니다.
- 명시된 미완료 작업은 이번 결함과 별개로 남아 있습니다.
  - 운영 bootstrap과 보호 OS 계정
  - 신뢰할 수 있는 build identity와 native qualification
  - 원래 core-request/root/lease 비용 연결, rootless 정책
  - 독립 signer, 인증된 dispatch, production delivery proof
  - PostgreSQL
  - 설치형 Linux·Windows·macOS 자격
- 이번 통과 결과는 private fixture, 가상 인증기, 소프트웨어 서명 키로 얻은 것입니다. 운영 발급이나 제품 완성을 뜻하지 않습니다.

반례 소스는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/zz19_signing_quota_probe.rs`에 있습니다. 로그도 같은 폴더에 있습니다. 비밀값, 개인키, 토큰은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다.

```bash
for w in /tmp/nox-claude19.bWyATG /tmp/nox-claude19r.lSiCT8 /tmp/nox-claude19m.abvIDK /tmp/nox-claude19c.xH7Kjf; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```