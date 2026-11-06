schema14·저장소 담당 검토자의 보고가 들어왔습니다. Medium 이상 결함은 없고 Low·정보성 항목 2건과 설계 한계 1건이 있습니다. 실제 구버전 바이너리로 만든 v13 DB의 이관도 확인됐습니다. 제 brief의 `window_migration` 필터는 0개에 일치했는데, 올바른 필터는 `window_tests`(2개)입니다.

`check.sh`가 끝나면 나머지 직접 실행으로 넘어가겠습니다.

세 검토자 모두 완료됐습니다. `check.sh`가 끝나기를 기다리고 있습니다.

`check.sh`가 종료 코드 0으로 통과했습니다. 이어서 umask 테스트, workspace 빌드, focused 테스트와 README의 smoke 11종을 차례로 실행하겠습니다.

백그라운드에서 실행 중입니다. 끝나면 결과를 모아 한국어 최종 보고서를 드리겠습니다.

이 알림은 이미 확인한 `check.sh` 완료 알림입니다(종료 코드 0). umask·빌드·focused·smoke 순차 실행이 끝나기를 기다리고 있습니다.

# PR #26 독립 통합 검토 — core 임시 접근 기능 묶음

## 결론
- **Medium 이상 결함은 없습니다.** 새로 확인한 사항은 Low 2건, 정보성 1건, 설계 한계 1건, lab 테스트 공백 4건입니다.
- 가장 중요한 지적은 **F1**이며 제가 직접 재현했습니다.
  - 같은 원본 요청에 고정 임대창 `[S,E)`가 이미 있어도, legacy provenance 경로로는 E를 넘는 정책의 계획이 등록되고 `current=true`로 표시됩니다.
  - 지금은 core 서명이 막혀 있고 예약·intent가 생기지 않아 실제 발급으로 이어지지 않습니다.
- **다음 개발을 막는 결함은 없습니다.** 다만 F1은 core 서명 프로필을 열기 전에 반드시 막아야 합니다.
- **원격 CI 미실행:** PR CI(42036443828)는 billing lock 때문에 실행 전에 실패했습니다. 아래 결과는 모두 로컬 실행이며, 원격 CI 통과를 대신하지 않습니다. 결제 변경, CI 우회, 병합은 하지 않았습니다.
- 운영 서명·dispatch·완료 증명은 계속 차단돼 있습니다. lab, 테스트 키, 가상 인증기의 성공은 운영 자격이 아닙니다.

## 검토 대상과 환경
- **기준:** `a624a1e684a8fc0065ac4f4609101410f56c50bb`(트리 `880986d`, PR25 포함)
- **대상:** `3866ceaa2b86da3ea3653da338d433a23a02b283`
  - 트리가 `7f349ae2b22d1c19464454bcec8eb079d15614ef`로 일치합니다.
  - 커밋 2개(`2cf66c6`, `3866cea`)이고, 기준의 자손입니다.
- **변경 범위:** 74개 파일, 7,896줄 추가, 471줄 삭제
  - SQL 001~013, `schema.sql`, `docs/specs`는 바뀌지 않았습니다. 새 SQL은 `migration_014.sql` 하나입니다.
  - 기존 검토 원문도 바뀌지 않았습니다. `pr25-claude-review.md`가 추가됐고 SHA256 `64665ea1…`이 일치합니다.
- **환경:** rustc 1.99.1, Node 22.22.0(`package.json`이 24.19.0을 지정해 EBADENGINE 경고), Python Playwright 1.62.0. 관리 Docker는 없습니다(`/var/run/docker.sock` 없음, `DOCKER_HOST` 미설정).
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude26.DgPaXF`
  - 병렬 검토자 worktree 4개: `26p`(계획·임대창), `26s`·`26o`(schema14·저장소, 구버전 바이너리), `26n`(Linux 실행기·API·UI)
  - 모두 detached 상태이며, 임시 코드를 원복해 `git status`가 비어 있음을 확인했습니다.

## 직접 실행한 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 943 통과 / 0 실패 / 3 ignored(중첩 요약 2건 제외) |
| — 별도 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 211 통과(파일 11개) |
| — 로케일 | | 8개 언어, 키 229개 |
| — Python 진단 | | 16 / 6 / 14 / 3 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 530 통과 / 3 ignored(중첩 2건 제외) |
| `cargo build --locked --workspace --bins --examples` | 0 | — |
| `--test core_access_window --test core_access_admin` | 0 | 11 + 12 |
| `--lib transition_atomicity` | 0 | 1 |
| `--lib window_tests` | 0 | 2 |
| `--lib native_authority_atomicity` | 0 | 8 |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` | 0 | 11 |
| `smoke_enrollment` API / 브라우저 / authority-metadata | 0 / 0 / 0 | 23 / 25 / 41 |
| `smoke_authority_review` | 0 | 43 |
| F1 직접 재현 프로브 | 0(1차는 프로브 컴파일 오류) | 1 통과, 아래 출력 |

- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드 번호가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 썼습니다.
- **NOT_RUN(관리 Docker 없음):** `linux-lab.py`, `signed-linux-lab.py`, `core-access-linux-lab.py`, `smoke_native_evidence.py`
  - 호스트에서 dockerd나 iptables를 켜지 않았습니다.
  - 따라서 실제 적용, 패킷 확인, 원래 E 시점의 연결 만료, 복구는 **이번에 실행 검증하지 못했고** 정적 검토만 했습니다.
- **0개 실행 필터:** `--lib window_migration`은 0개에 일치했습니다(PASS 아님, 제 brief의 오류이며 올바른 필터는 `window_tests`). `fw_testlab`의 `fw_signed_lab_fixture` 바이너리도 테스트가 0개입니다.

**병렬 검토자 실행 결과(같은 SHA, 새로 작성한 반례):**
- **계획·임대창:** `fw_planner` 27 통과. 반례 프로브 5개와 6개를 실행했습니다(1차 실패는 모두 프로브 쪽 오류).
- **schema14:** focused 테스트, 실제 구버전 바이너리로 만든 v13 DB의 이관, 실패 지점 3곳 주입, 정상 바이너리의 출력 유실 복구.
- **실행기·API·UI:**
  - `fw_linux_executor` 11, `fw_native_evidence` 18, `fw_testlab` 3, `fw_authority_service` 59 통과
  - Python runner 16 통과
  - vitest 56 통과(CoreAccessEvidence 20, Authority 36)

## 확정 결함과 한계

### F1 [Low, 직접 재현] legacy provenance 경로가 고정 임대창을 넘는 계획을 받아들임
- **위치:**
  - `store/access_provenance.rs:79-165`(`register_in_tx`)는 같은 요청의 임대창 기록을 확인하지 않습니다.
  - `signing_quota.rs:645-660`(`cost_for_plan`)도 임대창을 확인하지 않습니다.
- **재현:**
  1. 검토된 계획 B를 고정 임대창 `[08:00, 09:00)`으로 등록합니다(`current=true`).
  2. 같은 원본 요청과 provenance로, 정책이 `[08:10, 09:10)`인 계획 C를 `register_plan`과 `register_core_access_provenance`로 등록합니다.
- **기대:** E(09:00)를 넘으므로 거절.
- **실제:** 두 단계 모두 `Ok`. C의 provenance는 `lease_seconds=3600`, `current=true`이고 C에는 임대창 기록이 없습니다. 임대창 1개, 예약 0개, intent 0개입니다.
- **영향:** 지금은 core 서명이 차단돼 있고, C를 검토 경로로 가져오려 하면 거절되며, 임대당 예약은 1개뿐이라 실제 권한은 생기지 않습니다. 하지만 "단일 고정 `[S,E)`"라는 불변식이 저장소 차원에서는 완전히 강제되지 않습니다.
- **수정 방향:**
  - 같은 요청에 임대창 기록이 있으면 legacy provenance 결합이 `[S,E)` 밖의 정책을 거절하게 합니다.
  - core 서명을 열기 전에 `cost_for_plan`과 readiness에 보존된 임대창을 필수 조건으로 넣습니다.

### F2 [Low/정보성, 검토자 재현] 형식이 틀린 계획도 시각 관측을 먼저 commit함
- **위치:** `store/access_window.rs:57`의 시각 관측이 `:95-96`의 계획 형식 검증보다 먼저 실행됩니다.
- **재현:** CLI 등록 입력에 `plan.zz_unknown=1`을 넣습니다.
- **결과:** 거절되지만 project clock이 현재 시각으로 전진합니다.
- **영향:** CLI에서는 실제 현재 시각만 기록되므로 영향이 작습니다. 라이브러리 API에서는 호출자가 준 `now`로 floor를 올려 이후 등록을 막을 수 있습니다.
- **수정 방향:** 형식 검증을 관측보다 먼저 하거나, 문서에 이 순서를 정확히 적습니다.

### F3 [정보성, 검토자 재현] legacy provenance가 검토 프로필로 승격됨
- `register_plan`과 legacy provenance로 등록한 계획이, 나중에 `register_reviewed_core_access_plan`으로 임대창을 받을 수 있습니다(`:62-100`).
- 엄격한 검증은 모두 다시 수행되므로 우회는 없습니다.
- 다만 `docs/authority-store.md`의 "legacy는 엄격한 검토 프로필 자격이 없다"는 표현과 맞지 않습니다. 문서를 정정하거나, 결합 경로에서 legacy를 거절해야 합니다.

### F4 [설계 한계, 검토자 재현, 이번 PR의 회귀 아님]
- SQL 쓰기 권한이 있는 공격자가 단조 증가 트리거를 지우고, project clock을 승인 시각으로 되돌린 뒤 트리거를 복구할 수 있습니다.
- 그러면 `current=true`가 되살아나고 재개방도 통과합니다.
- 만료를 관측한 사실이 감사 기록에 남지 않기 때문입니다(`validate_retained :390-393`).
- 서명 quota clock도 같은 모델입니다. 필요하면 관측을 지속적으로 기록하는 수단이 있어야 합니다.

### lab 테스트 공백 [Low, 정적 검토, Docker 없어 실행 미확인]
1. 원래 E에서의 만료는 "E+1에 차단"만 확인합니다. E 직전(예: E−3초) 양성 확인과 token 잔여 시간의 하한 검사가 없어서, 수명이 짧아져도 통과할 수 있습니다.
2. `bad-core-signature` 사례는 66바이트 서명이라 서명 검증이 아니라 길이 검사에서 실패합니다. 길이가 맞는 64바이트 위조 서명으로 바꿔야 합니다.
3. 거절 사례는 종료 코드와 상태 불변만 확인하고 `CORE_BUNDLE_*` 거절 사유는 확인하지 않습니다. `production-trust` 사례는 trust 로드 단계에서 먼저 거절됩니다.
4. candidate 컴파일에 독립 고정 reference가 아니라 bundle 자체의 reference를 씁니다(synthetic이라고 명시돼 있음).

## 항목별 판정
1. **계획 재합성 — 정상(검토자).** 기존 deny, association, 무관한 allow, tombstone을 빠뜨리거나 정책을 확장하거나 effect를 바꾼 반례가 모두 거절됩니다. 승인 근거만 바꿔치기하면 planner는 구조만 보지만 authority 쪽에서 `Binding`으로 거절됩니다. 검토 결과만으로는 승인·서명 권한이 생기지 않습니다(관련 테이블 0행, `signing_allowed`·`dispatch_allowed` false).
2. **고정 임대창 — 정상, F1 제외(검토자 + 직접).** 기간 축소·이동·연장(3599, 3601, +1초), E 경계(반열린 구간), envelope·delegation·workload 경계, 만료 뒤 새 호환 계획·재시도·재개방 모두 되살아나지 않습니다. legacy v1의 원래 기간 비용(3600초)도 보존됩니다.
3. **schema14 — 정상(검토자).**
   - 결합 등록이 원자적입니다. 검토·임대창·감사 INSERT에서 늦은 실패를 주입하면 전체가 롤백됩니다.
   - 출력 유실(`OUTPUT_FAILED`) 뒤 읽기로 복구할 수 있고, 정확한 재시도는 감사 기록을 늘리지 않습니다.
   - REPLACE·rowid·FK OFF·고아·변조 시도는 거절되거나 검출됩니다.
   - 실제 구버전 바이너리로 만든 v13 DB가 v14로 이관되며 rowid와 행이 보존되고, 0600 백업이 생기고, 재실행은 no-op입니다. 실패 지점 3곳에서는 원본 바이트가 그대로입니다.
   - 저장소의 populated 이관 테스트는 실제 구버전 실행이 아니라 재구성 fixture입니다.
4. **clock floor — 정상, F2·F4 제외(검토자).** 거절된 시도도 floor는 전진하고, 만료 관측 뒤 과거 시각·재개방에서 `current`가 되살아나지 않습니다. `checked_at`은 실제 관측 시각입니다. pin, 예약, job, generation은 만들어지지 않습니다.
5. **bundle과 실행기 — 정상(정적 검토 + 단위 테스트).**
   - 입력은 닫힌 codec, 16 MiB 제한, 중복 키 거절로 처리됩니다.
   - 원본 증거와 runtime 투영·journal 결합을 재계산합니다.
   - DSSE의 목적·키·tenant·target·quota·시각을 호출마다 다시 검증하고 trust 파일도 다시 읽습니다.
   - scoped proof는 callback 밖으로 저장하거나 반환하면 컴파일 오류가 나므로 유출되지 않습니다.
   - 5초 설치 예산과 2초 native 예비 시간은 기준과 같습니다.
   - candidate 관측은 `mode=ro`, `query_only`, deferred 트랜잭션을 쓰고 `total_changes==0`을 확인합니다.
   - `LabApproval`·`LabTrust`는 `synthetic_test_fixture`와 `production_authorized=false`로 분리돼 있습니다.
   - 관찰 사항:
     - 실행기가 이제 `fw_authority`의 `approval-proofs`(SQLite, openssl, webauthn)를 포함해 신뢰 코드 범위가 커졌습니다.
     - lab grant가 운영 payload type을 쓰는 것은 기존부터였습니다.
6. **격리 Linux — NOT_RUN(정적 검토만).** 만료 뒤 복구는 원래 recovery 권한만 쓰며, 임대창·기한·material이 갱신되지 않는 구조를 확인했습니다. multiport 제한(nftables 1.0.6 readback)은 README, `core-access-enforcement.md`, 보고 필드 `multiport_conntrack_set_readback_qualified:false`에 과장 없이 적혀 있습니다.
7. **CLI·API·UI — 정상.**
   - CLI: 중복·미지 필드, 오버플로, 중첩, NUL, 후행 데이터가 고정 진단으로 거절됩니다.
   - API: GET 경로 하나뿐이고, 세션·CSRF·Origin·live role·tenant를 확인합니다. 다른 tenant와 존재하지 않는 계획은 모두 409를 반환해 존재 여부를 알 수 없습니다.
   - UI: 엄격한 parser와 세션 메모리 안의 time floor가 refresh·remount·계획 전환에도 유지됩니다. 영어가 기본이고 저장된 언어 선택이 유지되며, 새 키 18개가 8개 언어에 모두 있습니다.
   - 은퇴한 계획의 과거 임대창도 조회됩니다(설계상 의도).
8. **회귀·차단 — 정상(직접).**
   - 일반 정책, rooted·project-only quota, issued·UNKNOWN·미인증 delivered, 취소, native 회귀가 `check.sh`·umask·smoke에서 모두 통과했습니다.
   - `protected_authority`는 항상 거절하고, 새 서비스 경로는 GET뿐입니다. AI 자기 승인 경로는 추가되지 않았습니다.

## 결론 구분
- **다음 개발을 막는 결함:** 없음
- **core 서명 프로필을 열기 전에 필수:** F1. legacy 경로의 임대창 강제와 비용·readiness의 임대창 요구가 필요합니다.
- **출시 전 필요:**
  - F2·F3 정리, F4(관측 기록) 판단
  - lab 테스트 공백 4건
  - 원격 CI 실행(billing 해소 후)과 Docker 격리 Linux·core-access·native 검사 실제 실행
  - 미완성 범위: 보호 signer·bootstrap·dispatch·완료 증명, Linux 운영 설치·복구, Windows WFP/callout, macOS Network Extension, 외부 감사 앵커

F1 재현 소스와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr26/`에 있습니다. 비밀값과 원시 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다(다른 작업이 쓰지 않는지 먼저 확인하세요).

```bash
for w in /tmp/nox-claude26.DgPaXF /tmp/nox-claude26p.KBo08W /tmp/nox-claude26s.8yFI4u /tmp/nox-claude26o.r2vMVG /tmp/nox-claude26n.NZnEac; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```