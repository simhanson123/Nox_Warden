저장소 담당 검토자의 보고도 들어왔습니다. 확정 결함은 없습니다.
- F1은 양방향 순서, 만료·은퇴한 binding, alias까지 막힙니다.
- 이전 코드가 만든 충돌 schema14 DB는 원본 바이트를 그대로 둔 채 open이 `Binding`으로 거절됩니다.
- 다만 이 거절은 DB 전체에 적용되고 복구 절차가 문서에 없습니다(문서 공백, Low).

이제 `check.sh`만 기다리고 있습니다.

`check.sh`가 0으로 끝났고, 이어서 umask 테스트, workspace 빌드, focused 테스트, Python runner 테스트, smoke 11종을 차례로 실행하겠습니다.

순차 실행이 백그라운드에서 돌고 있습니다(방금 온 알림은 이미 확인한 `check.sh` 완료 알림입니다). 끝나면 한국어 최종 보고서로 정리하겠습니다.

# PR26 후속 수정 독립 통합 검토 — F1~F4와 lab 공백 보완

## 결론
- **Medium 이상 결함은 없습니다.** F1·F2·F3은 수정을 확인했습니다. F1은 제가 PR26 때 쓴 반례를 그대로 다시 실행해 직접 확인했습니다.
- 새로 확정한 사항은 모두 Low이며 lab 증거 검사기와 문서 쪽입니다.
  - D6a: 검사기가 F04 상수를 고정하지 않음(직접 재현)
  - D6b: E−8 하한 계산 때문에 정상 상태도 가끔 거절(병렬 검토자 재현)
  - 이전 코드가 만든 충돌 DB의 복구 절차가 문서에 없음
- **다음 개발을 막는 결함은 없습니다.**
- **원격 CI 미실행:** 새 PR CI(42150829408)는 billing lock 때문에 실행 전에 실패했습니다. 아래 결과는 모두 로컬 실행입니다. 결제 변경, CI 우회, 병합은 하지 않았습니다.
- 운영 signer·dispatch는 계속 차단돼 있고, AI 자기 승인 경로도 없습니다. lab, 테스트 키, 가상 인증기의 성공은 운영 자격이 아닙니다.

## 검토 대상과 환경
- **이번 기준:** `3866ceaa2b86da3ea3653da338d433a23a02b283`(이전 PR26 head, 트리 `7f349ae`)
- **대상:** `dded7e94e84ef0e59a0552e961c5c57eaaabdd81`
  - 트리가 `9108060e91b2cf9659b598e5f670f095f72f3305`로 일치합니다.
  - 단일 커밋이고, 기준의 자손입니다. 원래 PR 기준은 `a624a1e`입니다.
- **변경 범위:** 33개 파일, 2,525줄 추가, 332줄 삭제
  - SQL 001~014, `schema.sql`, specs, 기존 검토 원문은 바뀌지 않았습니다(SQL 변경 없음).
  - `pr26-claude-review.md`가 추가됐고 SHA256 `7f82e555…`이 일치합니다.
- **환경:** rustc 1.99.1, Node 22.22.0(`package.json`이 24.19.0을 지정해 EBADENGINE 경고), Python Playwright 1.62.0. 관리 Docker는 없습니다(`/var/run/docker.sock` 없음, `DOCKER_HOST` 미설정).
- **작업 폴더:**
  - 내 검토 worktree: `/tmp/nox-claude26f.lvjnYB`
  - 내 F1 재실행용: `26p`를 대상 SHA로 옮겨 사용
  - 병렬 검토자: `26g`·`26h`(저장소, 이전 코드), `26k`(native·lab, 제거됨)
  - 모두 원복했고 `git status`가 비어 있습니다. 시작 전에 실행 중인 작업이 없음을 확인한 뒤, 이전 PR26 때 제 target만 지웠습니다.

## 직접 실행한 명령과 결과

| 명령 | 종료 코드 | 실측 |
|---|---|---|
| `npm ci --prefix web` | 0 | — |
| `bash scripts/check.sh` | 0 | 아래 세부 |
| — workspace Rust | | 957 통과 / 0 실패 / 3 ignored(중첩 요약 2건 제외) |
| — 별도 취소 CLI process test | | 1 통과 |
| — 축소 기능 Rust | | 32 통과 |
| — UI | | 211 통과(파일 11개) |
| — 로케일 | | 8개 언어, 키 229개 |
| — Python 진단 | | 27 / 6 / 14 / 3 |
| `(umask 0002; cargo test -p fw_authority -p fw_authority_service)` | 0 | 541 통과 / 3 ignored(중첩 2건 제외) |
| `cargo build --locked --workspace --bins --examples` | 0 | — |
| `--test core_access_window --test core_access_admin` | 0 | 19 + 12 |
| `--lib core_access_cost_tests` | 0 | 7 |
| `--lib first_window_between_selection_and_final_snapshot` | 0 | 1 |
| `--lib window_tests` | 0 | 2 |
| `-p fw_testlab --bin fw_signed_lab_fixture reference_pin_tests` | 0 | 3 |
| `python native/linux/test_core_snapshot_runner.py` | 0 | 15 |
| `smoke_control` / `smoke_cli` / `smoke_login` | 0 / 0 / 0 | 24 / 13 / 5 |
| `smoke_passkeys` / `login_admission` / `audit` | 0 / 0 / 0 | 76 / 14 / 21 |
| `smoke_catalogue_navigation` | 0 | 11 |
| `smoke_enrollment` API / 브라우저 / authority-metadata | 0 / 0 / 0 | 23 / 25 / 41 |
| `smoke_authority_review` | 0 | 43 |
| 내 F1 반례 재실행(PR26 때와 같은 소스) | 0 | 1 통과, 아래 결과 |
| 내 D6a 검사기 프로브 | 0(1차는 모듈 경로 오류인 프로브 오류) | 아래 결과 |

- 브라우저 smoke는 Playwright와 설치된 브라우저의 빌드 번호가 달라 정식 옵션 `--browser-executable /opt/pw-browsers/chromium`을 썼습니다.
- **NOT_RUN(관리 Docker 없음):** `linux-lab.py`, `signed-linux-lab.py`, `core-access-linux-lab.py`, `smoke_native_evidence.py`
  - 호스트에서 dockerd나 iptables를 켜지 않았습니다.
  - 따라서 실제 패킷 확인, E−8 양성과 E 이후 음성, 64바이트 위조 서명 거절, reference pin 관측은 **실행 검증하지 못했고** 정적 검토와 단위 테스트로만 확인했습니다.
- **0개 실행 필터(PASS 아님):** 병렬 검토자가 확인했습니다. `--lib signing_quota_version_tests`는 0개에 일치하고, 올바른 필터는 `signing_quota::tests::version_tests`(6개)입니다.

**병렬 검토자 실행 결과(같은 SHA, 새로 작성한 반례):**
- **저장소:**
  - focused 테스트 외에 `core_access_store` 15, `core_access_provenance` 15, `version_tests` 6을 실행했습니다.
  - 이전(3866cea) 라이브러리로 **실제로 만든** 충돌 schema14 DB 3개를 시험했습니다. 저장소의 재구성 fixture가 아닙니다.
  - 두 연결 경합을 12회 돌렸습니다.
- **native·lab:**
  - Python runner 27 통과
  - `fw_testlab` 6 통과, `fw_linux_executor` 11 통과(빈 대상 1개는 0개로 PASS에서 제외)
  - 서명 검증 프로브 1개 통과

## 항목별 판정

### 1. F1 양방향 순서 — 수정
- **제 직접 재현:** 고정 임대창 `[08:00, 09:00)`이 있는 상태에서 09:10까지인 legacy 계획의 provenance 결합이 이제 `Binding`으로 거절되고, 결합 기록이 남지 않습니다. 임대창 안의 대조군은 3600초 비용, `current=true`로 정상 등록됩니다. PR26 때는 같은 반례가 받아들여졌습니다.
- **병렬 검토자(임대창 먼저 → legacy):** 다음은 모두 거절되고 모든 테이블이 바이트 단위로 그대로였습니다.
  - 이동, 앞당김, E+1, 만료 후 등록, plan id alias
  - 정확히 일치하는 구간과 내부 구간은 받아들여집니다.
- **병렬 검토자(legacy 먼저 → 임대창):** 다음은 원자적으로 거절되고 행이 하나도 쓰이지 않았습니다(`access_window.rs:352-382`).
  - 범위 밖의 만료·은퇴 binding, 일부만 범위 밖인 경우
- 요청 ID와 lease ID는 정규 소문자 UUID만 허용되므로 대소문자 alias는 불가능합니다.
- **이전 코드가 만든 충돌 DB:** 새 코드에서 `open`이 `Err(Binding)`으로 거절합니다. 원본 파일 SHA-256은 바뀌지 않았고 WAL·SHM 잔여물도 없습니다.

### 2. live 비용과 readiness — 정상(단, primitive 테스트)
- `cost_for_plan`은 새 intent를 만들 때만 호출됩니다(exact replay는 그 전에 반환). 따라서 이미 발급된 것은 다시 계산되거나 환급되지 않습니다.
- readiness는 완전한 검토와 현재 임대창을 요구합니다. 만료 후에는 `CORE_REQUEST_BINDING_UNAVAILABLE`과 `PLAN_STALE`이 표시됩니다.
- v1 예약·회계 테스트는 primitive 장부 테스트입니다. core 서명 작업의 전체 수명주기를 증명하는 것이 아니며, 테스트 스스로도 그렇게 밝힙니다.

### 3. F2 형식 오류의 clock 선관측 — 수정
- 다음 입력은 모두 quota clock 행 0개, 모든 테이블 불변으로 거절됐습니다.
  - 임대창 이동, E+1, 다른 계획의 검토, provenance 해시 불일치, revision 2, tenant 불일치, UUID가 아닌 plan id
- 정상 형식의 거절과 역사적 exact retry는 기존 floor와 `admitted_at`·`checked_at` 의미를 유지합니다.

### 4. 내부 동시성 — 정상
- 저장소의 hook 테스트(1개)를 통과했습니다.
- 병렬 검토자가 같은 요청의 다른 계획을 통해 최초 임대창이 생기는 경합을 주입했습니다. provenance 조회와 등록 모두 `Conflict`가 나고, 재시도는 만료로 `Time`입니다.
- 만료를 관측한 뒤에는 과거 시각과 재개방에서 `current`가 되살아나지 않습니다.
- 두 `AuthorityStore`를 동시에 12회 돌린 결과, 둘 다 commit된 경우는 없었습니다.

### 5. F3·F4 — 정상
- legacy 승격은 전체 결합 경로의 엄격한 검증으로만 가능하고, 자동 승격이나 이관 중 증거 생성은 없습니다.
- 문서는 F4에 대해 다음을 정확히 밝힙니다. 과장은 없습니다.
  - 보호 저장소가 전제라는 점
  - OS 계정·ACL과 외부 앵커가 미완성이라는 점
  - SQL guard와 로컬 체인이 schema 변경 권한을 가진 writer에 대한 단조성을 보장하지 않는다는 점

### 6. native 만료 — 대체로 정상, Low 2건(정적 + 함수 프로브)
- token 하한은 원래 E와 binding 시계로 독립 계산하고, token 자신의 남은 시간을 참조하지 않습니다.
- E−8 양성(신규·기존 TCP)과 E 이후 음성 단계가 있습니다.
- 실행기 상수는 기준과 같습니다(U=1, e=0, C=5, 5초 예산 안의 2초 reserve). 2초 샘플링 여유는 별도 값입니다.

### 7. 64바이트 위조 서명과 거절 사유 — 정상
- 64바이트 서명은 `from_slice`를 통과해 `verify_strict`까지 도달합니다(프로브로 확인).
- trust 로드 단계 거절과 bundle 서명 단계 거절이 구분되고, journal·세대·owned table 불변을 확인합니다.
- stderr 분류기는 선두의 정확한 GLIBC 2.39 경고 1줄만 허용합니다. 다음은 모두 거절됩니다.
  - primary 누락, 다른 code, 중복·비선두·변형 경고, CRLF, stdout 출력, exit 2
- 최초 실패의 원시 stderr는 보존되지 않았습니다. README는 같은 바이너리·이미지의 별도 환경 프로브와 이후 실제 부정 사례를 구분합니다.
- 관찰(정보성):
  - 디코드·길이·검증 실패가 모두 같은 code로 나와, lab 출력만으로는 `verify_strict` 도달을 증명할 수 없습니다(정적 근거로만 확인).
  - 일부 code는 wrapper가 없는 체인도 허용합니다.

### 8. reference pin — 정상
- 두 관측 경로가 별도의 `reference-pin.json`으로 baseline과 candidate를 다시 컴파일합니다.
- pin hash, revision, expected·submitted artifact, 두 signed capture가 서로 결합돼 있습니다.
- 문서는 driver init·apply·replay에 새 외부 pin gate를 추가했다거나 운영 reference 발급자를 인증했다고 주장하지 않습니다.
- multiport readback이 미검수라는 점도 유지합니다.
- 실행기 소스(`fw_linux_executor/src`)는 바뀌지 않았으므로 scoped proof, 호출마다 다시 하는 trust·DSSE·시각 검증, 읽기 전용 journal 관측, 제한된 복구는 그대로입니다.

### 기타 회귀 — 정상(직접)
일반 정책, rooted·project-only quota, 발급·취소·UNKNOWN, API·CLI·UI, 8개 locale이 `check.sh`·umask·smoke 11종에서 모두 통과했습니다.

## 확정 결함 (모두 Low)

### D6a [Low, 직접 재현] lab 검사기가 F04 상수와 binding 벽시계를 고정하지 않음
- **위치:**
  - `native/linux/core_access_lifecycle.py:331-390`(`original_token_lifetime_bounds`)는 U·e·C를 executor manifest에서 그대로 읽습니다.
  - 외부 검증기 `scripts/signed-linux-lab.py:25-56`은 `target==E−8`과 차감값 6을 확인하지 않습니다.
- **재현:** 검사기 함수에 구성 입력을 넣었습니다.

  | 입력 | 결과 |
  |---|---|
  | 정상 U=1, e=0, C=5 | 통과(timeout 54) |
  | remaining=1 | 거절 |
  | binding을 C=20으로 일관되게 변경 | **통과**(timeout 39) |
  | binding을 U=10으로 일관되게 변경 | **통과**(timeout 45) |
  | binding을 e=15로 일관되게 변경 | **통과**(timeout 39) |

- 병렬 검토자에 따르면, 양성 확인을 E−60에 한 보고서도 외부 검증기를 통과합니다.
- **기대:** F04의 1초 + 5초를 벗어나면 거절.
- **영향:** lab 증거의 문제입니다. 실행기 상수 자체는 바뀌지 않았고, 짧아진 token은 fail-safe입니다. 하지만 문서의 "단축된 timer 거절" 주장이 검사기 차원에서 완전하지 않습니다.
- **수정 방향:**
  - 두 검사기에서 U==1, e==0, C==5를 고정합니다.
  - 관측 벽시계와 binding의 관계를 ±1초 안으로 제한합니다.
  - 외부 검증기에서 `target_unix == E−8`과 차감값 6을 요구합니다.
  - `target_unix`가 없으면 KeyError 대신 StageFailure로 처리합니다.

### D6b [Low, 병렬 검토자 재현, fail-closed] E−8 하한 계산 때문에 정상 상태도 가끔 거절됨
- **위치:** `core_access_lifecycle.py:350`의 `minimum = T − ceil(elapsed) − 1`
- **원인:** W는 초 단위로 잘리고 M은 밀리초 단위입니다. 그래서 샘플링 지연이 W의 소수 부분보다 크면 하한이 0이 되어 "positive token observation window missed"로 거절합니다.
- **영향:** 실행당 약 1~5% 불안정성이 생깁니다(안전 쪽 실패).
- **수정 방향:** 추가 −1을 빼거나, 목표 시각을 단조 시계로 정합니다.

### 문서 공백 [Low, 병렬 검토자]
- 이전 PR26 코드로 충돌 기록을 담게 된 DB는 이제 open이 DB 전체 단위로 거절됩니다. 따라서 그 파일의 모든 tenant가 막힙니다.
- 그런데 `authority-store.md`와 `pr26-follow-up.md`에는 이 사실과 복구 절차(복원 또는 재등록)가 없습니다.

## 결론 구분
- **다음 개발을 막는 결함:** 없음
- **lab 증거를 운영 판단 근거로 쓰기 전에:** D6a(상수 고정과 E−8 검증), D6b(불안정성 제거)
- **출시 전 남은 범위:**
  - 원격 CI 실행(billing 해소 후)
  - Docker 격리 Linux·signed·core-access·native 검사 실제 실행(이번 NOT_RUN)
  - 충돌 DB 복구 절차 문서화
  - 미완성 범위: 보호 bootstrap·signer·dispatch·완료 증명, Linux 운영 설치·복구, Windows WFP/callout, macOS Network Extension, 외부 감사 앵커, nft 1.0.6 anonymous multiport readback(미검수, 계속 거절)
- scalar lab의 결과는 multiport 지원이나 운영 자격의 증명이 아닙니다.

반례와 로그는 `/tmp/claude-0/-home-user-Nox-Warden/58942fc3-f4bf-578f-a4d8-7d29d17aa411/scratchpad/pr26f/`에 있습니다. 비밀값과 인증값은 출력하지 않았습니다.

정리가 필요하면 아래 명령으로 worktree를 지울 수 있습니다(다른 작업이 쓰지 않는지 먼저 확인하세요).

```bash
for w in /tmp/nox-claude26f.lvjnYB /tmp/nox-claude26p.KBo08W /tmp/nox-claude26g.qd5VzU /tmp/nox-claude26h.c7GP2Q; do git -C /home/user/Nox_Warden worktree remove --force "$w"; done
```