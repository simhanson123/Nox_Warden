# Codex Cloud 구현 작업 계획

**F-2.0 · 설계 문서를 실제 제품으로 바꾸는 작업 순서와 인수 기준**

## 1. 저장소에 넣는 방법

이 패키지는 Markdown 원본, JSON 계약, 검증 도구, Agent 지침을 모두 포함한다. 공개 저장소는 아직 생성되지 않았다. 제공된 `F_저장소_내보내기.py`는 지정한 빈 폴더에 GitHub/Codex가 인식하는 이름으로 사본을 배치한다. 원본 F_ 파일은 변경하지 않으며 Git 생성·push·클라우드 자원 생성은 하지 않는다.

```sh
python F_저장소_내보내기.py --destination ../firewall-repository
```

이 명령은 패키지 디렉터리에서 실행한다. 목적지가 없거나 비어 있어야 한다. 실행 후 root `AGENTS.md`, `README.md`, `LICENSE`, 문서/계약, `scripts/validate_spec.py`, `skills/firewall-install/SKILL.md`가 생긴다. 후원 설정은 아직 활성화하지 않는 예제로 배치한다. 사용자가 정한 이름으로 GitHub 저장소를 만든 뒤 이 내용을 올려 Codex Cloud에 연결한다.

## 2. Cloud 환경

OpenAI 공식 문서의 현재 Cloud는 저장소·도구·접근 설정을 준비하고 테스트한 환경을 Publish한 뒤 새 작업에서 사용한다. 로컬 PC의 파일·로그인·VPN이 자동으로 전달된다고 가정하지 않는다. 환경 변경은 다시 publish하고 새 작업에서 확인한다. 실제 화면이 Legacy라면 그 문서의 setup/maintenance 방식을 따른다. Legacy의 secret 수명이나 네트워크 기본값을 현재 환경의 사실로 옮기지 않는다. [현재 Cloud 환경](https://learn.chatgpt.com/docs/environments/cloud-environments), [Legacy 환경](https://learn.chatgpt.com/docs/environments/cloud-environment)

root AGENTS.md는 짧게 유지하고 상세는 분야 문서로 연결한다. [AGENTS.md 공식 안내](https://learn.chatgpt.com/docs/agent-configuration/agents-md)

M00에서 준비할 도구는 Git, Rust stable/Cargo, Node LTS/npm, Python 3와 jsonschema, SQLite 개발 환경, C/C++ build 도구다. 정확한 설치 버전·digest를 기록한다. registry 접근은 필요한 도메인만 허용하고 설치된 dependency로 offline pure tests도 실행한다. code-signing key, production cloud credentials, Sponsors/은행 자료를 개발 환경에 넣지 않는다.

최초 설계 검증은 `python scripts/validate_spec.py --root docs/specs`다. kernel/capability는 매 환경에서 확인한다. `sudo` 또는 container 시작이 된다는 사실만으로 CAP_NET_ADMIN·Windows kernel·macOS system extension 시험이 가능하다고 추정하지 않는다. 실제 OS runner가 필요하면 아래 작업을 분리하여 Cloud에서는 순수 코어·계약·UI 작업을 계속한다.

등록·내부 집행·signer 통신은 [F_12](F_12_등록_내부통신_부트스트랩_명세.md)와 F_내부통신_스키마.json을 함께 구현하며 IPC01–IPC10을 M02/M03/M05/M08의 종료 조건에 포함한다.

## 3. 작업 DAG와 종료 조건

| ID | 선행 | 결과물 및 완료 조건 | 반드시 남길 증거 |
|---|---|---|---|
| M00 | 없음 | repository scaffold, exact toolchain/lockfiles, workspace, CI 기본, task ledger. 명세 검증 재현 | 버전 목록, dependency license/SBOM baseline, design check |
| M01 | M00 | strict domain types, canonicalization, F-1.0 + 확장계약 serializer, scope/expiry/reference evaluator | C/S suite, malformed JSON·Unicode·hash 반례 |
| M02 | M01 | SQLite/PostgreSQL migrations, auth, tenant RBAC, audit/outbox/work queue, idempotency | crash/retry/isolation/migration/경쟁 suite |
| M03 | M02 | planner, immutable approval, authority quota/trust/signing, DSSE verify, worker claim | signer bypass/replay/race/approval binding suite |
| M04L | M01,M03 | Linux compiler/executor, namespace lab와 host installer | K/F + OS01–OS10 Linux |
| M04W | M01,M03 | Windows service/WFP/callout, signed test installer, driver boundary | K/F + OS01–OS10 Windows VM |
| M04M | M01,M03 | macOS app/system extension/IPC, signed qualification, crash/boot/deadline 입증 | K/F + OS01–OS10 macOS 실제 지원 기기 |
| M05 | M02,M03 | OpenAPI endpoints, core MCP6 + 감사 read tools, CLI, enrollment/probes | A/M suite, live protocol interoperability |
| M06 | M05 | React UI, graph/table/timeline, plan approval, 6언어, accessibility | U + AUD01–AUD10, browser QA |
| M07 | M02,M05 | PBOM verifier/export, retention/backup/restore, notifications, telemetry off/on/delete | evidence tamper/tenant/redaction/retention tests |
| M08 | M04L,M04W,M04M,M05 | 각 OS packaging/update/uninstall, artifact signature/provenance, platform matrix | installer interruption/reboot/coexistence report |
| M09 | M05,M08 | AWS/GCP/Azure/Hostinger/IBM/Oracle/Alibaba VM 배포 프로필, CLI·Skill, 선택 npm wrapper, WordPress 연동 경계 | F_11 CLOUD01–CLOUD12 및 provider별 report |
| M10 | M06,M07,M08,M09 | 3OS end-to-end, docs 6언어 핵심 흐름, 공개 준비/공급망/보안 검토 | F_07 전체 인수+3OS+7provider 상태표 |

M04L/W/M은 공통 계약 확정 후 병렬 가능하다. M06 UI mock 개발은 M05 완료 전 가능하나 mock 시연을 API 통합 통과로 세지 않는다. M09 cloud-native security group 쓰기와 shared hosting용 WordPress plugin은 F_11의 별도 범위·게이트를 따른다. 한 사용자가 모든 cloud계정 비용을 지불해야 하는 기본 설치 모델을 만들지 않는다.

작업은 `reports/task-ledger.json`에 ID/status/commit/test_evidence/dependencies/blocker를 기록한다. status는 planned/in_progress/verified/blocked이고 verified는 해당 테스트가 실제로 통과한 경우뿐이다. 제품 support matrix의 상태와 작업 status를 혼용하지 않는다. 새 작업은 저장소의 ledger와 증거를 읽고 이어서 수행한다.

## 4. 제품 구현 후 사용할 검증 명령 계약

아래는 M00 이후 만들어야 할 개발 인터페이스이며 **현재 패키지에 구현된 제품 명령이 아니다**. 비어 있는 스크립트로 성공을 반환하지 않는다.

| 명령 | 생성 책임 | 검증 |
|---|---|---|
| `cargo fmt --all --check` | M00 | Rust formatting |
| `cargo clippy --workspace --all-targets -- -D warnings` | M00 | 공통 코어 및 현재 OS target 정적 검사 |
| `cargo test --workspace --locked` | M01부터 | pure/domain/store/API tests. native privileged는 별도 |
| `npm ci --prefix web` | M00 | lockfile 기반 UI dependency |
| `npm run check --prefix web` | M06 | TypeScript·lint·locale parity |
| `npm test --prefix web -- --run` | M06 | UI component tests |
| `npm run build --prefix web` | M06 | 정적 production bundle |
| `python scripts/check_contracts.py` | M01 | schema·API·core compatibility·fixtures |
| `python scripts/check_locales.py` | M06 | key/placeholder/ICU parity와 hardcoded text |
| `cargo run -p fw_testlab -- qualify --backend nftables --report reports/linux.json` | M04L | 격리 Linux lab |
| `cargo run -p fw_testlab -- qualify --backend windows_wfp --report reports/windows.json` | M04W | 격리 Windows VM |
| `cargo run -p fw_testlab -- qualify --backend macos_network_extension --report reports/macos.json` | M04M | 승인된 macOS test 기기 |

native testlab는 실제 fixture를 조작하고 관측한 결과를 기록한다. OS별 동작 불가이면 exit 2 및 NOT_RUN, 시험 실패 exit 1, 전부 통과만 exit 0이다. test runner의 환경 결함과 제품 결함을 구별하되 release gate에서는 둘 다 미통과다.

## 5. CI와 릴리스

PR CI는 unprivileged format/lint/types/schema/pure/domain/API/DB/UI 검사다. GitHub-hosted Windows/macOS runner의 권한·extension 제한을 확인하지 않고 privileged suite를 넣지 않는다. 격리 ephemeral Linux/Windows VM 및 전용 Mac runner에서 native suite를 실행한다. 외부 기여 PR에 production signing secret이나 장기 cloud credentials를 제공하지 않는다.

release job은 검토된 commit/tag → matrix build → tests → SBOM/notice → artifact hash/provenance → OS signing/notarization → 설치 검수 → release manifest 생성 순서다. 현재 task에 공개 권한이 없으면 release 후보까지만 만든다. 사용자가 이미 허용한 공개 작업에는 같은 허가를 반복 요청하지 않는다.

패키지·npm·winget·Homebrew·cloud-init·Skill은 같은 release manifest와 지원 matrix를 참조한다. 어느 채널도 별도 unsigned 실행 파일을 내려받지 않는다. npm install lifecycle에서 root 방화벽 변경을 하지 않는다. CDN/registry 장애가 이미 설치된 방화벽의 집행을 멈추지 않는다.

## 6. 일괄 완료 기준

기능 문서 존재, schema pass, 데모 동영상만으로 출시 완료가 아니다. 요구 R01–R24, F_07, F_09 OS01–OS10, F_10 AUD01–AUD10, F_11의 채널·클라우드 시험이 연결되어야 한다. 3OS의 지원 버전별 실제 증거, 서명 installer, 복원·업데이트·제거, scope 격리, 선택 통계 OFF, 번역·접근성, 라이선스·notice가 모두 검수되어야 한다.

macOS strict failure behavior처럼 OS가 제공하는 보장을 확인하지 못한 항목은 숨기지 않는다. 실제 제약이 드러나면 결과·대안·사용자 영향과 필요한 범위 변경을 기록하고, 독립적으로 가능한 구현을 계속한다. 아직 미지원인 상태를 최종 완성으로 보고하지 않는다.
