# Nox Warden

Apache-2.0 호스트 방화벽 프로젝트입니다. 첨부된 **F-2.0 개발 명세**를 보존하고 Rust 공통 코어, 로컬 제어 API, SQLite 저장소 및 6개 언어 관리 화면을 구현했습니다.

**현재 상태: 개발용 관측 모드. 출시된 방화벽이 아니며 호스트 트래픽을 보호하지 않습니다.** 네이티브 집행이 검증되지 않은 대상에 대한 배포는 거절합니다. 실제 OS 집행과 설치 인증이 완료될 때까지 운영망 보호 용도로 사용하면 안 됩니다.

## 구현된 흐름

- 제한된 JSON 입력 → 정규화·해시 → 인증된 접근 요청 → SQLite 원자 저장·멱등성 → 감사 조회.
- 자산·서비스 카탈로그의 불변 revision, ETag/If-Match, 멱등 재시도, 조직 격리와 감사 기록. 수동 등록은 검증된 workload 신원으로 승격되지 않습니다. 서비스 생성에는 실제 등록된 대상이 필요합니다.
- 대상 등록·신원·권위가 아직 연결되지 않은 요청은 `needs_info`, 검증 작업은 `failed`로 기록합니다. 허용 또는 배포 성공으로 표시하지 않습니다.
- 순수 라이브러리: deny 우선/current allow union, 24시간 lease, 정책 합성·유한 구간 의미 비교, 승인 조건, Ed25519 DSSE, 원자 quota, durable generation journal, PBOM 검증, 기본 OFF 통계 동의.
- React 화면: 개요, 자산·서비스 등록 및 revision, 요청·상세, 정책, 대상, 감사; 영어·한국어·일본어·스페인어·중국어 간체/번체. API 오류와 빈 결과를 구분합니다.
- 읽기 CLI와 인증된 MCP 조회. 승인·신뢰 변경·네이티브 배포 MCP 도구는 제공하지 않습니다.

전체 구현 경계와 남은 작업은 [설계 및 구현 현황](docs/implementation.md), [플랫폼 상태](docs/platform-support.md), [작업 원장](reports/task-ledger.json)에 기록합니다. 원본 계약은 [docs/specs](docs/specs/F_00_시작안내.md)에 있습니다.

## 개발 실행

필요 도구: Rust **1.99.1**, Node **24.19.0**, npm **11.9.0**, Python 3 + `scripts/requirements.txt`. Cargo/npm lockfile을 사용합니다.

```sh
# 준비된 Codex cloud 이미지에서 Rust 활성화
source scripts/dev-env.sh
# 새 Linux x86_64 환경은 먼저: bash scripts/install-rust.sh
python -m pip install -r scripts/requirements.txt
cargo build --workspace --locked
npm ci --prefix web
npm run build --prefix web
cargo run -p fw_control --locked
```

서버는 `127.0.0.1:8787`에만 바인딩합니다. 생성된 `state/bootstrap-token`을 로컬 로그인 화면에 입력하면 10분 유효·1회용 토큰이 세션으로 교환됩니다. 토큰 파일은 사용자 전용 권한으로 생성됩니다. 세션은 메모리에만 존재하며 서버 재시작 시 종료됩니다. 브라우저는 토큰·세션을 localStorage에 저장하지 않습니다. 상태 디렉터리는 `FW_STATE_DIR`, 포트는 `FW_PORT`, 정적 파일 경로는 `FW_WEB_DIR`로 지정합니다.

이 로그인은 명시적인 **로컬 개발 프로필**입니다. HTTP loopback의 HttpOnly/SameSite 쿠키와 Origin/CSRF 검사를 사용하며, 원격 TLS·OIDC·WebAuthn 운영 인증을 대체하지 않습니다. 서버는 원격 바인딩 옵션을 제공하지 않습니다.

```sh
cargo run -p fw_cli -- health
# 새 서버의 bootstrap token은 브라우저 또는 CLI에서 한 번만 사용할 수 있습니다.
cargo run -p fw_cli -- login
cargo run -p fw_cli -- status
cargo run -p fw_cli -- assets
# 전체 비특권 검사
bash scripts/check.sh
# 실제 별도 프로세스와 HTTP/OpenAPI 검사 (8788 포트 사용)
cargo build -p fw_control --locked
python scripts/smoke_control.py
```

CLI 로그인은 `FW_BOOTSTRAP_FILE`(기본 `state/bootstrap-token`)을 읽어 실제 서버 세션을 발급받고, `FW_SESSION_FILE`(기본 `state/cli-session.json`)에 사용자 전용 권한 `0600`으로 원자 저장합니다. 토큰·쿠키를 명령 인자나 로그에 출력하지 않습니다. Unix의 파일 권한·경로 안전성 검증이 구현되어 있으며 Windows ACL 지원은 아직 없습니다. 자세한 사용법은 [CLI 안내](crates/fw_cli/README.md)에 있습니다.

## 검증과 출시 경계

[검증 보고서](reports/verification.json)는 명령·실제 결과를 기록합니다. 명세 검사, 단위시험, HTTP·브라우저 시험은 커널 패킷 집행 인증이 아닙니다. [전체 OS 인증](reports/qualification)은 여전히 `NOT_RUN`입니다. 별도의 [실제 Linux 격리 패킷 시험](reports/linux-lab.json)은 **패킷 40건 / 검사 53건 통과**입니다. IPv4/IPv6 TCP·UDP 허용·차단, 기존 연결과 중복 allow의 만료를 실제 nftables 커널에서 확인했으며, 이 시험에서 발견한 timeout 단위 오류도 수정했습니다. 실행 방법과 보장 범위는 [Linux lab 안내](native/linux/README.md)를 참고하세요. Windows WFP/callout와 macOS Network Extension 구현, Linux 실집행·독립 watchdog, 서명 설치 패키지, PostgreSQL/OIDC/WebAuthn 및 클라우드 배포 검수는 남아 있습니다.

후원과 통계는 활성화되지 않았습니다. 저장소 게시, 패키지 배포, 클라우드 자원 생성, 운영 방화벽 변경은 수행하지 않았습니다.
