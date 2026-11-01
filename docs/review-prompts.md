# Independent review prompts

These prompts are prepared for the user's requested reviewers. Preparing them
does not mean those external models were called. The recovered baseline is
`d5cb339a8fa4a63d0c1cebad7a3609ed932798ce`; its tree equals the prior PR #13 head
`f626e04051d32aa268699dc8b6fbfccb4c8950c4`. Select the actual new review branch or
commit before dispatch and attach the resulting `git rev-parse HEAD` value.
Do not infer that an old review covers subsequent changes.

The following blocks are ready to copy independently. Full prior-review
disposition and design provenance are in [review-continuity.md](review-continuity.md).

## Claude Opus 5.5: authentication, cryptography and approval boundaries

```text
Nox_Warden의 독립 보안 검토를 수행하세요. 구현·커밋·푸시·병합 없이
읽기와 격리된 테스트만 수행하세요. 먼저 AGENTS.md, docs/specs/F_00_시작안내.md,
F_01_제품_구현_기준.md의 우선순위, docs/review-continuity.md를 읽으세요.

비교 기준은 d5cb339a8fa4a63d0c1cebad7a3609ed932798ce입니다.
검토 대상으로 전달받은 새 브랜치/커밋을 독립 worktree에 체크아웃하고
git rev-parse HEAD, git diff --stat 기준..HEAD를 보고하세요.
HEAD가 기준과 같으면 새 변경이 없는 기존 코드 검토임을 명시하세요.
전체 설계는 docs/specs의 F-2.0이며, 기존 외부 리뷰는 합격 증서가 아닙니다.

집중 범위:
1. controller 로그인과 authority 승인 신뢰 분리. 초기 소유자 등록,
   bootstrap 영구 차단, pending/verified/revoked 상태와 소유자 키 분실 경계.
2. BrowserPasskey/Cli 세션의 서버 소유 provenance, fresh UV 요구,
   빌린 등록 응답·재전송·철회·로그아웃·세션 교체를 통한 권한 확대 여부.
3. WebAuthn의 RP/origin/challenge/UP/UV/counter와 tenant/principal/plan/
   requirements/decision/role/time 결합. 검증된 Reject를 Approve로 오인하는지.
4. 새 익명 CLI 티켓 변경이 있다면 nonce/키 분리, 변조·잘린 입력·크기 상한,
   재시작·만료·동시 요청·일회 소비·지속 저장 실패 시의 원자성,
   terminal code/poll secret이 브라우저·URL·로그로 노출되지 않는지.
5. 승인 집합과 보존된 증거의 현재 유효성 재검증. 저장된 과거 영수증을
   새 서명 권한으로 재사용하거나 과거 승인만으로 grant를 만들 수 있는지.

관련 기준: docs/passkey-login.md, policy-approval-proofs.md, authority-store.md,
authority-review-service.md 및 해당 crates의 실제 코드와 회귀 테스트.
기존 실제 P-256 서명 테스트와 저장소 자체 브라우저 smoke를 우선 사용하고,
테스트용 성공 객체나 가짜 verifier만으로 암호 경계가 검증됐다고 쓰지 마세요.
source scripts/dev-env.sh 후 관련 fw_control/fw_webauthn/fw_authority/
fw_authority_service 테스트를 실행하고 정확한 명령·검사 수·종료 코드를 남기세요.

보고: 대상/기준 SHA, 확정 결함(심각도·파일:행·최소 재현·기대/실제·영향),
미재현 의심, 설계상 잔여 작업, 실제 실행 및 미실행 검사를 분리하세요.
기존 테스트 수를 재사용하지 마세요. 비밀값·원본 assertions는 출력하지 말고,
가상 인증기 결과를 물리 키·사람의 동의·OS 격리 인증으로 확대하지 마세요.
```

## GLM 5.3: storage, concurrency and isolated Linux execution

```text
Nox_Warden의 독립 저장소·동시성·격리 Linux 검토를 수행하세요.
소스 수정·커밋·푸시·병합 없이 독립 worktree에서 진행하세요.
AGENTS.md, docs/specs/F_00_시작안내.md, F_01_제품_구현_기준.md,
docs/review-continuity.md와 해당 F_03/F_04/F_07/F_08을 읽으세요.
비교 기준은 d5cb339a8fa4a63d0c1cebad7a3609ed932798ce이고,
검토 HEAD는 전달받은 새 브랜치/커밋을 체크아웃한 뒤 git rev-parse HEAD로
확정하세요. 변경 통계와 정확한 SHA를 보고하세요.

집중 범위:
1. 승인 후보의 현재 자격 필터·동일 인간/역할 중복 제거·64후보 상한.
   SQL budget 소진/외부 interrupt/panic에서 handler 정리와 전체 트랜잭션 롤백.
2. proof/counter/revision/decision/set/head/receipt/audit 원자성,
   exact retry·충돌·철회·시간 역행·다중 연결·재시작.
3. named-set 철회가 다른 현재 head를 무효화하지 않는지, 철회된 선택을
   조용히 다시 발급하는지. 현재 집합 조회를 signing reservation으로 오인하는지.
4. 새 증거·스키마 migration이 있다면 기존 행 보존, canonical/hash 정합,
   private backup/manifest/sidecar 충돌, Unicode 부모 경로, 권한·symlink,
   실패 후 원본 불변과 재시도 계약. fixture chmod로 제품 검사를 완화하지 마세요.
5. 새 CLI 저장 변경이 있다면 익명 요청만으로 DB가 무한 증가하는지,
   검증된 승인과 소비의 동시성·감사 실패·만료 시 재사용 경계.
6. Linux 서명 집행의 generation fence, 원래 만료 시각, 재시도 시 timeout
   연장 방지, 종료된 부모/남은 writer/제한 복구와 실제 패킷 readback.

source scripts/dev-env.sh 후 bash scripts/check.sh 및
umask 0002 환경의 cargo test --locked -p fw_authority -p fw_authority_service를
실행하세요. Docker를 사용할 수 있으면 저장소의 linux-lab.py와
signed-linux-lab.py를 폐기 가능한 namespace 안에서만 실행하세요.
개발 호스트·에이전트 제어 연결의 방화벽을 변경하지 마세요.
실행 요건이 없으면 미실행으로 기록하고 mock을 커널 PASS로 표시하지 마세요.

보고에는 정확한 명령/종료/검사 수, 실제 패킷 수를 따로 적으세요.
확정 결함은 심각도·파일:행·재현·기대/실제·보안 영향을 포함하고,
환경 실패와 미재현 의심, 문서화된 미완료를 구분하세요.
이전 외부 프로브 로그가 없으면 재실행했다고 주장하지 마세요.
Docker lab 통과는 설치형 호스트·hung-owner watchdog·Windows/macOS
인증이 아니며, 예약 보존 테스트는 retention cleanup 구현이 아닙니다.
```

## GLM 5.3 Flash: browser, CLI, diagnostics and localization

```text
Nox_Warden의 독립 브라우저·CLI·시작 진단·다국어 검토를 수행하세요.
소스 수정·커밋·푸시·병합 없이 독립 worktree에서 진행하세요.
AGENTS.md, docs/specs/F_00_시작안내.md, F_01_제품_구현_기준.md,
docs/review-continuity.md와 docs/passkey-login.md, authority-review-ui.md,
authority-review-service.md를 읽으세요.
비교 기준 d5cb339a8fa4a63d0c1cebad7a3609ed932798ce와 실제 검토 브랜치의
git rev-parse HEAD, 변경 통계를 보고하세요. 이전 UI 무변경 주장을
새 커밋에 그대로 적용하지 마세요.

집중 범위:
1. 첫 방문은 한국어 브라우저에서도 영어. 명시적으로 저장한 지원 언어는 유지.
   en/ko/ja/es/de/fr/zh-Hans/zh-Hant의 키·placeholder 일치와 키보드 사용.
   wire ID, 역할 값, hash, 서명 대상 바이트가 번역되지 않는지.
2. bootstrap 등록→패스키 로그인→CLI handoff→로그아웃/철회/재시작.
   terminal code를 사용자가 직접 입력하며 브라우저가 정답을 받지 않는지.
   CLI 세션의 일반 읽기/쓰기는 유지하면서 키 관리·다른 터미널 승인은 거절하는지.
3. 새 익명 CLI admission 흐름이 있다면 대량 생성 후 정상 로그인 가능 여부,
   만료·잘못된 코드·손상 티켓·중복 교환·연결 중단과 사용자 오류 안내.
4. authority 화면의 명시적 동의, fresh assertion, 역사적 receipt와 현재
   ApprovalSet 구분, signed rejection·stale·만료·재시작 후 자동 승인 금지.
5. 고정 stage/code 시작 진단과 catalogue failure_stage/failure_category가
   경로·키·비밀값 없이 실제 실패 원인을 가리키는지.

실행: source scripts/dev-env.sh, npm ci --prefix web,
npm run check --prefix web, npm test --prefix web -- --run,
두 UI 빌드, 문서의 Rust binaries/examples 빌드, startup/diagnostic 테스트,
smoke_passkeys.py, smoke_login_admission.py, smoke_catalogue_navigation.py,
smoke_authority_review.py, smoke_enrollment.py --browser.
정확한 옵션과 설치 요건은 reports/README.md의 현재 명령을 사용하세요.
실제 Chromium CDP 가상 CTAP2를 쓰고 HTTP 동작을 UI 모형으로 대신하지 마세요.

authority UI가 상속 ACL 때문에 0646 등 unsafe 모드이면 첫 실패 증거와
stage를 먼저 기록하세요. 폐기 worktree의 빌드 산출물 권한을 문서대로
정상화한 후 재실행할 수 있지만 제품 권한 검사 자체를 완화하지 마세요.
catalogue flake가 재현되지 않으면 원인을 해결했다고 단정하지 마세요.

보고: SHA, 명령·종료·실제 검사 수, 확정 결함의 심각도/파일:행/재현/영향,
환경 실패와 교정 전후 결과, 미재현 의심, 미실행 검사를 구분하세요.
실물 보안키·사람의 동의·원어민 번역·전체 접근성 검수가 완료됐다고
가상 인증기나 locale parity만으로 주장하지 마세요. 비밀값은 출력하지 마세요.
```
