# Independent review prompts

These prompts are prepared for the user's requested reviewers. Preparing them
does not mean those external models were called. The comparison baseline for the current target metadata slice is
`f400d03f0bca873d42a1af114fb4632e2357d03a` (merged PR #14). Select the actual new review branch or
commit before dispatch and attach the resulting `git rev-parse HEAD` value.
Do not infer that an old review covers subsequent changes.

The following blocks are ready to copy independently. Full prior-review
disposition and design provenance are in [review-continuity.md](review-continuity.md).

## Claude Opus 5.5: authentication, cryptography and approval boundaries

```text
Nox_Warden의 독립 보안 검토를 수행하세요. 구현·커밋·푸시·병합 없이
읽기와 격리된 테스트만 수행하세요. 먼저 AGENTS.md, docs/specs/F_00_시작안내.md,
F_01_제품_구현_기준.md의 우선순위, docs/review-continuity.md를 읽으세요.

비교 기준은 f400d03f0bca873d42a1af114fb4632e2357d03a입니다.
검토 대상으로 전달받은 새 브랜치/커밋을 독립 worktree에 체크아웃하고
git rev-parse HEAD, git diff --stat 기준..HEAD를 보고하세요.
HEAD가 기준과 같으면 새 변경이 없는 기존 코드 검토임을 명시하세요.
전체 설계는 docs/specs의 F-2.0이며, 기존 외부 리뷰는 합격 증서가 아닙니다.

집중 범위:
1. fw_target_evidence의 실제 Ed25519 domain separation, canonical bytes,
   nonce/tenant/target/SPKI/인증서/revision/시각 결합. 약한 키·변조·중복 필드 거절.
2. controller enrollment와 독립 authority pin 분리. 관리자 입력은 명시적 신뢰
   주입이며 인증서 chain을 저장소가 검증한다고 오인하지 않는지.
3. 현재 pin·철회·만료와 원래 서명의 재검증. 같은 키 인증서 갱신 후 과거
   서명을 새 revision으로 연결하거나 과거 receipt를 현재 권한으로 오인하는지.
4. 오프라인 agent의 등록된 키/CSR/인증서/CA와 challenge 결합, 새 private 출력,
   비UTF-8 인자·입력·실패 경로의 비밀 노출. 보호된 challenge 전달은 전제임을 명시.
5. 메타데이터를 native qualification/승인/dispatch 권한으로 승격하는 호출 경로가 있는지.

관련 기준: docs/target-metadata.md, docs/authority-store.md,
crates/fw_target_evidence/README.md, crates/fw_agent/README.md.
source scripts/dev-env.sh 후 cargo test --locked -p fw_target_evidence -p fw_agent
-p fw_authority를 실행하고 정확한 명령·검사 수·종료 코드를 남기세요.
소프트웨어 fixture의 실제 서명을 사용하며 가짜 verifier 성공값으로 대신하지 마세요.

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
비교 기준은 f400d03f0bca873d42a1af114fb4632e2357d03a이고,
검토 HEAD는 전달받은 새 브랜치/커밋을 체크아웃한 뒤 git rev-parse HEAD로
확정하세요. 변경 통계와 정확한 SHA를 보고하세요.

집중 범위:
1. schema5 migration1~4의 private backup·manifest·sidecar 충돌, 실패 롤백,
   이전 데이터 보존과 자동 pin/역할/권한 주입 금지.
2. pin CAS·조직 범위 키 소유권·영구 tombstone·동일 키 인증서 갱신;
   live challenge4개 상한과 current-pin 인덱스, 무한 이력의 영구 quota 거절 금지.
3. signature 검증/challenge소비/proof/receipt/head/audit 원자성,
   audit 실패·동시 exact retry·재시작·다른 tenant·altered retry.
4. 실패/만료 조회 후에도 보존되는 별도 clock fence. 시간 역행·expiry 경계,
   stale head·과거 receipt·coherent revision 변조로 현재 권한이 부활하는지.
5. CLI init-project가 namespace만 만들고 principal/role/basis를 만들지 않는지,
   stdin 대기 이후 시간 확인, stdout 실패와 이미 commit된 상태의 구분.
6. 기존 승인 quorum·SQL budget·named-set 철회·서명 Linux generation/recovery
   회귀. Docker 검사는 실제 격리 namespace에서만 실행하세요.

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
비교 기준 f400d03f0bca873d42a1af114fb4632e2357d03a와 실제 검토 브랜치의
git rev-parse HEAD, 변경 통계를 보고하세요. 이전 UI 무변경 주장을
새 커밋에 그대로 적용하지 마세요.

집중 범위:
1. docs/target-metadata.md 명령을 실제 별도 process로 실행. 독립 namespace/pin,
   challenge→enrolled agent 서명→admit→reopen→replay→revoke 경로를 검증.
2. smoke_enrollment.py --authority-metadata의 tamper/tenant/revocation 거절이
   panic이나 임의 비정상 종료를 PASS로 오인하지 않는지. 원래23/25검사는 유지되는지.
3. 관리자·agent의 non-UTF8 인자, stdin 상한, private 파일·alias·기존 파일 거절,
   고정 오류 코드·비밀 미노출과 실패 이후 복구 안내.
4. authority 기존31 브라우저 검사와 controller 패스키/CLI 회귀.
   과거 receipt와 현재 유효 authority 구분, 자동 승인 금지.
5. 영어 기본과8개 언어 키/placeholder·서명 바이트 불변, UI 변경 여부를 실제 diff로 확인.

실행: source scripts/dev-env.sh, npm ci --prefix web,
npm run check --prefix web, npm test --prefix web -- --run,
cargo build --locked -p fw_control -p fw_cli -p fw_agent -p fw_authority
-p fw_authority_service --bins --examples,
python scripts/smoke_enrollment.py --authority-metadata --report reports/target-metadata-smoke.json,
smoke_passkeys.py, smoke_authority_review.py, smoke_enrollment.py --browser.
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
