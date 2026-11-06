# Independent review prompts

The [received Claude Opus5.5 PR27 review](reviews/pr27-claude-review.md) targets
`5fc576f672c2e0671164b73a667e3452b99ea82a`, tree
`719b80f88255921711ede7b4f4da81876568f7e3`, against
`dded7e94e84ef0e59a0552e961c5c57eaaabdd81`. It identifies accepted High S-1
as the original next-development blocker, plus R-1/L1/L2 and informational findings. Read
the [follow-up contract](pr27-follow-up.md); do not request another review of
that unchanged target. Prior local PASS and attributed external results do not
validate the new correction.

Use the [complete Korean prompt](target-authority-review-prompt-ko.txt) for one
Claude Opus5.5 review of the integrated signer/origin16/target-confirmation change
on `feat/target-authority-confirmation`. Fix the actual resulting base/head/tree
in the PR completion record and conversational handoff. Preparing a prompt or
internal review is not a Claude execution. PR26/PR27 remain unmerged with
billing-blocked CI. Preserve SQL001–015, specifications and original reviews.

The protected-signing prompt and notice below are the historical PR27 request;
the review has now been received. They are not a new request for that target.

## PR27 protected-signing prompt checkpoint (historical)

> The supplied [Claude Opus5.5 PR26 follow-up review](reviews/pr26-follow-up-claude-review.md)
> is received for `dded7e94e84ef0e59a0552e961c5c57eaaabdd81`, tree
> `9108060e91b2cf9659b598e5f670f095f72f3305`, against
> `3866ceaa2b86da3ea3653da338d433a23a02b283`. It confirms F1–F3 and
> reports no development blocker. Do not request another review of either
> unchanged received PR26 target. Read [the follow-up](pr26-follow-up.md).
> The current substantial batch connects protected bootstrap/signed authority and
> independent signer boundaries and addresses D6a/D6b plus conflict recovery docs.
> Use **Claude Opus5.5 only** for one consolidated review of the actual new head.
> Fresh checks and current qualifications belong in [reports](../reports/README.md);
> prior counts remain historical. Preparing this request is not review execution.
> Next comparison base: `dded7e94e84ef0e59a0552e961c5c57eaaabdd81`.
> Original PR base: `a624a1e684a8fc0065ac4f4609101410f56c50bb`.
> Branch: `feat/protected-signing-authority`, based on open/unmerged PR26.
> Resolve the final target/tree and new PR CI separately. PR26 CI remains blocked
> before execution by billing; local results never replace remote CI success.
> The full prompt with actual new SHAs must be printed in the conversation and
> retained in the new PR. Prompt preparation/internal review is not Claude execution.
> Published SQL001–014 and original reviews/specs remain preserved; operational
> signing/dispatch remain closed. Start with [the session prompt](session-start-prompt.txt).

The current complete [Korean consolidated prompt](protected-signing-review-prompt-ko.txt)
pins comparison base `dded7e9` and resolves the new target from the final feature
commit/stacked-PR completion record. The PR and user handoff must additionally
print the actual complete head/tree; preparing this prompt is not review execution.

> Historical PR #16 prompts below. Historical reservation-integrity review prompts,
> exact base and target are in [PR #19](https://github.com/simhanson123/Nox_Warden/pull/19).
> Do not reuse the historical SHA for the current follow-up.

All three PR #15 reviews at `43146fd753ab288f8e1618f5fdead6b8b2093d3b`
against `f400d03f0bca873d42a1af114fb4632e2357d03a` have been supplied by the user;
their results and follow-up belong in review-continuity and the task ledger.
These retained prompts cover the subsequent integrated native-evidence batch,
PR #16 head `feab5c310761386d33aefb19ceb8a6f8aec1cd84`, with comparison base
`43146fd753ab288f8e1618f5fdead6b8b2093d3b`. They are not another review request
for each reliability correction. Pin and report the actual reviewed SHA;
never assume a prior review covers new code. Preparing prompts is not execution.
Print complete copyable prompts in the user conversation at review handoff.

## Claude Opus 5.5 — cryptography and evidence trust

```text
Nox_Warden의 이번 기능 묶음을 독립 보안 검토하세요.
저장소: https://github.com/simhanson123/Nox_Warden
비교 기준: 43146fd753ab288f8e1618f5fdead6b8b2093d3b
대상: feab5c310761386d33aefb19ceb8a6f8aec1cd84 (PR #16 head).
독립 worktree를 사용하고 제품 수정·커밋·푸시·병합 없이 진행하세요.
AGENTS.md, docs/review-continuity.md, docs/native-evidence.md,
docs/specs의 F00/F01 우선순위와 F03/F04/F12를 읽으세요.

집중 범위:
1. fw_native_evidence의 전체 상태·참조 재컴파일, 원래 plan.artifact_hash 결합.
   StateIR, native artifact, installation, lab capability, 장치 metadata hash를
   서로 대체하거나 caller PASS/컴파일러 digest를 검증된 사실로 오인하는지.
2. 실제 Ed25519 목적 분리·canonical bytes·nonce·tenant/target·키/revision·시각,
   compilation/metadata receipt/expected head/epoch/generation/installation 결합.
3. retained proof와 정규화된 열을 일관되게 변조하는 반례, exact retry와
   현재 유효성의 분리, 같은 키·갱신·철회로 과거 권한을 되살리는지.
4. 독립 관측 키와 transport 키의 양방향 목적 분리·영구 tombstone.
5. signed raw capture의 진위와 kernel 출처 신뢰를 혼동하는지.
   UNKNOWN/MISMATCH가 state hash, 운영 자격, 승인 또는 dispatch로 승격되는지.

source scripts/dev-env.sh
cargo test --locked -p fw_native_evidence -p fw_authority -p fw_linux_executor
실제 서명 경로를 사용하고 verifier 성공 모형으로 대신하지 마세요.
보고: 대상/기준 SHA, 확정 결함의 심각도·파일:행·최소 재현·기대/실제·영향,
실제 명령/종료/검사 수, 미재현 의심과 미실행 범위를 구분하세요.
이전 검사 수를 재사용하거나 private key·원본 인증 비밀을 출력하지 마세요.
```

## GLM 5.3 — persistence, concurrency and isolated native integration

```text
Nox_Warden의 이번 기능 묶음을 독립 저장소·동시성·native 통합 검토하세요.
저장소: https://github.com/simhanson123/Nox_Warden
비교 기준: 43146fd753ab288f8e1618f5fdead6b8b2093d3b
대상: feab5c310761386d33aefb19ceb8a6f8aec1cd84 (PR #16 head).
독립 worktree에서 제품 수정·커밋·푸시·병합 없이 진행하세요.
AGENTS.md, docs/authority-store.md, docs/native-evidence.md, reports/README.md,
원본 F03/F04/F07/F12를 읽고 실제 diff를 확인하세요.

집중 범위:
1. schema1~5→6 private backup/manifest/sidecar, 실패 롤백과 기존 자료 보존.
2. 참조/observer pin CAS·조직 범위 소유권·철회·목적 분리·동시 등록.
3. 재컴파일을 transaction 밖에서 수행한 뒤 현재 metadata/참조/plan을
   commit 시 재확인하는지. capability 플랫폼·backend가 Linux와 맞는지.
4. challenge/proof/receipt/head/audit 원자성, 감사 실패·동시 exact retry,
   같은 target의 여러 plan, 기존 head 교체·generation/epoch·altered retry.
5. 실패·만료 조회 후에도 유지되는 clock fence, 과거 signature 재검증,
   현재 상태와 역사적 receipt 구분, 일관되게 조작한 저장 projection 반례.
6. 실제 readback, TTL 연장 거절, UNKNOWN/MISMATCH의 null observed hash,
   기존 서명 집행·generation fence·제한 복구의 회귀.

source scripts/dev-env.sh
bash scripts/check.sh
(umask 0002; cargo test --locked -p fw_authority -p fw_authority_service)
python scripts/smoke_native_evidence.py --report reports/native-evidence-smoke.json
python scripts/linux-lab.py --report reports/linux-lab.json
python scripts/signed-linux-lab.py --report reports/signed-linux-lab.json

Docker 검사는 폐기 namespace/NET_ADMIN에서만 실행하세요. 호스트 방화벽을
변경하지 마세요. 실제 capture 수·패킷 수·일반 검사 수를 분리하세요.
알려진 GLIBC weak-version 경고의 좁은 분리와 임의 stderr 거절이 유지되는지,
실패/cleanup/NOT_RUN을 PASS로 오인하지 않는지도 확인하세요.
보고: SHA, 명령/종료/실측 수, 확정 결함의 위치·재현·영향, 환경 실패,
미재현 의심과 미실행 항목. 격리 lab 통과를 설치형 3OS 자격으로 확대하지 마세요.
```

## GLM 5.3 Flash — API, browser, command workflow and localization

```text
Nox_Warden의 이번 기능 묶음을 독립 API·브라우저·명령 흐름 검토하세요.
저장소: https://github.com/simhanson123/Nox_Warden
비교 기준: 43146fd753ab288f8e1618f5fdead6b8b2093d3b
대상: feab5c310761386d33aefb19ceb8a6f8aec1cd84 (PR #16 head).
독립 worktree에서 제품 수정·커밋·푸시·병합 없이 진행하세요.
AGENTS.md, docs/native-evidence.md, authority-review-service.md,
authority-review-ui.md와 reports/README.md를 읽으세요.

집중 범위:
1. fw_authority_admin의 실제 pin→compile→challenge→admit→read→revoke 흐름.
   closed stdin/크기/비UTF8/decimal revision/private 파일/시각 샘플링/오류 노출.
2. collect-evidence가 보호된 artifact/installation/challenge를 확인하고
   실제 kernel JSON을 수집하는지. caller raw dump·다른 scope·출력 덮어쓰기 거절.
3. GET /authority/v1/plans/{id}/native-evidence의 cookie+memory proof,
   정확한 Origin·tenant·현재 reviewer 자격과 bounded no-store 응답.
4. 새 화면이 원래 계획에 묶인 응답만 받고 historical/current/Match/Mismatch/
   UNKNOWN/미자격을 구별하는지. 다른 plan의 target-global head를 오인하는지.
5. 화면 만료와 wall-clock 전진→만료→역행, plan 전환 중 늦은 응답,
   refresh/restart/401에서 유효 표시나 자동 승인·서명이 생기는지.
6. 영어 기본, 저장한 언어 유지, 8개 locale 키·placeholder·keyboard 접근.
   wire 식별자와 서명 bytes는 번역하지 마세요.

source scripts/dev-env.sh
npm ci --prefix web
npm run check --prefix web
npm test --prefix web -- --run
cargo build --locked -p fw_control -p fw_cli -p fw_agent -p fw_authority -p fw_authority_service --bins --examples
npm run build --prefix web
npm run build:authority --prefix web
python scripts/smoke_authority_review.py --service-binary target/debug/fw_authority_service --fixture-binary target/debug/examples/review_fixture
python scripts/smoke_passkeys.py
python scripts/smoke_enrollment.py --authority-metadata --report reports/target-metadata-smoke.json
Docker 가능 시 python scripts/smoke_native_evidence.py도 실행하세요.

부정 검사가 panic·임의 비정상 종료를 정상 거절로 집계하지 않는지 확인하세요.
상속 ACL로 빌드 파일이 unsafe하면 첫 실패를 기록하고 산출물 권한만 정상화하세요.
제품 보안 검사는 완화하지 마세요. 비밀값·private key를 출력하지 마세요.
보고: 정확한 SHA·명령·종료·검사 수, 확정 결함의 파일:행·재현·영향,
환경 실패와 교정 전후 결과, 미재현 의심·미실행 항목을 구분하세요.
가상 인증기·locale parity를 물리 키·사람 동의·원어민·전체 접근성 검수로
확대해서 표현하지 마세요.
```
