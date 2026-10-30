# API 및 도메인 구현 명세

상태: 구현 계약 / 실제 제품 검증 전. 날짜: 2026-10-30. 기술 모듈 접두어: `fw_*`. 제품명과 코드 모듈명은 분리한다.

이 문서는 `F_확장계약_스키마.json`, `F_OpenAPI.json`, 동봉된 `F_기준자료/F_개발계약/F_계약_스키마.json`과 함께 구현한다. 기존 계약 25개 정의는 `Core_` 접두어를 붙여 복사했으며 로컬 `$ref` 이름 이외에는 바꾸지 않는다. 확장 파일의 `x-core-contract-sha256`로 원본을 고정한다. 원본의 synthetic fixture는 배포 가능한 credential이나 실제 서명 검증 증거가 아니다.

## 1. 지원 경계와 정본

하나의 제어 평면이 Linux, Windows Server, macOS에 직접 설치된 executor를 제어한다. `platform`은 `linux|windows|macos`, `enforcement_backend`는 각각 `nftables|windows_wfp|macos_network_extension`이다. macOS 실행기를 UI client나 Linux 원격제어기로 대체하지 않는다. macOS PF를 배포 제품 API로 사용하지 않는다. OS별 설치·권한·집행·시험 세부는 멀티플랫폼 명세와 집행·복구 명세를 따른다.

`lab`, `host`, `routed_gateway`는 설치/집행 모드이고 `team`은 조직 운영 프로필이다. Team에서도 실제 target은 앞의 세 모드 중 하나를 가진다. `qualification_profiles`의 `common-host-v1`은 세 OS host 기능의 버전별 검수 프로필, `linux-routed-v1`은 Linux routed 기능 검수 프로필이다. lab은 격리 시험 환경이며 기능 검증을 면제하지 않는다. 각 OS가 세 모드 모두를 지원한다고 가정하지 않는다. 필요한 family, direction, protocol, interface, binding, atomicity, expiry, read-back 특성을 target capability와 대조한다. 기능은 `supported|unsupported|unverified`로 표현하며 필수 항목이 `unverified`인 경우도 신규 쓰기를 거절한다. 실측 시험 evidence가 없는 기능을 `supported`로 표기하면 출시 결함이다.

신규 쓰기의 필수 feature는 timed_allow, persistent_deny, strict_current_union, atomic_apply, semantic_readback, writer_fencing, independent_watchdog, new_management_probe, interface_scope, independent_expiry, boot_guard, crash_fail_closed, absolute_deadline_guard다. 이 모두를 해당 프로필과 OS 조합에서 검증한다. process_binding은 선택 기능이며 요청에 필요하면 supported여야 한다. 플랫폼에 독립 만료/부팅 차단 보장이 없는데 controller 타이머만으로 timed_allow를 supported로 올리는 구현은 금지한다.

정책 의미는 보호된 관리 baseline `B`와 `union(active allow) - union(active deny)`다. 사용자 priority, 암묵적 any protocol, deny 자동삭제는 없다. 신규 allow는 최대 24시간, deny의 `review_at`은 최대 90일 이내 재검토 시각이며 자동 만료가 아니다. 삭제된 deny가 허용을 확대할 수 있으므로 삭제도 계획·승인 대상이다. 기존 연결도 현재 허용 집합을 평가한다. 일부 lease의 회수는 다른 유효 lease가 허용하는 통신까지 강제 종료한다는 뜻이 아니다.

## 2. 모듈 경계

| 모듈 | 입력 및 출력 | 금지되는 권한 |
|---|---|---|
| `fw_api` | 인증된 REST/MCP 요청, 읽기 projection | 임의 장비 명령·shell·사용자 입력 승인 상태 |
| `fw_domain` | closed 도메인 타입, 의미 검증, canonical bytes | DB·네트워크·시스템 시각에 숨은 의존 |
| `fw_registry` | 자산/서비스 revision, trusted workload binding, snapshot | 사용자 주장을 검증된 신원으로 승격 |
| `fw_planner` | baseline + 정확한 patch → candidate/차분/gates | 승인·실행 |
| `fw_authority` | 사람 승인, 위임 평가, quota reservation | target API 직접 호출 |
| `fw_signer` | 독립 재검증 후 domain-separated DSSE grant | DB approved boolean 단독 신뢰 |
| `fw_queue` | fenced claim, worker 결과 수집 | worker 결과로 승인 생략 |
| `fw_audit` | PBOM, 이벤트, topology projection | 해시 연결을 사실성 증명이라고 표현 |
| `fw_agent` / OS executor | 서명 허가, 로컬 저널, 집행, 관측·복구 | 다른 target 집행·무기한 grant 재사용 |

`fw_domain`의 결정 함수에는 명시적 `as_of`, immutable registry snapshot, target capability, baseline, authority snapshot을 전달한다. 테스트와 운영이 서로 다른 현재 시각을 읽어 결과가 달라지게 하지 않는다. 결정 결과는 PASS/FAIL/UNKNOWN과 근거를 구별한다.

## 3. 인증·권한·tenant

REST base는 `/api/v1`이다. `org_id`, `project_id`, `principal_id`는 검증한 credential 및 서버 측 project 선택 context에서 얻는다. 사용자 body의 ID로 tenant를 전환하지 않는다. 경로 ID와 참조된 모든 객체에 동일 tenant 및 프로젝트 범위 검사를 적용한다. 다른 tenant 객체는 일관되게 404다. 자신의 tenant 안에서 권한이 없는 기능은 403이며 내부 정책 내용은 응답하지 않는다.

브라우저는 Secure/HttpOnly/SameSite=Strict 서버 세션을 사용한다. unsafe method는 origin allowlist와 session-bound CSRF를 모두 검증한다. API bearer는 발급자·audience·만료·철회·현재 project capability를 검증한 access token이다. OIDC ID token, MCP client가 스스로 쓴 metadata, forwarded user header는 authority가 아니다. worker와 binding issuer에는 등록된 mTLS service identity를 사용한다. mTLS 인증 성공은 역할 부여나 payload 사실성 검증을 대신하지 않는다.

아래는 기본 역할 템플릿이며 최종 인가는 capability × tenant × resource scope × 현재 authority 상태다. owner도 무효 gate, 만료 binding, stale plan을 강제 승인할 수 없다.

| 역할 | 기본 capability 및 범위 |
|---|---|
| viewer | capabilities.read, targets.read, policies.read, topology.read; 배정 project의 비민감 요약 |
| auditor | viewer + audit.read, evidence.read, approvals.read, operations.read; 명시 허용 증적 분류 |
| operator | registry.assets/services.read/write, requests.create/read, plans.read, policies.change, deployments.create, leases.read/release, operations.read, authority.read; 배정 target |
| reviewer | plans.read, approvals.read/decide; 별도 역할 membership에 따라 network/service/security reviewer |
| owner | Lab의 위 권한 + authority.revoke, bindings.revoke, approvals.revoke; bootstrap 관리 권한은 로컬 분리 |
| workload | 자신의 requests.create/read, plans.read, deployments.create, leases.read/release, operations.read; 위임된 source·service·target·도구만 |
| worker | worker.queue.read/claim/complete 및 배정 입력 evidence.read만; approvals/deployments/authority 없음 |
| agent | 별도 privileged protocol의 자기 target 수신·보고만; 일반 사용자 API 관리 권한 없음 |

`bindings.attest`는 owner의 일반 UI 권한에도 자동 포함하지 않는다. 사전 등록된 신뢰 issuer에만 부여한다. capability 목록은 OpenAPI `x-required-capability`와 일치해야 한다. `actions`는 UX용 사전 안내이며 요청 시 현재 authority를 다시 검사한다. 일반 workload에 전체 조직 audit/topology를 자동 공개하지 않는다. 별도의 읽기 credential에 해당 capability와 자산/target 범위를 배정하면 Agent도 같은 구조화 REST 결과를 조회할 수 있다. 읽기 권한은 실행 권한을 늘리지 않는다.

## 4. 공통 HTTP 규칙

UTF-8 JSON, duplicate key 거절, unknown field 거절, NaN/Infinity 거절, 입력 65,536 bytes, 일반 응답 262,144 bytes다. 제한은 압축 해제 후 bytes에도 적용한다. null 허용은 schema에 명시된 필드뿐이다. 시간은 UTC 정수초 `YYYY-MM-DDTHH:mm:ssZ`다. wire counter는 정규 10진 문자열이며 의미 검증은 `0..18446744073709551615` 범위를 추가 확인한다.

자체 도메인 문자열은 명시된 NFC 정규화 후 JCS canonicalization을 한다. 외부 issuer/subject, WebAuthn clientDataJSON, DSSE payload, 원문 evidence는 원래 bytes를 보존한다. JCS가 NFC나 배열 정렬을 수행한다고 가정하지 않는다. uuid는 lowercase 표준 표기, CIDR은 host bits 없는 canonical 표기다. IPv4-mapped IPv6, family/protocol 불일치, 역전 또는 중첩 port range, 알 수 없는 interface identifier를 거절한다. 입력값을 보정하려면 별도 초안과 새 요청을 만든다.

모든 POST는 `Idempotency-Key: UUID`가 필수다. key scope는 `(org, project, principal, HTTP method, normalized route, key)`이고 digest는 검증·정규화한 body다. 동일 key/body는 처음 resource/operation/응답을 반환한다. 다른 body는 409 `IDEMPOTENCY_CONFLICT`다. access-request의 body `idempotency_key`는 header와 같아야 한다. 서버는 request 및 idempotency record와 outbox를 한 트랜잭션에서 저장한다. 응답을 잃은 client는 같은 key로 재시도한다. key의 raw 값은 secret이 아니지만 인증을 대체하지 않는다. 최소 30일 응답을 보관하고, 이후에도 동일 key/body의 resource 연결 tombstone은 해당 감사 보존 기간 동안 유지한다.

registry revision POST는 `If-Match: "rev-{revision}-sha256:{hex}"`가 필수다. 없음 428, 불일치 412다. 불변 plan, request, ApprovalSet은 덮어쓰지 않는다. 수정이 필요하면 새 요청/새 plan/새 승인으로 연결한다. `needs_info`에 대한 보완도 새 request이며 기존 ID를 재활용하지 않는다. UI의 로컬 draft는 서버 권한 객체가 아니다.

읽기 JSON의 envelope는 `{data, server_time, revision, actions, freshness, next_cursor}`다. 단일 객체의 cursor는 null. `revision`은 resource 또는 list snapshot의 증가 revision이다. `freshness={observed_at, stale_after_seconds, stale, source}`이고 관측이 없으면 `observed_at=null, stale=true`다. `actions` 항목은 `{action_id,allowed,reason_code}`이며 allowed=true이면 reason_code=null, false이면 비밀 없는 stable code다. 생략된 action은 허용이 아니다. wire 상태/오류 코드는 번역하지 않고 UI가 en/ko/ja/es/zh-Hans/zh-Hant 번역 key로 표시한다.

목록은 기본 50, 최대 100개를 `(created_at, id)` 오름차순으로 반환한다. audit는 `(sequence,event_id)`다. cursor는 HMAC 또는 AEAD로 tenant, principal authorization fingerprint, route, 필터, 정렬, snapshot revision, 마지막 key, 만료를 결합한다. 유효기간 15분. 이전 snapshot의 membership과 revision을 읽으므로 중간 추가/변경이 중복·누락을 만들지 않는다. 철회된 권한의 객체는 매 페이지에서 다시 검사하며 일부 누락이 생겼다는 민감 정보를 노출하지 않는다. cursor 만료는 410 `CURSOR_EXPIRED`, 조건 변경은 400이다. 페이지도 byte limit에 걸리면 더 적은 항목과 cursor를 반환하되 단일 항목이 한도를 넘으면 413이다.

오류 body는 `Problem`이다. 사용자에게 전달하는 detail에 token, 내부 경로, SQL, stack trace, 다른 tenant ID를 넣지 않는다. 400은 문법/shape, 422는 의미/미지원, 409는 현재 state 충돌, 429는 rate/quota, 503은 일시 장애 또는 안전하게 판별할 수 없는 target이다. `retryable=true`가 재승인·새 idempotency key를 허용하는 뜻은 아니다. 요청의 응답 목표는 2초이며 긴 작업은 202와 operation poll로 전환한다. poll은 5→10→20→40→60초 상한과 jitter를 사용한다. HTTP 연결 취소는 접근 회수 명령이 아니다.

## 5. registry와 WorkloadBinding

AssetRevision은 안정 asset UUID와 불변 revision으로 식별한다. 생성은 revision1, 수정은 이전 hash를 잇는 새 revision이다. 동일 project 내 이름은 case-sensitive NFC 유일. ServiceRevision의 service_id는 project 내 안정 ID다. service는 destination asset과 transport를 해석하는 catalogue이며 자체 허용 권한이 아니다. retired 자산/서비스는 신규 요청에 쓰지 않으며 과거 snapshot은 삭제하지 않는다.

수동 등록 주소는 관리자가 입력한 catalogue 주장이다. 그것만으로 workload가 그 주소를 소유했다고 인정하지 않는다. WorkloadBinding은 `{payload,dsse}`이며 payload의 canonical bytes와 DSSE payload bytes가 정확히 같아야 한다. payloadType은 `application/vnd.f.workload-binding.v1+json`, 알고리즘은 Ed25519다. 검증기는 keyid를 탐색 힌트로만 쓰고 trust registry에서 issuer·tenant·target·binding 종류·유효기간·철회를 확인한다.

binding은 principal, workload, target, 플랫폼, 자산 revision hashes, 주소, 격리 증거, 시작/만료, epoch에 결합된다. `asset_ids`와 `asset_revision_hashes`는 각각 정렬된 집합으로서 snapshot에서 ID→hash 관계가 정확히 일치해야 한다; 두 배열의 같은 index를 암묵적으로 대응시키지 않는다. 동일 주소가 공유된다면 isolation=host로 표시한다. VM/namespace/app identity를 주장하려면 해당 target executor가 그 속성을 실제 패킷/flow 인가에 바인딩할 수 있어야 한다.

Linux namespace binding에는 boot ID, namespace inode, veth ifindex, 네트워크 신원 hash가 필요하며 namespace 재생성 시 새 binding이다. Windows app identity에는 검증된 app ID hash와 service SID/token binding evidence가 필요하며 PID만으로 권한을 주지 않는다. macOS는 `macos_host`를 기본으로 하며 process identity가 필요한 요청은 capability가 입증되기 전 거절한다. 다른 OS isolation variant, 주소 재할당, 재부팅 후 옛 binding 재사용은 거절한다. binding 만료를 넘는 allow는 발급하지 않는다. 기존 core Scope의 interface는 최대15자 논리 alias다. TargetCapability.interfaces가 alias→OS native ID/identity hash를 고정한다. Windows의 긴 GUID/LUID나 macOS interface 정보를 core 필드에 잘라 넣지 않으며 현재 매핑 불일치는 stale capability로 거절한다.

binding revocation은 authority epoch와 tombstone을 먼저 원자적으로 기록하고 관련 신규 grant를 막는다. 이미 적용된 권한은 제한적 reconcile을 생성하며 verified receipt 전까지 UI에는 회수 중/unknown을 표시한다. registry 수정만으로 적용 중 rule의 scope를 바꾸지 않는다. 주소의 신원 변화처럼 보안 의미가 바뀌면 binding 철회와 새 계획을 명시적으로 수행한다.

## 6. 요청·계획과 전체 candidate

`POST /access-requests`는 기존 `Core_AccessRequest`를 그대로 받는다. backend가 인증 신원, binding, service registry, envelope × root delegation을 검증하고 요청 목적을 scope로 해석한다. AI 출력은 후보일 뿐이며 ID를 만들어 넣거나 CIDR을 넓힐 수 없다. 결정적 검증 뒤 기존 `Core_Plan`의 `change_kind=add_access_lease`를 생성한다. 이때 `requested_policies`는 새 allow patch다. 기존 deny와 다른 요청의 allow가 사라지는 target replacement로 해석해서는 안 된다.

`StateIR`는 승인된 전체 정책 프로그램을 나타낸다. 보호된 관리 baseline hash, 현재/예정 policy revision, lease association, tombstone, registry snapshot, capability와 OS/profile이 들어간다. `baseline_hash`와 `desired_state_hash`는 각각 이전/후보 StateIR의 canonical hash다. policy expiry는 절대시간으로 고정하며 흐르는 remaining timeout, counters, handles, 조회 시각은 hash에 넣지 않는다. 만료된 정책의 역사 record를 읽은 경우 runtime evaluator가 시간에 따라 비활성화하며, 정리 reconcile 자체가 과거 권한을 부활시키지 않는다.

`artifact_hash`는 절대기한 portable template와 TTL binding algorithm digest가 포함된 deterministic artifact의 hash다. target에서 적용 시각에 남은 TTL을 계산해 만든 InstallationManifest는 별도 hash/evidence다. 감소하는 TTL 때문에 candidate hash가 매초 바뀌어서는 안 된다. read-back은 실제 만료 상한·scope·revision을 확인하고 정상화하며 expiry-aware 의미 비교를 한다. 상세 집행·복구 문서가 이 비교의 정본이다.

정렬은 UUID/hash UTF-8 byte순, policy는 `(policy_id, policy_revision)`, mutation은 `policy_id`(add는 policy.policy_id), ports는 `(start,end)`, CIDR은 family/address/prefix순이다. 순서 없는 배열에 중복을 허용하지 않는다. 서로 같은 policy_id를 한 patch에서 두 번 변경하면 거절한다. 원본과 후보 policy set의 각 policy에 정확히 하나의 association이 있어야 한다. allow에는 계획 단계에서 미리 할당한 lease_id, deny에는 lease_id=null이다. association의 `authority_basis_hash`는 PolicyAuthorityBasis의 hash다. 이는 approval_requirements_hash와 envelope_hash/delegation_hash(사람 승인 정책 변경에서는 null)에 결합한 고정된 요구 근거다. 최종 ApprovalSet은 plan 승인 이후 grant/PBOM에서 연결하며 candidate 내부에 넣어 순환 hash를 만들지 않는다. plan hash는 자신의 hash/승인/서명을 제외한 plan content의 SHA-256(JCS)다. patch hash는 정렬된 정확한 operations 배열 또는 기존 core의 request patch 규칙을 따른다. generic envelope의 server_time/actions는 승인 hash에 포함하지 않는다.

NativeInstallationManifest는 exact grant/artifact/desired hash, 플랫폼·backend, capability·binding algorithm·clock evidence, epoch/generation, policy별 절대기한과 실제 설치 timeout, native payload hash를 기록한다. deny는 expires_at=null, bound_timeout_seconds=0이며 이는 무제한 allow 의미가 아니다. allow timeout은 signed 절대기한의 남은 시간 이하이고 이미 만료면 설치하지 않는다. ReadbackReport는 raw 관측 hash, normalization algorithm, expected/observed semantic hash, expiry 및 probe 증거를 결합한다. match이면 두 semantic hash가 같아야 하며 unknown은 active 근거가 될 수 없다. 이 두 객체는 PBOM evidence이며 기존 f.receipt/v1 필드를 바꾸지 않는다.

## 7. 일반 정책 변경의 별도 tagged 계약

`POST /policy-change-requests`는 `PolicyChangeRequest`를 받고 `PolicyChangePlan(change_kind=policy_change)`을 만든다. 이 경로는 operator가 사람 승인으로 요청하는 변경이며 MCP 도구로 노출하지 않는다. worker는 초안을 제출할 수 있을 뿐 operator로 가장해 요청하거나 승인할 수 없다. 보호된 `B` 교체는 이 경로에서 거절한다. B 변경은 observe-only/OOB 유지보수와 새 등록 기준선 절차다.

| op | 반드시 성립해야 하는 조건 | 허용 의미 |
|---|---|---|
| add_deny | 신규 policy_id, revision1, action=deny, review interval≤90일 | deny 추가; 영향·관리 경로 시험 필요 |
| replace_policy | 기존 ID/hash/revision 정확 일치, 새 revision=old+1, action 동일 | deny scope/검토시각 수정 또는 기존 allow 축소 |
| remove_policy | 기존 ID/hash/revision 정확 일치 | deny 제거는 허용 확대 가능; allow 제거는 해당 권한 축소 |

allow 교체는 기존 scope의 부분집합, 기존 not_before 이상, 기존 expires_at 이하, 동일 lease·owner·tenant·target만 허용한다. source/destination/프로토콜 의미상 확대 또는 lease 기간 연장은 거절하고 새 access-request를 요구한다. 이를 통해 general grant가 신규 allow quota/위임 검증을 우회하지 못하게 한다. action 전환, 동일 ID 재사용, 삭제 뒤 revision 초기화는 금지한다. tombstone이 있는 policy ID를 새 권한으로 재생성하지 않는다.

planner는 정확한 baseline에 operations를 적용하고 전체 before/after 영역 차분을 계산한다. `effect_summary`의 relation은 equivalent/restricting/expanding/mixed/unknown이다. deny를 삭제했다는 문법만으로 전체 변화 크기를 추측하지 않는다. `complete=false`나 relation=unknown, 필수 gate UNKNOWN/FAIL은 승인 인원과 관계없이 dispatch를 막는다. capability/baseline/identity/schema/scope/quota/semantic/expiry gate는 중복 없이 모두 required=true, PASS여야 한다. 정책 변경의 quota gate는 신규 lease 생성 없음과 target dispatch capacity를 검증한다.

candidate_state_ref의 object_hash는 desired_state_hash와 같아야 하고 JSON 전체가 StateIR에 맞아야 한다. 정책 수 최대4096, patch 최대256, artifact 최대16MiB이며 target이 더 작은 한도를 선언하면 그 한도가 우선한다. get_plan은 계획/patch 전체를 256KiB 내 반환한다. 전체 후보가 크면 evidence content의 bounded byte ranges로 조회·검증하고 UI는 전체 검토가 완료됐음을 확인한다. 화면에 표시한 일부 patch만으로 전체 candidate 검토를 했다고 표시하지 않는다. 접근 core plan은 바꾸지 않으며 backend의 plan→candidate evidence 관계로 동일한 전체 검토 자료를 제공한다.

general grant는 `f.policy-change-grant/v1`이며 payloadType=`application/vnd.f.policy-change-grant.v1+json`이다. core grant의 payloadType과 혼용하지 않는다. signer는 exact plan/approval/candidate/artifact/baseline/epoch/generation/dispatch reservation을 다시 검증한다. `not_after-issued_at≤300s`, confirm timeout60초, absolute confirm cap, 제한된 rollback authority를 적용한다. 신규 deny는 실패 후 기본 rollback에서도 유지하는 `preserve-current-restrictions` projection이 기본이다. raw 이전 ruleset 복원으로 철회·만료·새 deny를 되돌리지 않는다.

## 8. ApprovalSet과 WebAuthn

Lab은 owner1명, Team 일반은 서로 다른 network reviewer + service 또는 security reviewer 2명, 고위험은 network+service+security 3명이다. Team은 작성자/initiator를 독립 승인 인원으로 세지 않는다. Lab의 자기 승인은 명시적으로 약한 프로필이며 Team 독립성으로 홍보하지 않는다. deny 제거/축소, critical 자산 영향, 관리 경로 인접 변화는 고위험이다. risk를 LLM 점수 하나로 낮추지 않는다.

`POST /approvals/challenges`는 exact PlanRef, decision, 역할을 받고 5분 single-use challenge를 생성한다. nonce는 CSPRNG 32bytes 이상이다. challenge payload에는 서버 생성 challenge_id, principal/tenant, plan kind/id/hash, requirements hash, decision, role, RP ID, origin, expiry가 결합된다. 사용자에게 plan_hash 및 before/after 변화·만료·복구 범위를 보여준다. WebAuthn challenge bytes는 이 canonical payload의 domain-separated SHA-256이다.

`POST /approvals/assertions`는 credential_id/authenticator_data/client_data_json/signature를 받아 RP/origin/challenge/type/user presence/user verification/credential ownership/revocation을 검증한다. 인증 library의 counter/backup-credential 정책을 사용하고 counter 증가만을 유일한 복제 방지 증거로 삼지 않는다. challenge 소비와 HumanApproval 생성은 한 트랜잭션이다. raw proof는 제한 evidence store에 보존한다. 실패한 assertion은 challenge를 성공으로 소비하지 않고 rate limit와 감사 이벤트를 남긴다.

`HumanApproval`은 요청된 approved flag가 아니라 검증 결과다. ApprovalSet은 불변이며 사람형과 위임형 tagged union이다. 사람형은 동일 plan/requirements, 유효한 실제 역할, 필요한 독립 인원, 승인 decision만 포함한다. 반대 decision은 별도 기록되고 해결 전 승인집합을 만들지 않는다. `valid_until`은 각 approval/역할/계획 유효기간의 최소다. set의 생성 후 역할/credential/승인이 철회되면 set hash는 유지하되 authority에서 stale로 판정한다.

위임형은 root delegation/envelope/binding/principal/evaluation/quota preview hash를 backend가 생성한다. client가 제출하는 delegated=true는 없다. core access 요청에만 위임형을 허용하고 general policy_change에는 사람형을 요구한다. quota preview는 reservation이 아니며 실제 발급 시 원자 재검사한다. API `approval_state=approved|delegated`는 approval_set_hash가 non-null이어야 한다. approval_required/stale은 null이다. signer는 원본 proof와 현재 authority를 독립 확인하며 DB boolean에 의존하지 않는다.

`GET /plans/{id}/approvals`는 읽기 전용 alias다. 그 경로의 쓰기는 405. 승인 생성은 challenges/assertions로만 통일한다. 승인 철회는 `/approval-sets/{id}/revocations`로 authority 차단과 관련 작업 reconcile을 시작한다. 기존 네트워크 회수가 확인됐다는 뜻은 아니다.

## 9. root authority 운영

core-v1은 단일 root delegation이며 child delegation을 지원하지 않는다. AccessEnvelope는 최대 네트워크 영역, Delegation은 누가 어떤 binding/service/tool/기간/예산으로 요청할 수 있는지다. 두 객체와 신원/registry/binding/target capability의 교집합만 허용한다. 예약·grant가 envelope, delegation, binding의 expiry를 넘지 않도록 별도 검사한다. grant의 not_after는 실행 시작 창으로서 allow의 최종 expiry와 같은 뜻이 아니다.

초기 root 생성/확대는 인터넷 공개 REST에서 임의 JSON을 받아 즉시 적용하지 않는다. 로컬 관리 절차는 (1) owner가 core Envelope/Delegation과 trust keys를 포함한 bootstrap manifest 준비, (2) 검증기가 scope/time/issuer/tool/quota와 정확한 hashes를 출력, (3) owner WebAuthn exact manifest 승인, (4) 독립 signer가 authority manifest 서명, (5) controller가 새 authority epoch와 immutable records를 한 트랜잭션에 import한다. 승인 후 bytes가 바뀌면 처음부터 반복한다. 이 절차의 CLI/설치 정본은 배포 명세이며 API는 읽기·철회만 제공한다. Team 동적 다단계 governance는 별도 후속 profile로 남긴다. root 확대를 current record UPDATE로 구현하면 안 된다.

## 10. worker queue와 fencing

work item은 controller가 인증된 업무에서 생성한다. 입력은 allowlisted store의 content hash 참조만 주며 임의 URL fetch·비밀 파일·target credential을 주지 않는다. 종류는 interpret_request/explain_plan/investigate_event/draft_policy_change다. `execution_policy_hash`는 허용 모델/네트워크/도구/출력 종류/예산을 고정한다. 모델 공급자 설정은 별도 integration 관리 기능이다.

claim은 queue row를 원자 점유하고 claim_generation을 증가시킨다. 무작위 claim_token은 최소32bytes이며 DB에는 digest만 저장한다. lease는 15분, heartbeat는 현재 claim 소유자만 연장하며 work deadline을 넘기지 않는다. client가 보내는 시각은 권한 시계가 아니다. 재점유는 lease 만료를 확인하고 generation을 증가시켜 옛 worker를 fence한다. 최대3회 시도 후 dead_letter다. 재시도는 새 work item을 만들고 원인 관계를 남긴다.

complete는 `(item,worker identity,generation,token,input_hash,current lease)`가 모두 일치해야 한다. 최종 결과와 completion receipt/outbox를 한 트랜잭션에 저장한다. 동일 claim/result의 재전송은 같은 receipt, 다른 결과는409다. 만료·재점유 뒤 늦은 결과는409 CLAIM_STALE이며 모델 결과가 더 좋아도 권한이 되살아나지 않는다. heartbeat/complete/abandon은 동일 row lock 순서를 사용한다.

WorkerResult는 access_proposal/policy_change_proposal/explanation이다. `max_output_bytes=65536`; evidence는 할당된 입력 또는 해당 worker가 생성하도록 허용된 객체에 한정한다. `model_id`는 보고값이며 provider 응답 검증 없이는 사실로 표시하지 않는다. result_hash는 정확한 result canonical bytes다. `candidate_request_id`는 격리된 초안 ID이며 자동 승인/배포 ID가 아니다. 서버가 최초 workload principal/binding/tenant를 보존해 결정적 validation으로 넘기거나 operator의 명시 제출을 기다린다. worker의 principal이 requester/approver로 대체되지 않는다. `deployment_authorized`는 항상 false다.

## 11. PBOM·감사·topology

PBOM은 request→registry/binding→plan→validation→approval/authority/quota→grant→installation→receipt→revocation/recovery의 hash graph다. `EvidenceRef`의 store_id는 설정된 저장소 ID이며 URL/경로로 해석하지 않는다. object hash 소지만으로 접근을 허용하지 않는다. content_ref.object_hash=content_hash, size와 media type은 실제 객체와 일치해야 한다. duplicate node ID, dangling edge, DAG cycle, tenant 교차 참조를 거절한다. 입력 증거 원문은 기본 수집하지 않으며 필요한 제한 자료만 별도 분류/보존한다.

PBOMManifest는 DSSE/Ed25519로 서명하고 payloadType=`application/vnd.f.pbom-manifest.v1+json`이다. node 정렬은 node_id, edge 정렬은 `(from_id,to_id,relation)`이다. Merkle leaf는 `SHA256(0x00 || JCS(node))`, internal은 `SHA256(0x01 || left32 || right32)`이며 홀수 마지막은 다음 층으로 그대로 올린다. 빈 노드 집합은 허용하지 않는다. merkle_root는 node content 무결성을, 서명 payload는 edges와 metadata까지 결합한다. complete일 때 missing_hashes는 빈 배열이고 모든 필수 단계 evidence를 접근 가능한 내부 저장소에서 검증한 상태여야 한다. 일부 누락은 partial+목록으로 표시하며 실패한 장비 배포를 complete 성공으로 둔갑시키지 않는다.

한 manifest는 노드512/edge2048이 상한이다. 초과하면 operation 단위 child manifest를 생성하고 signed checkpoint node로 연결한다. 일반 조회 응답 한도는 여전히256KiB다. evidence raw content는 16MiB 이하, 한 번에256KiB 이하의 명시적 단일 byte range만 반환한다. exact bytes를 재조립하고 전체 content hash를 검증한 후 schema/signature 검증을 한다. 206 slice를 완전한 서명 객체처럼 파싱하면 안 된다. HTML을 실행 가능한 origin content로 제공하지 않으며 attachment/octet-stream으로 전달한다.

AuditEvent는 전체 과정의 immutable event와 sequence/previous_event_hash를 연결한다. event_hash는 자신의 event_hash를 제외한 canonical event의 hash다. 인증 실패, 거절, quota 부족, UNKNOWN, rollback 실패도 기록한다. actor를 알 수 없으면 null이며 로그인 입력값을 검증된 actor ID로 쓰지 않는다. 운영 trace_id와 비밀 없는 reason code로 사건을 연결하되 raw token/prompt/개인정보를 기본 기록하지 않는다. Team은 독립 checkpoint 저장소와 signing key를 사용한다. 관리자 DB 수정까지 예방했다고 해시 체인만으로 주장하지 않는다.

`GET /audit/events`, `/operations/{id}/timeline`은 구조화 단계 기록을 제공한다. `after_sequence`는 첫 페이지에만 사용하며 cursor와 동시 사용하지 않는다. target_id/event_type 필터는 cursor에 결합한다. `GET /topology`는 허용된 principal/workload/asset/service/target 노드와 bound_to/routed_via/requests/allows/denies edge를 반환한다. edge에 desired/observed/stale/unknown을 구분하고 실제 통신 관측 없는 allow를 연결 성공으로 표시하지 않는다. 노드256/edge512 또는 응답 bytes 상한 초과 시 RESULT_TOO_LARGE로 narrower target filter를 요구한다. incomplete 그래프를 complete=true로 내보내지 않는다. tenant 경계를 넘는 숨은 노드의 이름이나 개수를 누출하지 않는다.

## 12. 상태와 완료 조건

| 객체 | 핵심 전이 | 완료 근거 |
|---|---|---|
| Request | submitted→validating→ready/needs_info/rejected/cancelled | ready는 계획 준비만 |
| Plan | immutable content + approval state | 승인 이후 변경은 새 plan |
| Validate operation | queued→running→succeeded/failed | succeeded에 PlanRef 필수 |
| Deploy operation | queued→running→active/unknown/failed/partial | active에 검증된 active receipt 필수 |
| Release operation | queued→running→revoked/unknown/failed | revoked에 확인된 restrictive receipt 필수 |
| Authority revoke operation | queued→running→revoked/unknown/failed | revoked는 authority 원장 반영, 기존 flow 차단 완료와 별개 |
| Lease | scheduled/pending→active→release_pending→revoked/expired/unknown | expiry와 관측 시각 분리 |
| Target | observe_only→ready/applying→active/unknown/degraded/quarantined | 제어 DB 값만으로 actual active 선언 금지 |

`deploy+succeeded`, `deploy+active+unknown receipt`, `release+revoked+null evidence`, `validate+active`는 거절한다. 네트워크 결과가 불명확하면 UNKNOWN을 유지하고 새 권한 확대와 예약 반환을 중단한다. raw 장비 조회와 서명된 결정/영수증을 보존하여 reconciliation으로 판별한다. 취소는 아직 dispatch되지 않은 작업만 취소할 수 있으며 이미 발급·전달한 grant를 단순 DB cancelled로 회수했다고 표시하지 않는다.

## 13. 계약 완성도와 필수 구현 시험

schema는 형태와 일부 tagged 상태만 검증한다. cross-reference, 날짜 비교, CIDR 포함관계, IP 소유, signature authenticity, 역할 독립성, complete candidate 합성, DB 원자성, OS 집행은 운영 구현과 별도 시험이 필요하다. `additionalProperties:false`를 authorization이라고 오인하지 않는다.

최소 contract 시험은 core snapshot 무변경, 모든 `$ref` local 해소, OpenAPI operationId 유일성, unknown field 거절, 성공/unknown 혼합 거절, deny op에 allow 거절, 외부 issuer NFC 변경 거절, stale approval, 재사용 challenge, quota 동시 경합, worker fencing, cross-tenant ID/evidence/cursor 공격, full candidate에서 기존 deny 보존, allow 확대의 general route 우회 차단, 세 OS 미지원 capability admission 거절이다. 소스·schema·문서·정상/반례 fixture를 동일 변경에서 갱신한다. 제품 공개 지원은 OS별 집행·복구 시험 결과와 일치해야 한다.

## 14. 외부 규격 근거

- JSON Schema 2020-12: https://json-schema.org/draft/2020-12
- OpenAPI 3.1: https://spec.openapis.org/oas/v3.1.0
- JCS: https://www.rfc-editor.org/rfc/rfc8785
- DSSE protocol: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- WebAuthn: https://www.w3.org/TR/webauthn-3/

이 링크는 구현 시 해당 규격을 고정·확인하기 위한 근거이며 현재 파일이 규격 구현 또는 OS 안전성을 인증한다는 뜻이 아니다.
