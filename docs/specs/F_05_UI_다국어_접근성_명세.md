# UI·다국어·접근성 구현 명세

판본: F-2.0 · 2026-10-30 · 상태: 구현 계약, 런타임 구현 완료 표시 아님

이 문서는 Codex Cloud에서 구현할 화면·상호작용·번역·접근성의 인수 기준이다. 기존 최종 설계의 정책·승인·실제 관측 의미를 보존한다. 사용자 추가 요구에 따라 제어 서비스와 UI 제공은 Linux·Windows Server·macOS를 대상으로 하고, 각 OS의 실제 집행 기능은 교차 플랫폼 명세의 backend별 capability와 시험 결과를 따른다. Linux용 nftables 설명을 다른 OS의 실제 지원 증거로 대체하지 않는다. 프로젝트의 공개 이름은 확정 전이며 특정 후보명을 UI 브랜드로 굳히지 않는다.

## 1. 정본과 구현 경계

- API의 wire schema, capability, authorization, 승인 challenge는 API·도메인 명세가 정본이다. 이 문서의 ViewModel은 REST 응답을 화면에 투영하는 계약이며 MCP 결과 schema를 변경하지 않는다.
- `plan_hash`와 canonical protocol identifier는 영어 ASCII 계약을 그대로 사용한다. 번역된 문장·색상·위험 점수는 권한·승인·집행의 입력이 아니다.
- `operation.succeeded`, `target.active`, `lease.active`를 별개의 정보로 보여준다. 요청 접수·검증 완료를 통신 활성화로 표시하지 않는다.
- 다국어는 `en`, `ko`, `ja`, `es`, `zh-Hans`, `zh-Hant` 여섯 locale을 정식 지원 목표로 한다. 동봉한 `F_기본문구.json`은 40개 핵심 문구의 번역 초안이며 전체 UI·문서 번역 완료나 원어민 보안 검수 완료를 뜻하지 않는다.
- AI, GitHub 계정, 개발자 서버 로그인, telemetry, 후원은 로컬 UI·정책 집행의 선행 조건이 아니다. Team의 조직 인증과 개발자의 홍보용 등록을 혼동하지 않는다.

## 2. 프런트엔드와 배포

1. `web/`에 TypeScript strict·React 정적 앱을 만든다. Node는 잠근 버전의 개발·빌드 도구로만 사용한다. 운영 서버는 Rust 서비스가 정적 자산과 `/api/v1`을 제공하며 Node 서버·SSR·외부 CDN을 요구하지 않는다.
2. JS/CSS/번역 catalog는 release manifest의 content hash로 고정한다. hash가 붙은 자산은 immutable cache, HTML·bootstrap·인증 응답은 `no-store`다. API 응답을 브라우저의 영속 cache에 저장하지 않는다. service worker는 사용하지 않는다.
3. React 텍스트 렌더링을 사용하고 사용자 사유·asset 이름·AI 설명·로그를 HTML로 해석하지 않는다. 원격 markdown 이미지·iframe·외부 script는 금지한다. 증거 원문은 길이 제한·제어문자 표시를 적용한 텍스트로만 표시한다.
4. CSP는 기본 `default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`이며 inline script·`unsafe-eval`을 허용하지 않는다. 개발 환경의 별도 CSP를 배포물에 포함하지 않는다. 조직 SSO 이동은 검증된 인증 경로를 통해 수행한다.
5. 세션은 API 명세의 HttpOnly·Secure 쿠키/동등한 보호 계약을 따른다. access/refresh token, WebAuthn assertion, 정책 원문을 localStorage에 넣지 않는다. localStorage에는 locale·시간대·테이블 표시 설정만 저장한다. 서버 감사 로그와 브라우저 console에 credential을 출력하지 않는다.
6. 폰트는 system fallback을 기본으로 하고, 추가 파일을 번들할 경우 해당 폰트의 라이선스와 고지를 배포물에 포함한다. 기존 설계 PDF에 쓴 폰트의 고지가 새 앱 전체 의존성 감사를 대신하지 않는다.
7. deep link를 새로 열어도 동일 경로가 복구되어야 한다. 인증 실패는 안전한 내부 return path만 유지한다. URL query·fragment에는 원문 요청, IP 목록, token, 사용자 이메일을 넣지 않는다.
8. Linux·Windows Server·macOS의 동일 release는 같은 정적 번들을 사용한다. OS capability는 브라우저 user-agent가 아니라 대상 agent가 검증해 보고한 backend 정보로 결정한다.

## 3. 공통 REST ViewModel

REST 조회 응답은 다음 envelope를 사용한다. UI가 이 필드를 만들어 서버 결과를 보강했다고 주장해서는 안 된다.

```typescript
type Freshness = {
  observed_at: string | null;           // RFC 3339 UTC
  stale_after_seconds: number;          // 정수, 응답 종류별 서버 정책
  stale: boolean;
  source: "controller" | "target" | "registry";
};
type ActionPermission = {
  action_id: string;                    // API 명세의 action allowlist
  allowed: boolean;
  reason_code: string | null;           // 허용이면 null, 거절이면 안정된 대문자 코드
};
type ReadEnvelope<T> = {
  data: T;
  server_time: string;
  revision: number;                     // 1 이상, 컬렉션은 snapshot revision
  actions: ActionPermission[];
  freshness: Freshness;
  next_cursor: string | null;
};
```

`observed_at=null`이면 `stale=true`다. 브라우저는 응답 수신 후 경과 시간을 더해 표시의 신선도를 낮출 수 있지만, 서버가 stale이라고 한 응답을 fresh로 올릴 수 없다. 목록 cursor는 scope·sort·snapshot에 결합된 불투명 값으로 취급한다. API의 응답 크기·pagination 상한을 우회해 전체 자산을 다운로드하지 않는다.

프런트엔드 내부 `ResourceState<T>`는 `loading | ready | refreshing | empty | forbidden | failed`로 구분한다. 여기에 `freshness`와 도메인 상태를 별도 필드로 둔다. 네트워크 오류는 `failed`, 장비 적용 결과 미확정은 `unknown`이다. 서로 덮어쓰지 않는다. API 오류는 F_02의 closed `Problem` 객체인 `type,title,status,code,detail,request_id,retryable,field_errors`를 받는다. 안정된 `code`와 필드 오류의 `code`를 로컬 catalog에 매핑하며, 서버의 영어 자유문장을 번역 lookup key로 사용하지 않는다. 알 수 없는 code는 영어 원래 code와 일반 오류 문구를 함께 표시한다. `detail`은 제한된 escape 텍스트로만 보여준다.

기본 UI 목록은 `limit=25`를 명시적으로 요청하고 선택은 25/50/100행, 정렬은 서버가 허용한 필드만 사용한다. API에서 limit 생략 시 기본 50이라는 F_02 계약을 바꾸지 않는다. 전역 검색은 사용자에게 허용된 org/project 안에서 수행한다. 읽기 실패를 빈 목록으로 반환하지 않는다. 다른 조직 자원에 대한 404는 존재 유무를 노출하지 않는 일반 문구로 표시한다.

## 4. 권한과 조작 제어

`owner`, `operator`, `reviewer`, `auditor`, `viewer`, `workload`, `worker`, `agent`는 API 명세의 역할 이름이다. 버튼 권한을 역할 문자열만으로 계산하지 않는다. 현재 scope의 서버 `actions`와 capability가 모두 허용해야 조작 가능하다. `owner`도 필수 검증 실패·승인 독립성·지원되지 않는 집행 기능을 우회하지 못한다.

| 사용자 문맥 | 화면에서 가능한 종류 | 추가 제한 |
|---|---|---|
| viewer | 허용된 범위의 상태·목록 조회 | 비밀·다른 사용자 원문·관리 설정은 응답에서 제외 |
| operator | 요청 생성, 허용된 배포 요청, 자기 lease 반납 | 다른 사용자의 권한 회수·승인 권한은 별도 capability |
| reviewer | scope 안의 정확한 계획 검토·승인/거절 | Team 독립 검토 인원에 자기 요청자를 포함하지 않음 |
| auditor | 승인·영수증·PBOM 조회/허용된 내보내기 | 조회 권한이 배포·비밀 export 권한을 뜻하지 않음 |
| owner | bootstrap·등록·운영 설정·권한 관리 | 운영 변경은 해당 change workflow와 승인 계약 적용 |
| workload/worker/agent | 각 machine API의 제한 동작 | 브라우저 로그인으로 사람 승인 권한을 얻지 않음 |

버튼 상태는 `available`, `disabled-with-reason`, `not-in-scope`를 구별한다. 알려진 미지원 기능은 설명과 `UNSUPPORTED`를 표시한다. 사용자에게 해당 자원 존재를 공개할 수 없는 경우에만 화면 요소와 자원을 함께 숨긴다. CLI/API 직접 호출도 동일하게 거절해야 하므로 버튼 비활성화 자체는 보안 통제가 아니다.

모든 mutation은 작업별 idempotency key를 한 번 만들고 명확한 결과가 나올 때까지 보존한다. 같은 제출의 재시도는 같은 키, 사용자가 내용을 바꾼 새 제출은 새 키를 쓴다. double-click은 전송 중 잠그되 브라우저를 닫아도 이미 접수된 작업은 계속될 수 있음을 표시한다. 확인되지 않은 timeout 후 새 키로 배포를 다시 보내지 않는다.

## 5. 화면 경로와 필수 내용

아래 경로는 브라우저 route다. API 경로와 혼동하지 않는다. 각 화면은 공통 loading/empty/permission/error/freshness 규칙을 구현해야 한다.

| Route | ViewModel 필수 필드 | 필수 조작·제한 |
|---|---|---|
| `/login` | auth mode, 조직 표시 이름, 허용된 인증 방법, session error | 로컬 또는 조직 로그인. 개발자·GitHub 계정 가입은 요구하지 않음 |
| `/setup` | 설치 profile, control OS, release, bootstrap 단계, 완료 조건 | 최초 소유자 설정, target 관측 점검. 이미 완료된 bootstrap은 재실행 불가 |
| `/overview` | target별 OS/backend/support state, 마지막 관측, desired/observed hash 차이, active lease·review_due deny·unknown operation 개수 | scope/target/OS 필터, 실제 장애로 이동. 전체 정상 배지는 미관측 target을 포함하면 금지 |
| `/requests` | request ID/revision, 요청자 표시값, target, created_at, request state, plan/operation 참조 | 생성, 필터, 서버 pagination. 생성 202는 '접수됨' |
| `/requests/new` | 허용 asset/service/binding 목록과 revision, 기간 한도, target capability | 목적·자산·서비스·binding·기간 입력, 검증 요청. 모호한 자산은 선택 요구 |
| `/requests/:id` | 고정 요청 revision, 해석 결과, needs_info 목록, plan ID/hash, 작업 상태 | 로컬 초안 편집·허용된 취소. needs_info 보완과 이미 제출된 요청의 변경은 원래 요청을 참조하는 새 request·새 계획이며 기존 ID를 덮어쓰지 않음 |
| `/plans/:id` | §6의 ReviewVM 전체 | 읽기·검증 증거 열기·승인/거절·배포 요청. mutable inline 정책 편집 금지 |
| `/policies` | policy ID/revision, action, target, scope, owner, lifetime.kind, observed 상태 | allow/deny 필터. deny 제거는 새 변경 계획으로 이동 |
| `/leases` | lease ID, owner, target, expires_at, lifecycle, observed enforcement, overlapping allowance | 자기 lease 반납. 갱신은 새 요청으로 이동하며 기존 만료를 수정하지 않음 |
| `/assets` | asset/service revision, 명시적 IP family/CIDR/protocol/port, 출처, observed_at | scope 내 등록·새 revision·충돌 해결. host-bit CIDR 자동 보정 금지 |
| `/bindings` | binding ID/revision, principal·workload 참조, 네트워크 증거, valid_until, assurance | issuer 검증 결과 조회·허용된 철회 요청. owner의 일반 UI는 bindings.attest 권한을 자동 갖지 않음. API identity와 packet identity 차이 표시 |
| `/envelopes` | 허용 범위·제외 목적지·기간·최대 TTL·승인 hash | 조회·철회와 로컬 bootstrap manifest 생성/확대 절차 안내. core의 일반 REST에서 root를 직접 생성·확대하지 않음 |
| `/delegations` | root delegation, principal/workload, asset/service/tool 집합, quota 사용·예약, 기한 | core-v1의 자식 위임은 UNSUPPORTED. 철회 후 회수 결과를 target별 추적 |
| `/deployments` | deployment ID, plan/hash, target, stage, operation, grant 시작기한·confirm deadline | 필터, 상세 이동. UNKNOWN을 완료로 집계하지 않음 |
| `/operations/:id` | kind, operation state, target state, receipt, stage timestamps, rollback/remaining permission | 조회 재시도·승인된 reconcile 진입. '다시 적용' 버튼으로 불명확 결과 우회 금지 |
| `/evidence` | 허용된 PBOM manifest, 연결 hash·서명검증 결과, 포함/제외 범위, event time | 필터, manifest 검증, 권한 있는 export. 서명 유효와 사실 입증을 구별 |
| `/integrations` | connector ID/version, maintained/supported 수준, capability, 연결 상태, secret reference | configure/test/disable. credential 실물은 저장 후 다시 보여주지 않음 |
| `/administration` | profile, 대상 OS 지원표, 사용자/역할, 인증, 시각, backup 상태, audit storage, 공개 링크 상태 | 관리별 capability 확인. 위험 변경은 새 계획/승인 과정으로 이동 |
| `/administration/telemetry` | F_06의 설정 revision, consent, endpoint, 각 category, queue·삭제 상태 | payload 미리보기, 별도 동의 저장, 철회, 삭제. 기본 off |
| `/about` | release/commit, 라이선스·제3자 고지, 지원 상태, 검증된 외부 링크 | 후원은 선택적 외부 링크. 링크 없음은 제품 오류가 아님 |

화면 구성요소는 공개 이름이 확정되기 전 `Project`라는 내부 중립 label을 사용한다. 파일/코드 identifier와 공개 제품명을 결합하지 않는다.

## 6. 요청 작성과 계획 검토의 정확한 동작

### 6.1 요청 작성

필수 입력은 target, source/destination asset ID, service ID, workload binding, 시작 시각, 지속 시간 또는 종료 시각, 목적이다. 두 시간 입력을 동시에 받으면 서로 일치하는지 검증한다. 브라우저 검증은 UX용이며 서버가 다시 검증한다. 최대 24시간이라는 제품 상한보다 더 작은 봉투·위임·조직 한도가 있으면 실제 최솟값을 보여준다. 허용 한도에 맞추어 사용자 모르게 잘라내지 않는다.

IPv4·IPv6, TCP·UDP를 명시적으로 구분한다. port를 쉼표 텍스트로 받아 임의 shell 문자열로 합성하지 않는다. 자연어 입력은 선택적 초안 보조이며 추출된 asset/service/기간과 원문 근거를 검토한 뒤 정형 요청을 제출한다. AI 사용 불가 상태에서도 같은 정형 UI가 작동한다.

### 6.2 ReviewVM

검토 화면은 하나의 고정 `plan_id`와 `plan_hash`에 묶여 다음을 모두 보여준다.

- request ID/revision/hash, `change_kind`, target ID·표시명·OS/backend·capability hash.
- baseline hash와 전체 candidate desired-state hash, requested patch hash, artifact hash, compiler·validator digest.
- source snapshot·binding revision/hash·유효기간, scope와 policy lifetime의 정규값.
- 새로 열리는 흐름 Δ+와 새로 닫히는 흐름 Δ-: family/protocol/원본 source/destination/interface/port 또는 ICMP/type/code/시간 경계.
- 차분의 포함·제외 차원, 필수 gate별 PASS/FAIL/UNKNOWN과 evidence hash, 분석 budget 초과 여부.
- 기존 연결 영향, 겹친 allow, deny 우선 효과, 관리 경로 보호, 양성·음성·새 관리 연결 probe, rollback 권한 상한.
- approval route human/delegated, 필요한 역할·독립 인원·현재 충족 인원, 승인 기한·철회·stale 원인.
- plan의 valid_until, lease expires_at, deny review_at, grant 시작 유효기간, confirm deadline을 서로 다른 label로 표시.

해시는 세부 패널과 승인 확인란에 전체 `sha256:`+64자리 값으로 노출한다. 목록의 짧은 hash는 탐색용이며 클릭하면 원문을 복사할 수 있다. 해시 생략 부분에 의존해 승인하지 않는다. 큰 흐름 목록은 서버 pagination과 전체 개수를 보이며 잘린 화면을 완전한 분석이라고 표시하지 않는다. 계획 자체가 API의 완전 객체 상한을 초과하면 `RESULT_TOO_LARGE`이며 분할된 새 계획을 요구한다.

`newly_allowed_flow_count`는 compiler가 정의한 정규화 흐름 구간 수이며 패킷 수·실제 세션 수가 아니다. 새 allow가 겹친 deny 때문에 유효 허용을 늘리지 않으면 그 이유를 보여준다. Δ+가 0이어도 Δ-로 서비스가 중단될 수 있으므로 '위험 없음'으로 표시하지 않는다.

### 6.3 승인·거절·배포

1. 페이지 로드와 승인 버튼 클릭 직전에 최신 불변 계획·approval state·freshness를 다시 조회한다. 비교 대상은 전체 plan hash다. role/capability/baseline/snapshot가 바뀌면 server reason을 보여주고 재계획한다.
2. 검토자는 펼쳐진 '승인 대상' 패널에서 대상·범위·UTC 시간·Δ+/Δ-·필수 검증·복구 상한을 확인한다. '이 계획 해시에 대한 결정을 제출합니다' 확인란은 기본 해제다. 스크롤 완료 여부를 사람의 검토 증명으로 간주하지 않는다.
3. `/api/v1/approvals/challenges`로 `{plan_kind,plan_id,plan_hash,decision,role}`을 보내면 서버가 `challenge_id,nonce,expires_at,rp_id`를 제공한다. 사람 승인 증거는 API 명세의 WebAuthn/허용된 승인키 절차를 따른다. UI가 개인키·서명 결과를 자체 생성해 승인자로 가장하지 않는다.
4. WebAuthn 결과는 `/api/v1/approvals/assertions`에 `{challenge_id,credential_id,authenticator_data,client_data_json,signature}`로 제출한다. challenge와 결정 내용을 서버가 저장하고 승인 집합을 구성한다. `POST /plans/:id/approvals` 쓰기 alias는 사용하지 않는다. 기존 경로의 GET은 조회 전용이다.
5. `decision=reject`도 동일한 계획·검토자 결합을 사용한다. 오류·사용자 취소는 승인·거절로 기록하지 않는다. challenge 만료·재사용·origin/RP 불일치는 실패이며 새 challenge가 필요하다.
6. 승인되면 '승인 완료, 아직 적용되지 않음'으로 표시한다. 배포는 별도 명시적 조작으로 `/api/v1/deployments`에 정확한 plan ID/hash를 보내고 operation 화면으로 이동한다. 자동 delegated 경로는 그 근거와 quota를 표시하며 가짜 인간 승인을 만들지 않는다.
7. 필수 FAIL/UNKNOWN, stale, 권한 부족, reviewer 독립성 부족, unsupported backend는 승인/배포를 막는다. target read-back와 confirm 영수증이 있는 ACTIVE 전에는 성공 알림에 '통신 허용됨'을 쓰지 않는다.

## 7. 반납·deny 검토·실패 상태

lease 반납 dialog는 lease ID·owner·target·현재 만료와 다른 허용이 남을 수 있음을 보여준다. 반납 결과에는 해당 lease의 REVOKED와 실제 잔존 권한을 따로 표시한다. 반납 요청의 HTTP 202를 '모든 통신 차단됨'으로 표시하지 않는다.

deny의 `review_due`는 검토 알림이다. '만료' countdown을 붙이지 않는다. 검토 완료는 deny를 유지하며 새 review revision을 생성할 수 있고, 제거는 권한 확대 차분을 가진 별도 계획이다. 임의 DELETE 버튼으로 즉시 제거하지 않는다.

| 상황 | 필수 화면·조작 |
|---|---|
| 처음 loading | 데이터 0·정상 그래프 대신 skeleton과 읽는 중 label, 조작 잠금 |
| empty | 권한 범위 내 데이터 없음, create 가능자만 생성 링크 |
| 새로고침 중 | 이전 데이터와 마지막 관측 시각 유지, '갱신 중' 표시 |
| 연결 끊김/stale | 기존 값의 시각·지연 표시, 최신 상태인 초록 표시 제거, 읽기 재시도 |
| mutation timeout | '결과 미확정'과 기존 operation 조회; 재배포 버튼 금지 |
| target unknown | 관측 미확정·잠금·quota 유지 설명, 권한 있는 reconcile/OOB 안내 |
| rolled_back | 복구 관측 결과와 복구 후 남은 정책, 처음 계획 성공과 구별 |
| degraded | 복구 불완전한 target·증거·운영 대응, 성공 toast 금지 |
| 401 | 작업 참조는 보존하고 재인증; credential·정책 원문은 영속 저장하지 않음 |
| 409/412/428 | 최신 revision 재조회, 변경 사항 차분, 무조건 덮어쓰기 없음 |
| 429/503 | Retry-After·상한 있는 backoff, queued 작업의 상태 조회 분리 |
| 새/알 수 없는 enum | 영문 원래 값과 '지원되지 않는 상태', 읽기만 허용하고 조작 중지 |

## 8. 갱신·시각·브라우저 동작

실시간 이벤트 경로가 capability에 없으면 polling만 사용한다. SSE를 제공하면 event ID로 이어받고 순서 누락·재연결 시 REST snapshot을 다시 읽는다. SSE 자체 payload만으로 권한을 새로 부여하지 않는다. polling은 활성 상세 화면 5초에서 시작해 오류 시 10·20·40·60초로 backoff하며 jitter ±20%, 성공 시 5초로 돌아간다. 탭 비활성 시 60초, 읽는 화면 이탈 시 취소한다. 수동 새로고침은 2초 debounce를 적용한다.

UTC가 저장·비교·서명 기준이다. 기본 시간 표시는 `YYYY-MM-DD HH:mm:ss UTC`다. 사용자는 IANA 시간대를 추가 표시로 선택할 수 있으며 승인 화면에는 UTC를 항상 병기한다. 지역 형식 날짜를 payload에 되돌려 보내지 않는다. DST의 모호하거나 존재하지 않는 입력 시각은 offset과 UTC를 확인해야 제출 가능하다.

countdown은 서버 시각과 브라우저 monotonic elapsed의 표시값이며 정책 집행 시간이 아니다. 로컬 시계가 틀려도 서버 만료가 연장되지 않는다. 남은 시간 0에서 UI는 '만료 시각 도달, 집행 상태 확인 중'을 표시하고 실제 관측을 갱신한다. 이미 확인된 EXPIRED/REVOKED는 다시 ACTIVE로 애니메이션하지 않는다. 브라우저 재개 후 오래된 데이터는 즉시 stale 처리한다.

## 9. 언어 선택과 fallback

지원 태그는 BCP 47의 `en`, `ko`, `ja`, `es`, `zh-Hans`, `zh-Hant`다. 기본 선택 순서는 사용자 저장 선택 → 지원되는 브라우저 선호 언어 → `en`이다. 조직 관리자는 설치 기본값만 정할 수 있고, 사용자 선택 때문에 wire 의미가 바뀌지 않는다. 국기 아이콘으로 언어를 표현하지 않고 각 언어의 자기 이름을 보여준다.

locale resolution은 `en-*→en`, `ko-*→ko`, `ja-*→ja`, `es-*→es`, 명시적 `zh-Hans-*→zh-Hans`, `zh-Hant-*→zh-Hant`, `zh-CN/SG→zh-Hans`, `zh-TW/HK/MO→zh-Hant`다. script/region이 없는 `zh`는 브라우저 자동 판정에서 `zh-Hans`를 선택하되 언어 메뉴에 간체/번체 선택을 명확히 노출한다. 이미 저장한 `zh-Hant`를 다음 접속에 덮어쓰지 않는다.

키 누락 시 해당 key의 `en`으로 fallback하며 missing counter를 로컬 개발 진단에 기록한다. 서버 telemetry에 번역 실패 원문·페이지 데이터를 보내지 않는다. runtime에서 승인·거절·기간·UNKNOWN·철회·동의 같은 critical key가 fallback되면 해당 패널에 영어 fallback 배지를 표시한다. catalog 자체 integrity 실패 또는 영어 critical key 누락은 조작 차단과 오류 화면이다. 번역되지 않은 화면 전체를 같은 locale의 정식 지원으로 광고하지 않는다.

HTML `lang`과 번역되지 않은 원문 구간의 언어를 선언한다. 코드·hash·IP·protocol·UUID는 locale로 변형하지 않으며 bidi isolate를 적용한다. locale switching은 미제출 폼 데이터와 plan hash를 보존하고 승인 challenge는 폐기해 새로 발급받는다. 번역문은 English canonical 의미의 표시일 뿐 별도의 정책 해석기가 아니다. [W3C 언어 선언 지침](https://www.w3.org/International/questions/qa-html-language-declarations)

## 10. 번역 catalog와 검수 계약

- key는 `section.intent` 형태의 영어 식별자로 고정하고 문장 자체를 key로 쓰지 않는다. catalog에 HTML·JS·URL·동적 key를 넣지 않는다.
- ICU MessageFormat과 `Intl`을 사용한다. 숫자·복수형·날짜를 문자열 이어붙이기로 조합하지 않는다. 영어/스페인어는 필요한 `one/other`, 한국어·일본어·중국어는 locale 규칙에 맞는 `other`를 사용한다. 선택형 enum은 명시적 allowlist를 사용하며 `other`가 안전한 불확실성 문구로 귀결되어야 한다. [Unicode CLDR 복수 규칙](https://unicode-org.github.io/cldr/ldml/tr35-numbers.html#Language_Plural_Rules)
- 같은 key의 interpolation 변수 집합·숫자 type·ICU selector 구조를 모든 언어에서 검사한다. `expires_at`과 `review_at`, approve와 deploy, reject와 revoke를 같은 번역 key로 합치지 않는다.
- 번역 상태는 `draft`, `reviewed`, `released`다. 모든 언어의 기초 데이터는 현재 `draft`; 영어도 안전 문구 검수가 끝났다고 자동 가정하지 않는다. 보안 의미를 이해하는 검토자와 해당 언어 검토자의 확인을 PR에 남겨 `reviewed`로 올린다. 한 사람이 두 자격을 충족할 수 있으나 역할을 기록한다.
- locale의 `released` gate는 필수 route key 100%, critical key 100% 검수, 변수/ICU 오류 0, 접근성·overflow·키보드 시나리오 통과다. 미통과 locale은 preview 배지를 붙이며 core-v1 여섯 언어 정식 출시 완료로 계산하지 않는다.
- 문자열을 늘린 `en-XA`와 RTL 모사 `ar-XB`는 test-only locale로 생성한다. 약 40% 길이 확장, 긴 이름, 이모지, combining character, 장문 CJK, 200%/400% 확대, 작은 화면에서 검증한다. test-only locale은 release 목록·wire 계약·실제 번역 지원 목록에 넣지 않는다.
- 문서 번역은 UI와 별도 완료율이다. 설치·초기 복구·정책 의미·보안 제보·telemetry 동의 안내는 해당 locale 출시 때 사용 가능한 검수본을 연결한다. 나머지 개발 문서는 원문 언어와 번역 상태를 표시한다. '전체 문서 6언어 완료'라는 문구를 현재 패키지에 사용하지 않는다.
- 언어 추가는 BCP 47 태그·fallback·글꼴·복수형·날짜·RTL 지원·검토자·fixture·보안 용어집을 같은 PR에서 추가해야 한다. 이름만 등록하거나 런타임 AI 번역을 붙여 지원으로 승격하지 않는다.

`F_기본문구.json`은 위 40개 key의 시작 데이터다. 구현자는 catalog generator로 `web/src/locales/<locale>/core.json`에 변환하고 나머지 route key를 추가한다. 변환 과정은 `_meta`를 제품 문구로 렌더링하지 않는다. `translation_status`와 검수 상태는 release manifest에 유지한다.

## 11. 접근성·시각 표현

목표는 WCAG 2.2 AA이며 자동 검사만으로 준수 인증을 주장하지 않는다. 모든 기능은 키보드로 동작하고 focus가 보이며 sticky header/modal에 가려지지 않아야 한다. 표는 caption·column header를 가지며 정렬 상태를 읽을 수 있어야 한다. modal은 label·초점 이동/복귀를 관리하고 Escape 취소가 서버 작업 취소를 뜻하지 않음을 구별한다.

본문 대비는 4.5:1, 큰 글자·중요 UI 경계는 해당 AA 기준을 적용한다. 상태는 색+텍스트+아이콘으로 구별하고 빨강/초록만 사용하지 않는다. 클릭 목표는 최소 24×24 CSS px를 만족시키며 주요 버튼은 44×44를 권장값으로 둔다. 320 CSS px 폭에서 핵심 작업은 reflow하고 큰 정책 표만 이름 있는 가로 scroll 영역을 허용한다.

폼 label·오류 연결·입력 예시를 제공한다. 제출 오류는 상단 요약과 해당 필드에 함께 표시하며 입력값을 지우지 않는다. 작업 완료·연결 끊김은 적절한 live region으로 알리되 매초 countdown을 읽어주지 않는다. `prefers-reduced-motion`이면 비필수 애니메이션을 끈다. WebAuthn/로그인에 복사·붙여넣기·password manager를 방해하지 않고 접근 가능한 다른 인증 수단은 동일 보안 정책 범위에서 제공한다. [WCAG 2.2](https://www.w3.org/TR/WCAG22/)

## 12. 구현 인수 시험

| ID | 시험 | 통과 기준 |
|---|---|---|
| UI01 | AI·인터넷·GitHub 없이 로컬 요청→검토→적용→반납 | 외부 호출 없이 동일 정형 흐름 완료 |
| UI02 | HTTP 202, validation succeeded, target unknown | 어느 상태도 허위 ACTIVE로 표시하지 않음 |
| UI03 | 검토 중 plan hash·baseline·role 변경 | 기존 확인란/challenge 폐기, 서버 승인 거절 |
| UI04 | 필수 UNKNOWN/FAIL·unsupported OS capability | UI 비활성 이유와 API 거절 모두 확인 |
| UI05 | self-review·역할 중복·위임 경로 | Team 독립 인원 정확, 위임을 사람으로 표시하지 않음 |
| UI06 | submit double-click·timeout·새로고침·탭 종료 | 중복 mutation 없음, 기존 operation으로 복구 |
| UI07 | SSE 중단·순서 누락·서버 503·offline | 제한 polling, stale와 domain UNKNOWN 구별 |
| UI08 | 겹치는 lease 반납·deny review_due | 잔존 권한 표시, deny 자동 제거 없음 |
| UI09 | DST·시계 오차·suspend·만료 경계 | UTC 불변, UI countdown이 TTL을 연장하지 않음 |
| UI10 | 여섯 locale·locale 변경·missing critical key | key/변수 일치, fallback 명시, 승인 대상 불변 |
| UI11 | 영문 확대·CJK·pseudo RTL·zoom | 버튼 잘림·의미 손실·조작 불능 없음 |
| UI12 | keyboard·screen reader·대비·reduced motion | 요청·승인·회수·동의 전체 경로 수동 검수 |
| UI13 | XSS·HTML 이름·bidi·길이 초과·credential 오류 | 텍스트 escape, 비밀 로그 없음, 안전한 제한 |
| UI14 | Linux/Windows Server/macOS fleet 혼합 | 실제 backend별 지원·관측·실패를 개별 표시 |
| UI15 | telemetry·후원 비활성 | 기능 차이·runtime 외부 검사·강제가입 없음 |

시험 보고서는 브라우저/OS/스크린리더 버전, route, locale, commit, fixture와 실패를 기록한다. Playwright 등 자동 E2E와 수동 접근성 검수를 구분한다. 참조 문구 JSON의 구문 통과만으로 UI 시험을 통과한 것으로 표시하지 않는다.

## 13. 풍부한 대시보드·경로·감사 탐색

대시보드는 큰 숫자 카드와 채팅 창만으로 끝내지 않는다. 같은 scope 안에서 fleet 상태, 정책 변화, 업무 경로, 전체 수명 timeline, 증거 연결을 오갈 수 있어야 한다. 사람이 이해하는 표·그래프와 AI agent가 읽는 typed 데이터는 같은 application service와 증거 ID를 사용한다.

### 13.1 실제 구현할 탐색 화면

| 화면·경로 | 데이터·상호작용 | 정확성 조건 |
|---|---|---|
| `/overview` fleet dashboard | OS/backend별 대상 분포, ACTIVE/UNKNOWN/DEGRADED, 관측 지연, expiry/review_due, 최근 변경·probe 실패. 카드 선택이 동일 filter의 목록으로 이동 | 응답 없는 target은 정상으로 집계하지 않으며 기간·분모·snapshot 표시 |
| `/topology` | source workload→source asset→집행 target→destination/service 그래프, OS/backend/filter scope 표시, 방향·protocol·서비스·시간 필터 | 등록 자산·route snapshot으로 계산한 intended path와 관측 evidence layer를 명시적으로 분리 |
| `/operations/:id` timeline | 요청→해석/정규화→검증/컴파일→계획→승인→grant→apply→read-back/probe→confirm→회수/만료/복구 | 실제 event time과 인과 참조로 순서 표시. 승인을 받기 전에 고정한 artifact를 승인 후 임의 재컴파일하지 않음 |
| `/plans/:id` semantic diff | 좌측 baseline/우측 candidate, Δ+/Δ-, 시간 경계 slider, 기존 세션 영향·겹친 lease·deny 우선 | slider는 고정 계획의 분석 시각을 선택할 뿐 운영 시간·정책을 변경하지 않음 |
| `/evidence/:id` PBOM graph | request·snapshot·plan·approval·artifact·grant·receipt·probe·revoke/recovery node와 hash 참조 edge | 증거 연결과 무결성 확인 결과를 보여주며 graph edge를 실제 패킷 이동으로 표현하지 않음 |
| `/audit` | UTC 범위, actor/role/scope/event type/target/outcome 필터, 원문 접근 권한에 따른 redaction, export | 기간 내 누락/보존 종료와 검증되지 않은 서명·신뢰 root를 구별 |

topology의 intended node/edge는 점선과 '계획/등록 정보', 실제 read-back/probe 증거는 실선과 증거 시각·종류를 함께 표시한다. 색만으로 구분하지 않는다. 패킷 캡처가 없으면 '실제 패킷 경로 전체 확인'이라고 쓰지 않는다. 성공 probe는 그 시점의 표본이고 모든 흐름·모든 hop의 증명이 아니다. 관측하지 못한 hop은 UNKNOWN으로 남기며, 등록되지 않은 외부 인터넷 경로를 상상해 그리지 않는다. encrypted payload나 내부 프로세스 신원을 network tuple만으로 알아냈다고 주장하지 않는다.

topology 응답은 F_02와 동일하게 최대 256 node·512 edge·256 KiB다. 초과 시 `RESULT_TOO_LARGE`를 표시하고 더 좁은 target 필터를 요구한다. 현재 topology API에 없는 cursor·증분 확장을 지원한다고 표시하지 않는다. `complete`와 scope/snapshot을 화면에 보이고 incomplete를 전체 분석으로 표시하지 않는다. PBOM은 한 manifest 최대 512 node·2048 edge, 더 큰 것은 서명된 child manifest로 이동한다. layout 작업은 browser worker에서 수행하고 React main thread·제어 API를 장시간 막지 않는다. pan/zoom/search/reset/focus selected, node detail panel, 동등한 표와 텍스트 인접 목록을 제공한다. drag만 가능한 필수 조작은 만들지 않는다.

timeline wire는 F_02의 `AuditEvent`이며 `event_id,sequence,recorded_at,event_type,actor_id,resource_kind,resource_id,operation_id,plan_hash,outcome,reason_code,evidence_hashes,previous_event_hash,event_hash`와 tenant/schema 필드를 그대로 읽는다. UI의 기록/관측/검증/미확정 구분은 event outcome과 참조 evidence의 종류·검증 결과에서 파생하며 새 wire enum을 만들지 않는다. 실제 실행 시각이 참조 receipt에 있을 때만 기록 시각과 병기한다. browser 수신 시각이나 AuditEvent 기록 시각을 실제 패킷 실행 시각으로 바꾸지 않는다. 제품 계약에서 정의하지 않은 event type은 영어 identifier와 미지원 표시로 남긴다.

### 13.2 증거 검증과 내보내기

PBOM export는 사용자가 허용받은 범위의 manifest와 참조 객체만 포함한다. manifest에는 schema/version, request/plan/operation/target 참조, 생성 시각, 포함 범위, 제외/삭제/미조회 목록, hash algorithm, 각 객체 digest, 서명 envelope와 검증에 필요한 공개 신뢰 자료를 포함한다. secret·승인 개인키·session token·실제 원문 payload는 기본 포함하지 않는다. 운영 증적과 공개 GitHub 합성 예제를 섞지 않는다.

검증 UI는 `hash match`, `signature valid under selected trust root`, `missing object`, `expired/revoked signing authority`, `unverified source`를 개별 표시한다. hash가 맞는 문서라는 사실과 과거 장비 동작의 진실성을 구별한다. 번역·pretty-print된 JSON을 원래 DSSE payload bytes 대신 검증하지 않는다. 원본 manifest와 사람이 읽는 HTML/CSV 요약을 함께 export할 수 있으나 요약은 별도 derivative임을 표시하고 원본 digest를 보존한다. CSV 셀의 formula injection을 차단하며, HTML export에 외부 script/이미지 요청을 포함하지 않는다.

### 13.3 사람과 agent의 공통 조회

상세 화면은 `GET /api/v1/operations/{operation_id}/timeline`, `/api/v1/audit/events`, `/api/v1/topology`, `/api/v1/pbom/{manifest_id}`, `/api/v1/evidence/{object_hash}` 및 `/api/v1/evidence/{object_hash}/content`를 사용한다. evidence metadata와 exact bytes를 구별하며 content는 16 MiB 전체 상한·요청당 256 KiB 단일 range를 지키고 전체 hash 확인 전 완전한 서명 객체로 처리하지 않는다. HTML을 긁거나 화면 캡처를 해석해야만 증거를 얻을 수 있는 제품으로 만들지 않는다. machine 응답은 canonical 영어 ID·UTC·typed state·hash와 각 schema에 정의된 completeness/freshness를 포함한다. audit pagination과 topology의 좁은 filter를 구별한다. 설명을 위한 locale 문구는 부가 표시일 뿐 agent의 분기 조건이 아니다.

기존 core-v1 MCP 여섯 도구는 호환성을 유지한다. evidence/topology/audit 읽기를 추가할 경우 별도 versioned read capability에 연결하고 도구별 allowlist·입력/출력 schema·scope·최대 결과·cursor·감사 시험을 통과한 경우에만 discovery에 노출한다. 조회 extension이 미구현이면 UNSUPPORTED이며 사람이 승인하는 도구를 덧붙이지 않는다. 그래프에서 선택한 node가 승인·배포를 수행하거나 machine principal에 reviewer 권한을 암묵 부여하지 않는다.

### 13.4 오픈소스 UI 구성요소

초기 구현 선택은 React Flow의 `@xyflow/react`로 그래프, TanStack Table로 서버 목록/필터/표, Radix Primitives로 dialog/menu/tab/focus, Recharts로 시간 series·분포 chart다. 각각의 공식 저장소에서 현재 MIT 원문을 확인했다. 이 선택은 유료 Pro 예제·템플릿·hosted 서비스 이용권을 포함하지 않는다. 실제 선택 버전·전이 의존성과 번들 asset의 라이선스는 lockfile·SBOM·NOTICE 검수로 고정한다. [React Flow/xyflow LICENSE](https://raw.githubusercontent.com/xyflow/xyflow/main/LICENSE), [TanStack Table LICENSE](https://raw.githubusercontent.com/TanStack/table/main/LICENSE), [Radix Primitives LICENSE](https://raw.githubusercontent.com/radix-ui/primitives/main/LICENSE), [Recharts LICENSE](https://raw.githubusercontent.com/recharts/recharts/main/LICENSE)

컴포넌트 사용만으로 접근성 준수를 가정하지 않는다. chart마다 제목·단위·기간·분모·동일 데이터를 담은 표를 제공하고 tooltip의 핵심 정보를 keyboard focus로도 읽을 수 있게 한다. 비연속 관측은 선을 끊고 missing을 0으로 채우지 않는다. dark/light theme 모두 대비를 검증한다. screenshot용 가짜 데이터와 실제 API 상태는 fixture 표시로 구분하며 운영 화면에 가짜 실시간 수치를 채우지 않는다.

추가 인수 시험은 그래프와 표의 동일 node/edge 집합, 접근권한 밖 node 비노출, topology 256/512 상한과 target filter, audit pagination, stale topology, missing evidence, 변조된 hash, 서명은 유효하나 신뢰 root 미승인, export redaction, agent 조회와 화면의 동일 snapshot, reduce-motion/keyboard/screen-reader다. 이 시험을 마치기 전에는 '모든 경로를 검증하는 대시보드'라는 보장을 사용하지 않는다.

SPDX-License-Identifier: Apache-2.0
