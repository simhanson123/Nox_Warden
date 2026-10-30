# 최종 개발계약 v1

이 디렉터리는 최종 설계에서 사용하는 데이터 계약과 합성 예제를 담는다. 실행 가능한 방화벽, 배포 서버, 승인 서버를 제공하는 디렉터리가 아니다. JSON 구문 검사와 업무 의미 검사를 구분하며, 검증기의 통과 결과는 실제 접근 권한을 발급하지 않는다.

## 1. 파일과 정본

| 파일 | 용도 |
|---|---|
| `F_계약_스키마.json` | Draft 2020-12. 핵심 도메인 객체 7개와 MCP 결과 묶음 1개를 합친 8종 계약. 중첩 정의까지 포함한 정확한 정의 수는 검증결과 참조. 루트는 연결된 합성 fixture 묶음 |
| `F_계약_예제.json` | 요청 → 계획 → 배포 허가 → 관측 영수증 → MCP 결과가 연결된 합성 예제 |
| `F_차단정책_예제.json` | 실제 종료 시각 없이 정기 검토 시각만 가진 deny 정책 예제 |
| `F_MCP_도구_카탈로그.json` | 자체 완결 input/output schema를 가진 핵심 도구 6개. `tools` 배열만 MCP 도구 목록으로 사용 |
| `F_참조검증기.py` | schema·CIDR·포트·시간·권한 범위·해시 참조 검사 및 반례 시험 |
| `F_계약_검증결과.json` | 실제 실행한 계약 검사 결과 및 미실행 영역 |

제품 정본의 수명·권한·승인 의미가 상위 기준이다. 구현 중 schema가 그 의미를 전부 표현하지 못하면 semantic validator와 런타임 검사가 추가로 강제해야 한다. schema에서 허용된다는 이유로 권한을 발급해서는 안 된다.

## 2. 핵심 객체

| 정의 | 필수 의미 |
|---|---|
| `Policy` | `policy_id`, `policy_revision`, 조직·프로젝트·단일 대상, 소유자, 이유, scope, action별 lifetime |
| `AccessRequest` | 클라이언트의 workload binding·자산 ID·서비스 ID·기간·목적. principal·원시 CIDR·원시 포트·승인 필드는 없음 |
| `AccessEnvelope` | 사전 승인된 최대 네트워크 범위, 명시적 제외 목적지, 유효기간·최대 lease, approval hash |
| `Delegation` | 단일 root의 요청 가능 principal·workload·자산·service·도구·합산 한도, 유효기간과 rolling 24시간 예산. `can_delegate=false` |
| `Plan` | `change_kind=add_access_lease`인 접근 추가 변경 계획. 불변 request/requested-policy/envelope/delegation 해시와 요청 정책 전체, baseline 및 별도 full candidate hash, capability·자산·workload snapshot, 가드레일·컴파일러·validator·artifact·검증report, 영향 요약, probe·승인조건·복구 상한, epoch·generation |
| `Grant` | 해석된 `payload`와 그 정확한 바이트를 서명한 `dsse` 봉투. plan/artifact/baseline·주체·workload·대상·정책 revision hash·승인 집합·quota reservation·시작 기한·confirm 기한·복구 상한을 결합 |
| `Receipt` | 대상과 grant/plan·epoch/generation에 결합한 관측 결과. active는 observed state hash·적용/확인/confirm/기록 시각·새 관리 접속 probe hash·durable confirm hash를 필수로 가짐 |
| `McpResult` | 도구·작업 종류·상태별 tagged union. active+null, 배포 succeeded+UNKNOWN 대상, lease 없는 active는 금지 |

`ApprovalSet` 전체, PBOM 전체, workload binding/자산/service registry 전체, worker queue, 벤더 Import IR, HTTP/OAuth 및 MCP wire message는 이 소규모 계약 패키지에 포함되지 않는다. 이들의 hash 참조는 검증된 외부 객체를 뜻하며, 참조 문자열 자체가 진실성을 증명하지 않는다. 이 패키지만으로 해당 하위 시스템을 구현 완료했다고 주장하면 안 된다.

**이 패키지의 Plan은 접근 lease 추가용 patch 계약이다.** `requested_policies`에는 이번 요청의 allow만 들어가고 `requested_policy_hashes`와 `request_patch_hash`는 그 변경분에 결합된다. 이것을 전체 target ruleset으로 replace해서는 안 된다. 기존 deny 및 다른 유효 allow를 포함한 기준 상태에 patch를 합성하는 것은 runtime compiler의 책임이며, 그 전체 candidate의 fingerprint가 `desired_state_hash`, portable compiled artifact의 해시가 `artifact_hash`다. baseline이 달라지면 새 계획을 만든다. validator는 patch 내용의 hash 및 전체 candidate hash의 Grant/Receipt 참조 일치를 확인하지만, 외부 baseline과 합성한 전체 후보 상태를 계산하거나 기존 deny 보존을 입증하지 않는다. 이 검증은 실제 semantic gate의 필수 조건이다.

일반 deny 추가/제거·기존 정책 수정·다중 요청 통합의 Plan 스키마, 전체 후보 ruleset 열람·다운로드 API는 별도 구현 계약으로 추가해야 한다. `Policy` 타입은 deny를 표현하지만, access grant가 deny를 만들거나 없애는 데 사용될 수는 없다.

## 3. 정책 의미

native v1은 `allow 합집합 - 명시 deny 합집합`이다. `priority` 속성은 허용하지 않는다. 기존 벤더의 first-match 정책은 별도 Import IR에서 보존한다.

- allow: `lifetime={kind:"lease",not_before,expires_at}`. 기간은 최대 24시간. 기한은 신규·기존 연결의 권한 종료를 뜻한다.
- deny: `lifetime={kind:"review",not_before,review_at}`. 검토 주기는 최대 90일. `review_at`에 차단이 사라지지 않으며 `expires_at` 속성은 금지한다. v1 자동 deny 삭제는 없다.
- 방향은 요청을 시작하는 패킷 기준의 `input`, `output`, `forward`다. 응답 패킷을 다른 요청자로 다시 분류하지 않는다.
- `scope.transport`는 TCP/UDP의 `destination_ports[{start,end}]` 또는 ICMP/ICMPv6의 `type,code`다. ICMP에 포트를 넣을 수 없다.
- input은 ingress만, output은 egress만, forward는 둘 다 명시한다. IPv4/IPv6 주소와 ICMP 계열을 맞춘다.
- 한 access patch에는 policy ID별 revision이 하나다. 과거 revision·철회 기록이나 기존 target 정책 전체를 이 변경분 목록에 섞지 않는다. 전체 후보 상태의 중복·충돌 검사는 별도 semantic gate가 수행한다.

새 통신 요청을 처리할 때 허용 범위는 envelope, delegation, 현재 workload binding, 자산 snapshot, 조직 가드레일 및 quota의 교집합이다. 요청의 `source_asset_ids`는 클라이언트 주장일 뿐이며 서버가 인증된 workload에 실제 결합돼 있는지 검증한다. service ID를 포트로 해석하는 것은 서버 resolver의 책임이다.

## 4. 도구 흐름

1. `get_capabilities`로 프로필과 제약을 확인한다.
2. `request_access`는 초안 접수, 검증, 위임 평가와 계획 준비를 시작한다. 이 호출 자체는 패킷 집행을 하지 않는다.
3. `get_operation`의 `kind=validate,state=succeeded` 결과에서 plan ID/hash를 얻는다. `get_plan`으로 같은 불변 계획을 읽는다.
4. 사람이 필요한 승인은 UI/REST에서 처리한다. 사전 위임으로 충족되는 승인 집합은 서버가 작성한다. MCP에 approve 도구는 없다.
5. `request_deployment(plan_id,plan_hash,idempotency_key)`가 실제 배포 요청이다. signer가 승인, 현재 snapshot, baseline, quota, epoch/generation을 다시 확인한다.
6. `get_operation`의 `kind=deploy,state=active`와 일치하는 대상별 영수증을 확인한 뒤 활성 상태로 표시한다. 접수·검증 성공·승인은 active가 아니다.
7. `release_access`로 자기 lease를 회수 요청한다. accepted는 접수이며, `kind=release,state=revoked`와 제거 영수증이 완료 의미다. 다른 권한이 남을 수 있다는 필드는 별도로 반환한다.

갱신은 새 `request_access`와 새 idempotency key를 사용한다. 기존 request/plan/lease를 덮어쓰지 않는다. 기존 연결의 후속 패킷도 현재 유효 allow의 합집합에서 deny를 뺀 결과로 평가하므로, 같은 흐름을 허용하는 다른 유효 lease가 남으면 통신이 계속될 수 있다. 오래된 lease의 승인·소유권을 새 lease로 덮어쓰는 것과 현재 유효 권한으로 통신을 계속 허용하는 것은 구분한다. `needs_info`도 새 요청으로 다시 제출한다. 이전 미완료 초안은 권한을 발급하지 않고 보존기간 이후 정리된다. 자동 재시도에는 원래 idempotency key를 재사용하고, 서버는 인증 principal·도구·입력 hash에 결합해 같은 결과만 반환해야 한다.

v1은 단일 대상·최대 256개 **요청 정책**의 완전한 변경 계획 객체를 반환한다. target의 전체 후보 ruleset을 이 목록으로 표현하지 않는다. 요청 변경분도 잘라 반환하지 않으며, 256개보다 적어도 출력이 카탈로그의 **256 KiB** 제한을 넘으면 `get_plan`은 `unavailable/RESULT_TOO_LARGE`를 반환한다. 더 작은 요청으로 재계획한다. 이후 대규모 지원에서는 고정 snapshot에 결합한 cursor 계약을 별도 버전으로 추가한다. 조회 도구 실패가 허용을 만들지는 않는다. transport 구현은 실제 JSON-RPC 봉투와 content를 포함한 송수신 바이트 한도도 검사한다.

도메인의 operation 진행 상태와 도구의 결과 표시는 구분한다. 검증 작업 완료는 `kind=validate,state=succeeded`, 배포 완료는 `kind=deploy,state=active`, 회수 완료는 `kind=release,state=revoked`다. 도구 wrapper의 `accepted`, `ready`, `ok`는 각각 접수·불변 계획 조회·기능 조회를 나타내며 자체적으로 패킷 집행 상태를 뜻하지 않는다. `get_plan.data.approval_state`는 변경 가능한 승인 조회 상태이므로 PlanContent 해시에 넣지 않는다.

`tools/list` 자체의 wire pagination과 여기의 plan 데이터 pagination은 별개다. authorization_contracts는 서버 정책 메타데이터이며 MCP 표준 필드로 전송하지 않는다. tool annotations는 권한 판단 수단이 아니다. HTTP 인증, Origin 검사, 프로토콜 버전 협상, 취소, rate limit, 도구 오류 전송 형식은 최종 설계의 별도 wire/인증 계약에 따른다.

## 5. 정규화, 해시, 서명

- 해시는 모두 `sha256:`와 소문자 16진 64자로 표기한다.
- 시각은 UTC의 `YYYY-MM-DDTHH:MM:SSZ`다. 로컬 시간대나 오프셋 문자열은 정본 입력으로 사용하지 않는다.
- 큰 authority epoch와 target generation은 u64 범위의 정규 10진 문자열이다. 앞에 0을 붙이지 않는다.
- JSON 중복 키·NaN·Infinity·부동소수점·표현 범위를 벗어난 정수는 거절한다. 도메인 입력을 받아 계획으로 확정하기 전에 NFC 정규화하며, 버전은 `f.normalize/nfc-v1`로 계획에 고정한다. 서명 검증 때 이미 서명된 바이트를 다시 정규화하지 않는다. 참조검증기는 비정규 NFC 값을 거절하고, canonical serializer 자체는 문자열 값을 그대로 보존한다.
- 이 제한된 형식에서 키를 정렬하고 공백 없는 UTF-8 JSON을 만드는 `canonical_bytes()`는 RFC 8785에 맞는 부분집합 직렬화다. 일반적인 임의 JSON용 JCS 구현을 제공하는 것은 아니다.
- CIDR은 네트워크 주소의 정규형이어야 하며 host bit가 남은 입력을 거절한다. scope CIDR 목록은 address family·주소·prefix 순, ID/인터페이스 목록은 사전순, 포트 범위는 start/end 순으로 고정한다. scope 내 중복·겹치는 범위는 정규화 후 넣는다.
- JSON 배열 순서는 해시에 포함된다. 임의로 순서를 바꾼 뒤 같은 계획이라고 주장하지 않는다. `requested_policy_hashes`는 정렬하고 `request_patch_hash`는 policy ID/revision 순으로 정렬한 요청 정책 배열의 해시다. `desired_state_hash`는 기준 상태와 이 patch를 합성한 전체 candidate의 별도 semantic fingerprint다. 이번 참조검증기는 그 값을 직접 재계산하지 않는다.
- `plan_hash`는 Plan 전체의 canonical bytes, `request_hash`는 AccessRequest 전체, 각 authority hash는 해당 전체 객체의 해시다. Grant에는 자기 hash 필드가 없으므로 순환 참조가 없다.
- Grant의 `dsse`는 표준 `payloadType`, base64 `payload`, `signatures[{keyid,sig}]` 봉투다. payloadType은 `application/vnd.f.grant.v1+json`으로 고정하고 payload는 canonical GrantPayload 바이트다. 서명 대상은 [DSSE 공식 프로토콜](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)의 PAE다. 운영에서는 검증된 DSSE/Ed25519 라이브러리와 신뢰 키 registry·키 철회를 사용한다. `keyid`는 검증할 키를 찾는 힌트이며 그 문자열만으로 권한을 부여하지 않는다. 일반/URL-safe base64를 해석하고, 확인한 바이트와 애플리케이션이 사용하는 payload가 정확히 같아야 한다.
- Grant의 바깥 `payload` 객체는 schema·개발도구가 읽기 위한 투영이다. DSSE payload를 decode한 정확한 바이트가 이 객체의 canonical bytes와 다르면 거절한다. 실제 집행자는 서명이 검증된 바이트에서 해석한 객체만 사용해야 한다.
- Receipt의 `grant_hash`는 DSSE 봉투와 투영된 payload를 포함한 Grant 전체를 가리킨다. Receipt 자체의 진위는 인증된 집행 채널과 서명된 감사 증적에 결합해서 검증해야 한다. 이 파일의 receipt 데이터만 신뢰하면 안 된다.

합성 예제에는 공개 재현용 키로 만든 DSSE/Ed25519 signature와 public key가 들어 있다. 실제 사용자·장비·조직의 서명이 아니며 제품의 trust store에 넣어서는 안 된다. 참조검증기는 봉투 형식·decode된 payload 일치·signature 길이만 확인한다. 암호학적 진위 및 운영 키의 권한은 검증하지 않는다.

## 6. 참조검증 실행

Python과 `jsonschema`만 필요하다.

```powershell
python -m pip install "jsonschema>=4.23,<5"
python .\F_참조검증기.py --self-test --report .\F_계약_검증결과.json
python .\F_참조검증기.py --file .\F_계약_예제.json --at 2026-10-30T09:00:02Z
python .\F_참조검증기.py --kind Policy --file .\F_차단정책_예제.json
```

위 명령은 이 디렉터리에서 실행한다. 예제 시각은 고정된 테스트 시계다. `--at`를 생략하면 현재 UTC를 사용하므로 날짜가 지난 예제는 유효기간 검사에 실패하는 것이 정상이다. fixture 파일의 `fixture_time`을 운영 신뢰 시각으로 받아들이지 않는다. bundle 검사는 grant가 새 쓰기를 시작하는 시점을 검사하는 것으로, 적용 허가 5분이 지난 뒤에도 유효한 lease의 상태 조회 전체를 대신하지 않는다.

스키마 단독 검사와 semantic 검사를 구분한다. `--kind Policy`와 전체 fixture는 의미 검사까지 수행한다. 나머지 개별 `--kind`는 schema 검사만 수행한다. cross-object 정합성은 전체 fixture 검사를 통해 확인한다.

## 7. 런타임이 별도로 책임져야 할 부분

필수 관문 8개가 PASS로 적힌 JSON을 받았다는 이유로 배포하면 안 된다. signer는 현재 신뢰 가능한 입력으로 schema, identity, scope, quota, semantic, expiry, capability, baseline을 다시 평가한다. 클라이언트가 제출한 PASS나 projected quota는 권위가 없다.

quota 예약은 원자적 공유 상태에서 실제 합산값을 계산해야 한다. core-v1의 창은 발급 시각 `as_of` 기준 `(as_of-86400초,as_of]`이며, grant에는 실제 계산 창의 시작·끝을 결합한다. 신규 lease는 고유 lease ID별 한 번, 고유 목적지는 그 창의 승인/예약 목적지 asset ID 합집합, 누적 lease seconds는 창 안에서 발급/예약한 각 lease의 전체 승인 기간을 정수 초로 합산한다. 여러 대상이 없는 core-v1에서 여러 정책 branch가 같은 lease를 실현해도 기간을 branch 수만큼 중복 계산하지 않는다. 만료를 기다리는 현재 활성 lease와 UNKNOWN은 현재 동시 한도에 포함하며, 회수로 과거 24시간 누적 사용량을 돌려받지 않는다. 동시 적용은 dispatch 시작 전 예약하고 confirmed/failed-before-write/verified-rollback 등 확정 결과에서 해제한다. UNKNOWN에서는 점유를 유지한다.

`projected_*`는 해당 요청까지 포함한 원자적 연산 후 합산값이다. 참조검증기는 상한·최소 필요량·시간 창만 검사하며 다른 요청의 원장을 알지 못하므로 정확한 전체 사용량이나 동시성을 입증하지 않는다. 프로젝트에 여러 root가 있으면 프로젝트 합산 한도도 같은 transaction에서 검사해야 한다. 권한·워크로드 폐기와 발급의 경쟁, 중복 전송, DB 복구, epoch의 실제 단조성, 장비의 현재 baseline은 별도 시험 대상이다.

업무 lease는 envelope·delegation·workload binding의 종료 상한을 넘지 않는다. **업무 lease를 5분짜리 grant.not_after보다 짧게 제한하는 것은 아니다.** `not_after`는 새 적용을 시작할 수 있는 기한이다. confirm은 실제 적용 후 60초 이내이며 `confirm_not_after`라는 절대 상한도 함께 지킨다. 복구 권한은 이 확인 구간을 덮되 승인된 scope와 현재 만료·철회·deny 조건을 지켜야 한다.

Plan은 예제의 요청 변경 범위 및 별도 candidate hash를 보여주지만 전역 정책 의미·기존 deny 보존·deny 우선·관리 보호 경로를 실제로 계산하는 Twin을 포함하지 않는다. 전체 제품은 기준 정책 집합과 변경분을 합성하고 신규·기존 패킷, NAT 전후, 복구와 만료를 검증해야 한다. 이 검증기에는 커널 API 호출이나 장비 자격증명 처리가 없다.

## 8. 실제 확인한 범위

계약 시험은 스키마 구조, 잘못된 상태 조합, CIDR/포트/family/방향, 수명, envelope·delegation 교집합, projected quota 상한, DSSE payload 투영 일치, ID·해시와 epoch/generation의 객체 간 일치, confirm 시간 및 출력 상한을 검사한다. 최신 정확한 개수와 각 결과는 `F_계약_검증결과.json`에 기록한다.

실제 서명 신뢰, 승인자의 신원, service-to-port resolver, 공유 DB 원자성, nftables 집행, 실제 timeout·세션 회수, 벤더 장비, live MCP 클라이언트 상호운용은 검증하지 않았다. 이 구분은 구현 및 출시 검수에서도 유지한다.
