# Controlled Open Source Firewall

**Status: design preview. No firewall runtime release is included.**

Linux nftables를 기반으로 사람과 업무 에이전트의 통신 접근을 통제하는 오픈소스 프로젝트다. AI는 선택적으로 요청을 해석하고 설명한다. 실제 권한은 검증 가능한 정책·승인·제한 위임·서명·만료로 결정한다.

## Design commitments

- 기본 차단, 명시 deny 우선, 현재 유효한 allow의 합집합.
- 새 연결과 기존 연결에 일관된 만료·철회 의미 적용.
- 접근 봉투, 신원·workload binding, 위임 범위, root/project quota의 교집합.
- 계획 해시에 결합한 승인, 독립 signer, target별 적용·관측·복구.
- AI·인터넷·GitHub 장애와 분리된 기본 패킷 집행.
- 지원되지 않는 기능과 검증되지 않은 보장을 명시적으로 공개.

NAT, 동적 FQDN, XDP, inline IPS, HA와 벤더 쓰기는 별도 검수 단계다. 현재 자료는 아키텍처와 합성 계약 시험이며 production-ready 제품이 아니다.

## Documents

- [Architecture](docs/architecture.md)
- [Design decisions](docs/decisions.md)
- [License and distribution policy](LICENSE-POLICY.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Governance](GOVERNANCE.md)

이 링크는 공개 준비 파일의 매핑대로 실제 저장소를 구성한 뒤 사용한다. 임의의 다운로드 주소나 구현되지 않은 설치 명령은 제공하지 않는다.

## Implementation order

Start with the typed policy model, semantic reference evaluator, nftables compiler and isolated Linux network-namespace tests. Complete expiry, crash recovery, signed grants and replay prevention before enabling autonomous access requests. Promote each support profile only with reproducible test evidence.

## License

Original project contributions are licensed under the [Apache License 2.0](LICENSE), subject to their documented ownership and provenance. Third-party components retain their own licenses. See [NOTICE](NOTICE), [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and the licensing policy. This project is not affiliated with the vendors referenced in its design.

SPDX-License-Identifier: Apache-2.0
