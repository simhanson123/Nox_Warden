# 라이선스 및 GitHub 공개 지침

설계 기준판 1.0 | 2026-10-30 | 적용 대상: 통제형 오픈소스 방화벽 프로젝트

**최종 결정은 자체 작성한 사용자 공간 코어·API·SDK·UI·스키마와 새 프로젝트 문서의 기본 라이선스를 Apache License 2.0으로 통일하는 것이다.** 외부 코드, eBPF 모듈, 규칙, 모델, 데이터, 이미지·폰트에는 해당 구성요소의 조건을 따로 적용한다. 현재 결과물은 설계와 공개 준비 문서이며 실행 가능한 방화벽 제품, 실제 배포물의 라이선스 감사, GitHub 공개 완료를 의미하지 않는다.

## 1. Apache 2.0이 작성자를 보호하는 범위

Apache-2.0은 무보증·책임제한, 저작권·라이선스 고지 유지, 명시적 특허 허여를 제공한다. 다만 적용 법률이 요구하거나 별도 서면으로 약정한 책임에는 예외가 있다. 소프트웨어의 보안성·무중단·특정 용도 적합성을 보장하는 증명서도 아니다. [Apache License 2.0, §§2–9](https://www.apache.org/licenses/LICENSE-2.0)

| 항목 | 기대할 수 있는 효과 | 한계 |
|---|---|---|
| 저작권 | 라이선스 제공은 저작권 양도가 아니며, 관련 고지와 수정 사실을 보존하게 한다 | 다른 사람의 정당한 상업적 재사용을 막는 권한은 아니다 |
| 특허 | 기여자가 허락할 수 있는 일정 범위의 특허 청구항을 사용할 수 있게 한다 | 모든 제3자 특허의 무침해·분쟁 비용을 보장하지 않는다 |
| 특허 소송 | 해당 작업·기여에 대한 특허 침해 주장을 제기하면 정해진 특허 허락이 종료될 수 있다 | 모든 종류의 소송이나 책임에서 면제하지 않는다 |
| 제품 사고 | 무보증·책임제한 조건이 있다 | 강행 법률, 고의·중과실 등 법률상 예외, 별도 약정은 따로 고려한다 |
| 브랜드 | 상표 사용권을 일반적으로 허여하지 않는다 | 이름·로고의 실제 권리 확보와 별도 정책은 필요하다 |

위 표는 라이선스의 일반 구조를 설명한다. 개별 분쟁에서의 효력은 관할과 사실관계에 따라 다르다. 원문과 [ASF 특허·배포 FAQ](https://www.apache.org/foundation/license-faq.html)를 함께 확인한다.

**타인이 코드를 가져가 상업 제품·비공개 파생 제품에 사용하는 것을 막는 목적이라면 Apache-2.0은 그 목적에 맞지 않는다.** 수정 내용을 원 프로젝트에 돌려줄 의무도 일반적으로 요구하지 않는다. 이 프로젝트에서는 공개 개발과 도입 확대를 우선하고, 신뢰할 수 있는 릴리스·브랜드·지원·유지보수로 지속 가능성을 확보한다. [ASF FAQ: 수정·재배포](https://www.apache.org/foundation/license-faq.html)

개인 프로젝트가 Apache-2.0을 사용해도 Apache Software Foundation 소속·인증·법률 지원을 받는다는 뜻은 아니다. 이름에 Apache를 넣거나 공식 후원을 암시하지 않는다. [ASF FAQ: 자체 소프트웨어 적용 및 상표](https://www.apache.org/foundation/license-faq.html)

## 2. 라이선스 적용 경계

| 대상 | 최종 원칙 | 공개 시 증거 |
|---|---|---|
| 자체 사용자 공간 코어·CLI·API·SDK·UI | Apache-2.0 | 파일별 SPDX 식별자, 기여 이력, 루트 LICENSE |
| 자체 작성 스키마·정책 예제·새 문서 | Apache-2.0 | 제3자 자료의 원 조건을 별도 표시 |
| 외부 라이브러리·복사한 코드 | 각 원 라이선스 | 버전·소스·해시·LICENSE·NOTICE·수정 내역 |
| Linux·nftables·Suricata 등 별도 프로그램 | 원 라이선스 유지 | 실제 배포 여부와 대응 소스 제공 방법 |
| eBPF/XDP 모듈 | 프로그램 타입·helper에 맞는 GPL 호환성 별도 결정 | 소스 SPDX, 로더 license, helper·kfunc 목록 |
| Grafana·기타 외부 서비스 | 서비스별 라이선스 및 약관 | 사용 에디션·수정·결합·배포 형태 |
| 모델 가중치·토크나이저·데이터·규칙 피드 | 코드와 독립적으로 확인 | 개별 자산의 권리·재배포·수정 조건 |
| 이름·로고·상표 | 소프트웨어 라이선스와 별도 | 권리자 확인과 상표 사용 정책 |

Apache-2.0 영어 원문을 수정하지 않는다. 비상업적 이용 제한, 경쟁사 사용 금지, 책임의 무조건 전가 등을 덧붙여 놓고 Apache-2.0이라고 표시하지 않는다. 번역은 설명용이며 원문을 대체하지 않는다. [ASF FAQ: 라이선스 수정·번역](https://www.apache.org/foundation/license-faq.html)

## 3. 방화벽 의존성과 배포 방식

### 3.1 Linux와 nftables

Linux 커널은 GPL-2.0-only와 명시적 syscall 예외를 사용한다. Linux 위에서 실행하는 독립 사용자 공간 프로그램이라는 사실만으로 자체 코어가 GPL이 되는 것은 아니다. 반대로 커널을 포함한 VM·어플라이언스를 배포하면 커널 자체의 배포 의무는 남는다. [Linux kernel licensing rules](https://www.kernel.org/doc/html/latest/process/license-rules.html)

nftables는 공식 문서에서 GPLv2로 안내한다. v1은 `nft`를 **고정 실행파일과 분리된 인자 배열로 실행하는 외부 프로세스 방식**으로 한다. 셸 명령 문자열을 조립하지 않는다. `libnftables`를 코어에 직접 정적·동적 링크하거나 FFI로 연결하는 것은 다른 결합 방식이므로 v1에서 제외하고, 도입 전 별도 ADR와 라이선스 검토를 요구한다. 고수준 `libnftables`와 저수준 `libnftnl`도 구분한다. [nftables 공식 manpage](https://www.netfilter.org/projects/nftables/manpage.html), [Netfilter 라이선스 안내](https://www.nftables.org/licensing.html)

Apache-2.0과 GPLv2-only의 직접 결합에는 호환성 문제가 있다. GPLv3와의 호환성은 결합물 전체를 Apache-2.0만으로 배포해도 된다는 뜻이 아니다. [ASF GPL 호환성 설명](https://www.apache.org/licenses/GPL-compatibility.html)

CLI·소켓·컨테이너 분리는 독립 프로그램이라는 판단에 도움을 주지만 자동 면제 규칙이 아니다. 공유하는 내부 구조와 통신의 결합 정도도 고려해야 한다. **프로세스 분리와 재배포 의무 이행을 별개로 검토한다.** [GNU GPLv2 FAQ: mere aggregation](https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.en.html#MereAggregation)

### 3.2 eBPF/XDP

Linux 공식 문서는 GPL-only helper, kfunc 및 일부 프로그램 타입에 GPL 호환 라이선스가 필요하다고 설명한다. Rust/Aya로 작성해도 이 요구는 동일하게 검토한다. [BPF licensing](https://docs.kernel.org/bpf/bpf_licensing.html)

eBPF는 후속 독립 모듈로 개발한다. 실제 프로그램 타입·helper·가져온 소스를 확정하고 소스 라이선스와 로더 선언을 일치시킨다. 직접 작성한 코드에 GPL 호환 선택지를 두는 방식을 검토할 수 있지만, 제3자 코드까지 임의로 재라이선스하지 않는다. 로더 문자열만 GPL로 선언하는 것은 적합성 검토의 대체가 아니다.

### 3.3 Suricata·탐지 규칙

Suricata는 GPLv2이며 수정·라이브러리 결합·재배포에 따른 조건이 있다. 기본 연동은 독립 프로세스의 EVE JSON을 읽는 방식으로 한다. 엔진 코드 수정·링크 또는 자체 이미지 번들은 별도 배포 검토 대상이다. [Suricata 라이선스 안내](https://suricata.io/features/open-source/), [OISF GPL FAQ](https://suricata.io/gpl-faqs/)

엔진과 탐지 규칙의 라이선스는 별개다. ET·Sigma·커뮤니티·상용 규칙의 이름만으로 재배포를 승인하지 않는다. 기본 배포에는 프로젝트가 권리를 가진 실습 규칙만 넣고 외부 피드는 이용자가 승인한 소스에서 선택한다. 각 규칙 번들의 출처·버전·수정·상업 이용·재배포·구독 조건을 기록한다.

### 3.4 관측·비밀관리·자산관리

Grafana의 핵심 오픈소스 프로젝트는 AGPLv3로 전환됐다. 정확한 에디션과 버전의 LICENSE를 확인한다. 수정된 AGPL 프로그램을 네트워크로 이용시키는 경우에는 §13의 소스 제공 기회 요건을 검토한다. 단순 API 이용만으로 자체 코어가 무조건 AGPL이 된다고 하거나, 별도 컨테이너라는 이유로 항상 무관하다고 단정하지 않는다. [Grafana licensing](https://grafana.com/licensing/), [Grafana LICENSE](https://raw.githubusercontent.com/grafana/grafana/main/LICENSE)

OpenBao는 MPL-2.0, NetBox core는 Apache-2.0로 확인된다. 같은 브랜드의 플러그인·상용 애드온까지 조건이 같다고 추정하지 않는다. [OpenBao LICENSE](https://raw.githubusercontent.com/openbao/openbao/main/LICENSE), [NetBox LICENSE](https://github.com/netbox-community/netbox/blob/main/LICENSE.txt)

나머지 Rust·UI·DB·검증 라이브러리는 실제 lockfile과 릴리스 파일에서 버전·전이 의존성·라이선스를 확정한다. 설계에 등장한 선택적 연동을 이미 포함된 의존성이나 검증 완료 지원으로 표시하지 않는다.

### 3.5 AI 모델·외부 API

모델 실행 코드, 기반 모델, 가중치, 토크나이저, 학습·평가 데이터, 상용 API 약관은 별도 승인 단위다. 예를 들어 Laya 저장소의 Apache-2.0 표시는 코드에 대한 확인 근거이지 임의의 파생 가중치와 데이터 전체에 대한 승인 증거가 아니다. [Laya LICENSE](https://github.com/NandhaKishorM/laya/blob/main/LICENSE)

초기 저장소·배포 이미지에는 외부 가중치와 유료 SDK를 넣지 않는다. 선택 다운로드도 출처와 조건을 표시하며 계정·구독·접근 제한을 우회하지 않는다. 모델 선택과 데이터 송신 허가는 운영 정책으로 따로 관리한다.

## 4. 배포물별 필요한 자료

| 배포물 | 추가 확인 사항 |
|---|---|
| 자체 소스 저장소 | 파일 출처·SPDX·LICENSE·기여 권리·복사한 코드·문서 자산 |
| 자체 바이너리 | 정적·동적 링크한 라이브러리, 생성 코드, 포함 UI·폰트·Wasm |
| 컨테이너 | 모든 레이어의 OS 패키지와 도구·런타임·모델·규칙 |
| VM·어플라이언스 | 커널·부트 구성·드라이버·펌웨어·배포판 패치까지 포함 |
| 플러그인·규칙·모델 번들 | 각 번들의 원문·고지·재배포 권한·라이선스 호환성 |

GPL 등이 요구하는 대응 소스에는 정확한 바이너리 버전의 소스와 해당 빌드·설치에 필요한 스크립트가 포함될 수 있다. 실제 배포에 맞는 제공 방식을 선택하고 릴리스에서 접근 가능하게 유지한다. 단순 upstream 홈페이지 링크 하나로 의무 이행을 완료했다고 처리하지 않는다. [Netfilter 배포 안내](https://www.nftables.org/licensing.html)

릴리스 manifest의 필수 필드는 `component_kind`, `source_url`, `version_or_revision`, `sha256`, `license_expression`, `license_text_path`, `copyright_notice`, `redistribution_allowed`, `modification_conditions`, `source_delivery`, `reviewer`, `reviewed_at`다. SBOM·스캔 결과는 증거이며 법률 검토의 자동 대체가 아니다.

## 5. 원자료와 개인·회사 권리

현재 작업 자료가 채용 사전과제와 관련된 폴더에 있다는 사실만으로 공개 권한의 유무를 확정할 수 없다. **새 GitHub 저장소는 최종 독립 설계와 프로젝트가 권리를 가진 파일만 허용 목록으로 옮긴다. 작업 폴더 전체를 저장소에 올리지 않는다.**

공개 전 다음을 확인하고 `확인자·일자·근거·허용 파일`을 기록한다.

1. 회사가 제공한 과제 원문·안내 PDF·슬라이드·이미지·로고를 재배포할 권리가 있는가. 권리가 확인되지 않으면 포함하지 않는다.
2. 제출·채용·고용·외주 계약에 비밀유지 또는 지식재산 귀속 약정이 있는가. 이 문서만으로 해당 약정의 존재나 효력을 판단하지 않는다.
3. 실제 내부 주소·호스트명·조직도·네트워크 설정·로그·개인정보·토큰·인증서가 남아 있는가. 예제는 가상 데이터로 바꾼다.
4. 외부 코드·표·그림·긴 문서 인용을 복사했는가. 출처와 원 라이선스가 허용하는 범위를 확인한다.
5. 기존 문서의 CC BY 등 표기가 실제 권리자의 결정인가. 기존에 유효하게 적용된 타인 라이선스를 새 LICENSE로 덮어쓰지 않는다.
6. 본인이 검토·작성한 기여와 AI 보조로 생성된 부분의 출처를 추적할 수 있는가. AI 생성이라는 이유로 제3자 권리 검사를 면제하지 않는다.

본 최종본의 라이선스 결정은 권리를 가진 자체 작성분에 대한 것이다. 선행 자료 전체의 저작권을 프로젝트가 소유한다고 주장하지 않는다. 개별 계약·권리·책임의 판단이 필요한 부분은 실제 사실관계를 확보한 뒤 법률 전문가에게 확인한다.

## 6. 기여와 거버넌스

초기 기여는 DCO 1.1과 `Signed-off-by`로 받는다. DCO는 제출 권리와 출처에 대한 기여자의 진술이며 저작권 양도가 아니다. 공개된 sign-off의 개인정보가 기여 이력에 남을 수 있음을 알린다. [DCO 1.1](https://developercertificate.org/)

Apache-2.0을 선택했다고 CLA가 자동으로 필수인 것은 아니다. 기업 기여·기존 코드 기증·향후 재라이선싱처럼 별도 약정이 필요한 때 검토한다. ASF 내부의 CLA 절차를 이 프로젝트의 의무로 복사하지 않는다. [ASF Contributor Agreements](https://www.apache.org/licenses/contributor-agreements.html)

초기 관리자는 저장소 소유자가 지정한다. 실제로 없는 검토자·보안팀·지원 인력을 기재하지 않는다. 1인 단계의 자기 검토를 독립 검토로 표시하지 않고, 인원이 확보되면 권한·배포·서명 경계 변경에 별도 검토자를 지정한다. 세부 절차는 함께 제공한 기여·거버넌스 문서에 따른다.

## 7. GitHub 적용 순서

1. 별도 저장소에 허용한 최종 자료만 복사한다. 원본·임시 파일·개인 경로·회사 과제 파일·실제 운영 증적을 제외한다.
2. `F_GitHub_공개준비/F_배포파일명_매핑.md`대로 LICENSE·NOTICE·SECURITY·CONTRIBUTING·GOVERNANCE를 표준 이름으로 배치한다. 전달물의 `F_` 접두어와 실제 GitHub 인식 이름을 구분한다.
3. 실제 권리자와 파일 범위를 확인하고, 파일별 SPDX와 필요한 제3자 고지를 정리한다. `F_NOTICE.txt`의 일반 기여자 표기를 근거 없는 실명·회사 소유권 주장으로 바꾸지 않는다.
4. 기본 브랜치 보호·최소 토큰 권한·비밀 검사·필요한 검수 작업을 설정한다. 코드가 아직 없으면 존재하지 않는 빌드 성공 배지를 넣지 않는다.
5. 비공개 취약점 제보 기능을 활성화하고 수신 경로를 점검한다. SECURITY 파일만 넣어서는 기능이 활성화되지 않는다. [GitHub 설정 안내](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
6. README에 `설계 단계`, 구현 범위, 지원·미지원 기능, 검증 범위, 라이선스 경계를 공개한다. 제품 출시 시에는 이 상태를 실제 테스트 결과에 맞춰 갱신한다.
7. 코드·이미지를 배포하기 전 실제 포함물의 SBOM·고지·대응 소스·provenance·서명·체크섬을 함께 검수한다.

GitHub 공개 저장소라는 사실만으로 재사용 조건이 정해지는 것은 아니다. 루트의 표준 LICENSE와 명확한 범위 설명을 제공한다. [GitHub: Licensing a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)

## 8. 공개 중단 조건과 남은 확인

다음이 발견되면 해당 파일·배포물을 공개 후보에서 제외하고 해결한다: 권리·출처 불명, 무단 회사 자료·개인정보·비밀 포함, Apache-only와 GPLv2-only의 미해결 직접 결합, eBPF source/license 불일치, 외부 모델·규칙·SDK의 무단 번들, 필요한 소스·고지 제공 불가.

현재 확인된 것은 공식 라이선스의 일반 구조와 이 설계의 공개 정책이다. **실제 소스 저장소의 전체 의존성, 배포 바이너리·이미지, 회사 계약, 이름·로고의 권리, 개별 관할의 면책 효력은 아직 검증된 사실이 아니다.** 이 자료를 배포 적합성 인증이나 법률 의견서로 표시하지 않는다.

