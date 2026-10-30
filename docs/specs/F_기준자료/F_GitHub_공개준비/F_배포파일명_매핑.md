# 전달 파일과 GitHub 파일명 매핑

사용자 전달물은 `F_` 접두어를 유지한다. 실제 저장소에서는 GitHub와 도구가 인식하는 표준 이름으로 복사한다. 현재 작업은 파일 준비이며 원격 저장소 생성·푸시·공개·설정 변경을 수행하지 않았다.

| 전달 파일 | 실제 저장소 경로 | 적용 방법 |
|---|---|---|
| `F_README.md` | `README.md` | 실제 지원 상태와 아래 문서 경로를 확인한 뒤 복사 |
| `F_LICENSE.txt` | `LICENSE` | 공식 Apache-2.0 원문을 바이트 변경 없이 복사 |
| `F_NOTICE.txt` | `NOTICE` | 자체 자료의 귀속 범위를 확인한 후 복사. 외부 구성요소 고지는 실제 포함물에 맞춰 추가 |
| `F_SECURITY.md` | `SECURITY.md` | 비공개 제보 기능을 활성화·점검한 뒤 함께 적용 |
| `F_CONTRIBUTING.md` | `CONTRIBUTING.md` | DCO와 기여·검수 절차 적용 |
| `F_GOVERNANCE.md` | `GOVERNANCE.md` | 실제 유지보수자·독립 검토 가능 인원을 별도 기록 |
| 상위 폴더 `F_라이선스_및_GitHub_공개지침.md` | `LICENSE-POLICY.md` | 자체 제작분·eBPF·제3자 구성요소의 경계를 명시 |
| 상위 폴더 `F_오픈소스_방화벽_최종설계서.md` | `docs/architecture.md` | 공개 권리 확인 후 독립 설계 기준으로 복사 |
| 상위 폴더 `F_설계결정_및_통합근거.md` | `docs/decisions.md` | 원자료 명칭·검토 이력의 공개 필요성 확인 후 복사 |
| 상위 폴더 `F_제3자_고지.md` | `THIRD-PARTY-NOTICES.md` | 구성도·PDF를 배포하는 경우 고지 동봉, 실제 배포물 변경 시 갱신 |

표의 표준 이름은 실제 GitHub 적용 단계에서만 사용한다. 이번 최종 전달 파일의 이름을 바꾸라는 의미가 아니다.

## LICENSE 원문 출처

- 다운로드 URL: [Apache License 2.0 원문](https://www.apache.org/licenses/LICENSE-2.0.txt)
- 다운로드 기준일: 2026-10-30
- 파일은 공식 영어 원문이며 별도 조항을 삽입하지 않았다.
- 정확한 파일 해시는 최종 패키지 검증 결과에서 확인한다.

LICENSE 원문의 적용 예시 속 `[yyyy]`와 `[name of copyright owner]`는 공식 원문에 포함된 예시다. 이를 채우기 위해 LICENSE 원문을 수정하지 않는다. 실제 소스 파일에는 해당 파일의 권리자가 확인된 저작권 고지와 `SPDX-License-Identifier: Apache-2.0`을 별도로 넣는다.

## 공개 전에 실제로 설정할 사항

1. 최종 공개 파일만 새 저장소에 복사한다. 회사 과제 원문, 비교 작업의 임시 파일, 개인 경로, 운영 비밀은 제외한다.
2. 권리·라이선스와 실제 저작권자를 확인한다. 이 패키지의 일반 기여자 표기는 선행 자료의 소유권을 주장하지 않는다.
3. GitHub의 Private vulnerability reporting을 활성화하고 관리자 알림 수신을 점검한다. SECURITY 파일만으로 자동 활성화되지 않는다.
4. README에 현재 설계 단계와 미구현 기능을 표시한다. 실제 런타임을 배포할 때 지원 버전과 테스트 증거를 갱신한다.
5. 코드·이미지 배포 시 실제 포함물의 SBOM, 제3자 라이선스·NOTICE, 필요한 대응 소스, 서명·체크섬을 추가한다.

이 준비 파일에는 가짜 저장소 주소·보안 이메일·유지보수자 계정을 넣지 않았다. 실제 운영 채널을 정하고 검증한 뒤에만 추가한다.

근거: [GitHub 라이선스 파일 안내](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository), [비공개 제보 설정](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository), [ASF 자체 프로젝트 라이선스 적용](https://www.apache.org/foundation/license-faq.html).

SPDX-License-Identifier: Apache-2.0

