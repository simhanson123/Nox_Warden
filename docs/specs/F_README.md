# Open-source firewall — development specification

This repository contains the **F-2.0 implementation specification**, not a released firewall binary. The public project name is still being selected from the Warden family.

The intended product installs natively on Windows/Windows Server, macOS, and Linux. It shares an auditable policy and approval system, a multilingual dashboard, structured agent APIs, and platform-specific enforcement. Native releases, cloud VM deployment, CLI, and an installation skill are part of the implementation plan.

- Start with [the specification index](docs/specs/F_00_시작안내.md).
- Implement in [the task order](docs/specs/F_08_Codex_Cloud_작업계획.md).
- Read [platform requirements](docs/specs/F_09_멀티플랫폼_설치_집행_명세.md) and [cloud/hosting requirements](docs/specs/F_11_클라우드_호스팅_설치채널_명세.md).
- Follow [AGENTS.md](AGENTS.md) for repository work.

Original project work uses Apache-2.0. Third-party notices remain applicable. Optional usage telemetry defaults off; donations are voluntary. Product UI and core user journeys target English, Korean, Japanese, Spanish, Simplified Chinese, and Traditional Chinese. Specification prose is currently Korean; seed UI translations require language review before release.

한국어: 이 저장소는 개발 명세와 계약을 담습니다. 설계 검증 결과를 실제 방화벽·운영체제·클라우드 지원 인증으로 해석하지 마세요. 이전 Linux 중심 설계는 근거 자료로 보존하며 F-2.0의 멀티플랫폼 변경표가 우선합니다.
