# Node2Shell (CVE-2026-111497) 격리 재현

> [!CAUTION]
> **이 자료는 보안 연구, 교육 및 방어 검증 목적으로만 사용해 주세요.**
>
> 본인이 소유하거나 명시적으로 허가받은 격리 환경에서만 실행해 주세요. 제3자
> 시스템에 대한 접근, 서비스 중단, 데이터 수집, 지속성 확보 또는 탐지 회피에
> 사용해서는 안 됩니다.

Node.js에 포함된 Brotli 디코더의 out-of-bounds write인
CVE-2026-111497을 WSL Ubuntu 24.04의 로컬 Docker 환경에서 검증한 기록이다.
외부 대상이나 임의 명령을 받지 않는다. RCE 증명은 고정된 `/n2s`의 프로세스별
nonce와 `/usr/bin/id`, 또는 fresh loopback callback token과 고정
`/usr/bin/id` 결과로만 수행한다.

## 결과

2026-10-23 기준 Node.js 공식 배포 목록에 존재하는 영향 범위 내의 모든
`linux-x64` 릴리스에서 RCE를 확인했다. Express direct-overwrite 검증뿐 아니라
ASLR을 켠 worker-heap 경로도 전 릴리스에서 검증했다.

| 계열 | 확인한 정확한 범위 | 공식 릴리스 수 | RCE 확인 |
| --- | --- | ---: | ---: |
| 22.x | `22.0.0`–`22.23.3` | 36 | 36/36 |
| 24.x | `24.0.0`–`24.22.0` | 30 | 30/30 |
| 26.x | `26.0.0`–`26.12.0` | 18 | 18/18 |
| 합계 | 공식 영향 범위의 Linux x86-64 릴리스 | **84** | **84/84** |

전체 집계는 [evidence/matrix/summary.json](evidence/matrix/summary.json), 각 버전의
아카이브 SHA-256·Node 바이너리 SHA-256·런타임 보정값·시도별 결과·nonce와
`id` 증거는 `evidence/matrix/<version>.json`에 기록했다. 대응하는 정확한
바이너리 프로필은 `poc/profiles/<version>.json`에 있다.

ASLR을 켜고 GDB나 런타임 주소 읽기 없이 수행한 별도 매트릭스도 같은 공식
84개 릴리스에서 **84/84**를 확인했다. 전체 집계는
[evidence/aslr-on-network-only/summary.json](evidence/aslr-on-network-only/summary.json),
버전별 증거는 `evidence/aslr-on-network-only/<version>.json`에 있다.

| 검증 모드 | ASLR | 결과 | 의미 |
| --- | --- | ---: | --- |
| 결정적 direct-overwrite matrix | 꺼짐 | 84/84 | 프로필의 저장 프레임 덮기와 전체 ROP를 그대로 실행 |
| worker-heap network-only matrix | 켜짐 (`randomize_va_space=2`) | **84/84** | GDB·주소 읽기·`LD_PRELOAD` 없이 loopback 입력만으로 고정 `id` callback 확인 |
| same-request debugger-steered matrix | 켜짐 (`randomize_va_space=2`) | 84/84 | 개발 이력: 현재 요청의 링·프레임을 GDB로 읽어 direct ROP 체인을 검증 |

worker-heap 결과는 취약한 Brotli ring과 같은 worker arena 안의 glibc tcache entry
사이에 일정한 상대 거리를 사용한다. 공식 Node 바이너리는 non-PIE이므로 ICU
allocator hook, libuv callback thunk와 `execvp@plt`는 각 바이너리의 정적 심볼에서
산출한다. 실행 중 `/proc`, debugger, core dump 또는 메모리 주소 누출은 사용하지
않는다. 다만 이는 아래의 정확한 앱·allocator 배치에 대한 검증이며, 임의의 원격
Node 애플리케이션에 보편적으로 적용되는 ASLR 우회를 주장하는 것은 아니다.

기존 `evidence/aslr-on-debugger-steered/` 기록은 direct ROP 체인의 개발 이력으로
남겨 두었다. 그 결과는 GDB 보조이며 network-only 결과와 혼동해서는 안 된다.
초기 단일 버전 상대 피벗 기록도
[evidence/aslr-on-network-only-24.22.0.json](evidence/aslr-on-network-only-24.22.0.json)에
그대로 보존했다.

이 84/84 결과의 범위는 다음 조건으로 한정된다.

- Node.js 공식 `node-v<version>-linux-x64.tar.xz` 바이너리
- Express `5.3.0`, body-parser `2.4.0`, Debian bookworm 사용자 공간
- ASLR network-only 매트릭스는 worker-per-connection, built-in `node:zlib`,
  독립 record allocation과 `Intl.DateTimeFormat`을 사용하는 번들 실험 앱
- `UV_THREADPOOL_SIZE=1`
- direct-overwrite 매트릭스는 ASLR을 끈 재현 전용 컨테이너와 버전별 GDB 보정
- network-only 매트릭스는 `N2S_DISABLE_ASLR` 없이 `randomize_va_space=2`를
  유지하고 GDB·주소 읽기·`LD_PRELOAD`를 사용하지 않음
- worker heap 후보는 22.x의 두 ring 거리와 0x220/0x250 record, 24.x의
  0x330/0x200 record, 26.x의 0x200 record로 제한
- loopback의 `127.0.0.1:3000`만 사용하는 고정 실험 앱

따라서 다른 운영체제, CPU 아키텍처 또는 배포판 재빌드에 그대로 일반화한 결과는
아니다. ASLR-off 결과는 공식 바이너리별 direct ROP를 결정적으로 검증하기 위한
것이고, network-only 결과는 위 worker heap 배치에 한정된다.

## 공식 취약 버전 범위

Node.js 공식 권고는 CVE-2026-111497이 22.x, 24.x, 26.x에 영향을 준다고 명시하고
다음 보안 릴리스를 제공한다.

| Node.js 계열 | 영향받는 범위 | 최초 수정 버전 |
| --- | --- | --- |
| 22.x | `22.0.0` 이상 `22.23.4` 미만 | `22.23.4` |
| 24.x | `24.0.0` 이상 `24.22.1` 미만 | `24.22.1` |
| 26.x | `26.0.0` 이상 `26.12.1` 미만 | `26.12.1` |

위의 84개는 이 범위와 Node.js 공식 배포 인덱스에서 `linux-x64` 아카이브가 있는
릴리스를 교차해 산출했다. 지원 종료 계열이나 제3자 빌드는 번들된 Brotli와
백포트 상태를 별도로 확인해야 한다. 수정 버전 음성 대조군으로는 `24.22.1`에 같은
입력을 보냈으며, 디코더가 `ERR__ERROR_FORMAT_BLOCK_SWITCH`로 거부하고 같은
서버 프로세스가 계속 정상 동작하는 것을 확인했다.

## RCE 판정 방식

direct-overwrite 실험에서 컨테이너의 각 Node 프로세스는 시작할 때 128비트 nonce를
만들고 `/health`에 노출한다. 체인은 명령 문자열을 입력받지 않고 고정된 `/n2s`만
실행한다. `/n2s`는 같은 nonce와 `/usr/bin/id` 출력을 exploit된 HTTP 요청
소켓으로 보낸다.

다음 두 조건이 동시에 충족될 때만 `rce-verified`로 기록한다.

1. 응답의 `N2S-PROOF:<nonce>`가 공격 직전 `/health`에서 읽은 현재 프로세스
   nonce와 정확히 일치한다.
2. 같은 응답에 새 `/usr/bin/id` 출력이 존재한다.

크래시, 무응답, 이전 프로세스의 출력, nonce만 있는 응답 및 `id`만 있는 응답은
모두 실패다. 역방향 셸, 파일 생성·삭제, 권한 상승, 자격 증명 접근 및 외부 시스템
접속은 수행하지 않았다.

worker-heap 실험은 공격 직전에 fresh 128비트 token과 `127.0.0.1:4444` listener를
만든다. payload에 내장된 고정 `/bin/bash -c` 문자열은 그 token과
`/usr/bin/id` 결과만 해당 loopback listener로 보낸다. 정확한 token 뒤에 완전한
`uid=`/`gid=` 출력이 도착할 때만 성공으로 판정한다. callback 주소·포트·명령은
CLI로 바꿀 수 없다.

## 기존 공개 PoC 대비 개선점

이 저장소는 `SOURCE_LOCK.json`에 고정한 공개 PoC의 trigger와 worker-heap
시나리오를 검토한 뒤, 외부 대상·임의 명령 인터페이스를 제거하고 별도 하네스로
재구성했다. 정확한 버전 식별, 안전한 증명, 재현성 및 오탐 방지에 초점을 맞췄다.

| 항목 | 기존 Express PoC | 이 저장소의 통합 v4 하네스 |
| --- | --- | --- |
| 검증 범위 | 소수의 고정 프로필 | 공식 영향 Linux x64 릴리스 84개 전부 |
| 성공 증거 | `id` 출력 관찰 | 현재 프로세스 nonce + 새 `id` 출력 동시 검증 |
| 실행 대상 | loopback 제한 | `127.0.0.1:3000`으로 코드에 고정 |
| 실행 프로그램 | 고정 `id` | 고정 `/n2s`; 임의 명령·경로 인수 없음 |
| 바이너리 확인 | 개별 프로필 지문 | 공식 SHASUMS256와 추출 바이너리 SHA-256 모두 확인 |
| 주소·FD 처리 | 고정 값 또는 추측 | 버전별 GDB 보정과 요청 socket FD 자동 탐지 |
| ASLR 결과 구분 | 조건이 불명확할 수 있음 | ASLR-off, debugger-steered, network-only 증거를 별도 보관 |
| heap 체인 | 단일 고정 Node/allocator 프로필 | 정적 심볼 자동 추출 + 소수의 allowlisted 상대 layout 후보 |
| 실패 판정 | 출력 미관찰 | 크래시·무응답·부분 증거·누락 증거를 분리 기록 |
| 격리 | 기본 컨테이너 | read-only rootfs, capability 제거, no-new-privileges, 리소스 제한 |

exploit 로직도 바이너리 차이를 흡수하도록 다음과 같이 바꿨다.

- saved RIP만 직접 덮는 기존 pivot 대신 saved RBP와 saved RIP의 16바이트 쌍을
  제어하고 `leave; ret`으로 링 버퍼에 pivot한다. 초기 22.x에서 두 번째 포인터가
  1 KiB 물리 링 끝을 넘던 문제를 피한다.
- Node 버전에 따라 달라지는 Brotli fast-copy의 source/destination 레지스터 형태를
  정적 분석기가 식별한다.
- `leave; ret`, `pop` 계열, `add rax, 0x90`, 메모리 저장, `execvp` 호출 기반,
  BSS scratch를 공식 바이너리에서 직접 찾는다.
- 런타임에서 링 주소, copy source/destination, saved frame 위치와 첫 빈 FD를
  보정하고, 제어 prefix·bootstrap·ROP·증명 문자열이 겹치지 않는 배치를 고른다.
- Node 26에서 return 전에 RSI가 초기화되는 차이는 링에서 RAX 기반 주소를 다시
  구성하는 bootstrap으로 처리한다.
- ASLR-on worker 경로는 ICU `pFree`/`pContext`의 순서와 정렬을 심볼에서 산출하고,
  `align_down(min(pFree,pContext), 16)` 기준으로 payload 내부 offset을 생성한다.
- Brotli 출력 buffer는 0x330으로 유지하면서 후속 record 크기만 분리해, 릴리스별로
  자연스럽게 채워진 tcache bin을 선택한다. 22.x의 ring-layout 전환도 후보 순서에
  반영한다.

이 개선으로 22.x의 여러 source offset과 FD 19/22 전환, 24.x의 prefix 겹침,
26.x의 레지스터 상태 및 빌드별 stack 위치 차이를 하나의 체인으로 처리했다.

## 재현 방법

WSL Ubuntu에서 Docker, Python 3, binutils가 필요하다. GDB는 과거
debugger-steered/direct 개발 검증을 다시 실행할 때만 필요하다. 먼저 고정된 기본
실험 이미지를 만든다.

```bash
docker build --platform linux/amd64 \
  -t node2shell-nonce-local:matrix \
  -f lab/express-nonce-proof/Dockerfile \
  lab/express-nonce-proof
```

단일 버전(`24.22.0`)과 수정 대조군(`24.22.1`)은 다음처럼 실행한다. 스크립트는
정확한 Node 바이너리 해시를 검사하고 컨테이너를 종료 시 제거한다.

```bash
chmod +x lab/run.sh
./lab/run.sh vulnerable
./lab/run.sh patched
```

전체 공식 범위 또는 특정 버전은 matrix runner로 검증한다. Docker daemon과 다른
경로를 사용하면 `N2S_DOCKER`, 임시 작업 경로를 바꾸려면
`N2S_MATRIX_WORKDIR` 환경 변수를 사용할 수 있다.

```bash
sudo -E python3 tools/verify_release_matrix.py
sudo -E python3 tools/verify_release_matrix.py --version 22.0.0 --include-verified
sudo -E python3 tools/verify_release_matrix.py --aslr debugger-steered
```

ASLR을 켠 network-only worker-heap 매트릭스는 다음과 같다. 이 runner는 GDB를
실행하지 않으며 `/proc/<pid>/maps` 같은 런타임 주소도 읽지 않는다.

```bash
sudo -E python3 tools/verify_aslr_network_matrix.py
sudo -E python3 tools/verify_aslr_network_matrix.py \
  --version 22.0.0 --include-verified
```

공식 아카이브와 `SHASUMS256.txt`를 확인하고, 바이너리 정적 심볼에서 프로필을
생성한 뒤 read-only Docker에서 각 layout을 기본 두 번까지 시도한다. 결과는
`evidence/aslr-on-network-only/<version>.json`에 기록한다.

runner는 공식 배포 인덱스와 각 릴리스의 `SHASUMS256.txt`를 받고, 해당 버전의
`bin/node`만 임시로 추출한다. 정적 프로필 생성, 읽기 전용 GDB 보정, 격리 Docker
검증 뒤 임시 바이너리는 삭제하고 프로필과 JSON 증거만 남긴다. 이미
`rce-verified`인 버전은 기본적으로 건너뛴다.

`--aslr debugger-steered`는 ASLR을 끄는 환경 변수를 넣지 않는다. GDB가 현재
요청의 취약 저장 지점에서 링과 저장 프레임을 관찰하고, v4 체인이 만들 반환
상태로 전환한 뒤 분리된다. 따라서 이 모드는 방어 검증과 버전 회귀 확인용이며,
ASLR 우회 PoC로 해석해서는 안 된다.

단위 테스트는 다음과 같다.

```bash
python3 -m unittest discover -s tests -v
```

## 저장소 구성

- `poc/node2shell_lab.py`: loopback 전용 payload 생성과 엄격한 proof 판정
- `tools/profile_node_binary.py`: 공식 Node 바이너리의 가젯·copy 형태 정적 분석
- `tools/verify_release_matrix.py`: 공식 범위 산출, 해시 검증, 보정 및 84개 matrix 실행
- `poc/node2shell_heap.py`: loopback·고정 `id` 전용 ASLR-on worker-heap 체인
- `tools/verify_aslr_network_matrix.py`: GDB 없는 공식 84개 ASLR 매트릭스 실행기
- `poc/profiles/`: 버전별 통합 v4 프로필 84개
- `evidence/matrix/`: 버전별 검증 증거와 전체 요약
- `evidence/aslr-on-debugger-steered/`: ASLR 활성·GDB 보조 버전별 증거와 전체 요약
- `evidence/aslr-on-network-only/`: ASLR 활성·GDB 없는 버전별 증거와 전체 요약
- `lab/express-nonce-proof/`: Express 앱, 고정 `/n2s`, 감독 루프와 Dockerfile
- `lab/worker-record-transform/`: worker/zlib/record/ICU heap 실험 앱
- `lab/run.sh`: `24.22.0` 취약/`24.22.1` 수정 대조군 실행기

## 출처

- [Node.js 2026년 10월 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Node.js 공식 배포 인덱스](https://nodejs.org/dist/index.json)
- [Imperva의 Node2Shell RCE 분석](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- [검토한 공개 PoC](https://github.com/dimasma0305/CVE-2026-111497-POC/tree/e3382551df02b3ac8c925aeeffb9e0d206f052d4)
- [upstream Brotli 수정](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)

초기 단일 버전 재현 기록은
[evidence/2026-10-23-wsl-docker.txt](evidence/2026-10-23-wsl-docker.txt), 강화된
nonce 판정 기록은
[evidence/2026-10-23-nonce-proof.txt](evidence/2026-10-23-nonce-proof.txt)에
보존했다.
