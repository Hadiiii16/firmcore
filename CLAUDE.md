# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 개요

FirmCore는 펌웨어 이미지를 업로드하면 자동으로 rootfs를 추출하고, SBOM을 생성하며, CVE를 탐지하고, Gemini CLI를 이용한 정적 분석으로 VEX(Vulnerability Exploitability eXchange) 판정을 수행하는 플랫폼입니다.

## 실행 명령

```bash
# 전체 서버 시작 (백엔드 :8080 + 프론트엔드 :5173)
./start.sh

# 옵션
./start.sh --mock           # MOCK 모드 (binwalk/grype/Gemini 없이 더미 데이터)
./start.sh --backend-only
./start.sh --frontend-only

# 백엔드 단독 실행 (개발)
cd backend
source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# 프론트엔드 단독 실행 (개발)
cd frontend
npm run dev

# TypeScript 타입 검사 (테스트 대용)
cd frontend && npx tsc --noEmit

# Python 문법 검사
python3 -c "import ast; ast.parse(open('backend/pipeline/vex.py').read())"
```

## 아키텍처

### 파이프라인 흐름

```
펌웨어 업로드
    → [1] extracting      binwalk -e -M → rootfs 탐지 (squashfs / UBI / JFFS2 자동)
    → [2] sbom_generating sbom_claude_scripts (syft 기반) → CycloneDX SBOM
    → [3] scanning        grype → scan.json (CVE 목록)
    → [4] vex_analyzing   Gemini CLI --yolo (PTY) → OpenVEX JSON + 분석 보고서
```

각 단계는 `backend/pipeline/runner.py`의 `run_pipeline()`이 순차 실행합니다. FastAPI `BackgroundTasks`로 비동기 실행되며, 단계별 진행 이벤트는 `event_bus.py`를 통해 SSE로 프론트엔드에 스트리밍됩니다.

### SSE 이벤트 전달 구조

```
pipeline/runner.py  →  event_bus.broadcast()  →  인메모리 Queue
                                                         ↓
GET /api/jobs/{id}/stream  ←  DB 폴링 (after_id 기반 중복 방지)  ←  Queue 알림 수신
```

이벤트 본문은 항상 `job_events` DB 테이블이 source of truth입니다. `event_bus`는 "새 이벤트가 있으니 DB를 읽어라"는 신호 역할만 합니다. SSE 재연결 시 `after_id` 파라미터로 중복 없이 이어받습니다.

### VEX 분석 엔진 (`backend/pipeline/vex.py`)

Gemini CLI를 `--yolo` + `cwd=rootfs_path`로 **PTY(pseudo-terminal) 방식**으로 실행합니다. `--output-format` 플래그 없이 일반 텍스트 출력으로 동작하며 수동 실행과 완전히 동일하게 동작합니다.

```python
# PTY 실행 방식 (stream_gemini_yolo 내부)
master_fd, slave_fd = pty.openpty()
proc = await asyncio.create_subprocess_exec(
    *args, cwd=rootfs_path, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
    env=env,                    # ★ TERM 등 명시 주입 (아래 설명)
    preexec_fn=os.setsid,  # 새 프로세스 그룹 생성
)
# asyncio.connect_read_pipe()로 master_fd를 비동기 StreamReader에 연결
```

**PTY 만으로는 부족 — TERM 을 반드시 주입해야 함**: Gemini CLI 는 Ink(React-for-CLI) 기반이고, Ink 는 rich 박스 렌더링을 켜기 위해 `isatty(stdout)` 뿐 아니라 유효한 `TERM` 값을 요구합니다. `start.sh` 의 `BACKEND_ENV` 에는 `TERM` 이 없기 때문에 uvicorn 에서 상속된 환경을 그대로 쓰면 Ink 가 plain text 폴백으로 떨어져 박스(`╭│╰`) 가 전혀 출력되지 않고, Shell 도구 **결과**가 우리 로그에 실시간으로 잡히지 않습니다. 그래서 `_launch_gemini_pty` 는 subprocess 환경을 다음과 같이 구성합니다:

```python
env = os.environ.copy()
if not env.get("TERM") or env["TERM"] == "dumb":
    env["TERM"] = "xterm-256color"
env.setdefault("COLORTERM", "truecolor")
env.setdefault("FORCE_COLOR", "1")
for ci_var in ("CI", "GITHUB_ACTIONS", "BUILDKITE"):
    env.pop(ci_var, None)  # non-interactive 모드로 오판하는 것 방지
```

**두 번째 함정 — bash 래퍼의 stdin 리다이렉트**: `_gemini_process_args` 는 시그널 트랩을 걸기 위해 `bash -c 'trap ...; "$@" <&0 & wait'` 로 감쌉니다. 여기서 **`<&0` 은 절대 생략하면 안 됩니다**. `bash -c` 는 job control 이 꺼진 상태로 실행되는데, 이 때 `&` 로 백그라운드 실행되는 명령의 stdin 은 bash 가 자동으로 `/dev/null` 로 리다이렉트합니다(POSIX 명세). 그러면 PTY slave 를 stdin 으로 붙여 줘도 gemini 입장에서는 `process.stdin.isTTY === false` 가 되고, Ink 가 다시 plain text 모드로 떨어져 박스가 안 나옵니다. `<&0` 은 부모에게서 상속받은 fd 0(=PTY slave)을 명시적으로 유지시켜 이 리다이렉트를 무력화합니다. 실측: `<&0` 없으면 PTY 로그 3.6KB plain text, 붙이면 53KB + 박스 + ANSI.

Gemini가 내장 Shell 도구로 `find`, `nm`, `readelf`, `strings`, `grep` 등을 **직접** rootfs에서 실행하며 3단계 도달성 분석을 수행합니다:

1. **Library Level** — 취약 함수/심볼이 라이브러리에 존재하는가
2. **Binary Level** — ELF 바이너리 중 해당 함수를 호출/링크하는 것이 있는가
3. **Config Level** — 런타임에 실제로 활성화되는가

`~/.gemini/GEMINI.md`가 전역 시스템 프롬프트로 자동 로드됩니다 (gemini CLI의 프로젝트 컨텍스트 기능). **`@filepath` 구문은 CLI 인자에서는 작동하지 않고 대화형 입력에서만 작동**하므로 프롬프트 파일 내용을 직접 삽입하는 방식을 사용하지 않습니다.

#### PTY 출력 스트리밍 (pyte 가상 터미널 → 스크롤백만 방출)

Gemini CLI v0.38.1 은 Ink(React-for-CLI) 기반으로 **매 프레임마다 가시 영역 전체**(입력 프롬프트, 스피너, 상태바)를 커서-업 ANSI 로 다시 그립니다. PTY 원문을 그대로 흘려 보내면 `*   Type your message…` 입력 프롬프트가 수백 번, `✦ CVE 분석 시작` 같은 문구가 글자 한 개씩 늘어나며 프레임마다 방출되어 로그가 사용 불가능해집니다.

해결책: **[pyte](https://pypi.org/project/pyte/) 가상 터미널로 PTY 바이트를 렌더링 → 라이브 뷰포트를 벗어나 스크롤백(history)에 커밋된 라인만 방출**. 이렇게 하면 사용자가 실제 터미널에서 수동으로 `gemini --yolo` 를 실행했을 때 위로 스크롤되는 화면과 동일한 흐름(Shell 도구 박스, `✦` 분석 코멘트, 최종 보고서)만 로그에 남습니다.

핵심 구현:

```python
class _GeminiScreen(pyte.HistoryScreen):
    """pyte 0.8.2 의 Stream 은 private CSI 시퀀스에 대해
    ``select_graphic_rendition(*params, private=True)`` 로 호출하는데
    Screen 기본 구현은 ``private`` 키워드를 받지 않는다. Gemini CLI (Ink/chalk)
    가 컬러 팔레트에 private SGR 를 쓰므로 override 로 흡수해야 한다."""
    def select_graphic_rendition(self, *attrs, **_):
        super().select_graphic_rendition(*attrs)

pyte_screen = _GeminiScreen(columns=200, lines=50, history=10000, ratio=0.05)
pyte_feed = pyte.ByteStream(pyte_screen)
# 매 PTY 청크마다 pyte_feed.feed(chunk_bytes) → history.top 에 새로 쌓인
# 라인만 logger + progress_q 로 방출.  최종 보고서 / OpenVEX JSON 은 보통
# 뷰포트 안에서 끝나므로 OpenVEX 감지 / idle shutdown 시 _flush_viewport()
# 로 뷰포트를 한 번 더 떠서 방출.
```

뷰포트 크기는 반드시 `_launch_gemini_pty` 의 `TIOCSWINSZ` (200 columns × 50 rows) 와 일치시켜야 Ink 가 pyte 화면 밖으로 선을 그리지 않습니다.

**Chrome 필터 (_CHROME_BLOCK)**: pyte 로 걸러지지 못하고 스크롤백에 한 번이라도 흘러들어간 프레임 장식(`▀▀▀`/`▄▄▄`/`───` 분리선, `YOLO Ctrl+Y`, `workspace (/directory)`, `no sandbox gemini-…` 푸터, `*   Type your message…` 입력 프롬프트)은 정규식으로 제거합니다. Shell 박스의 `╭/╰/│` 는 필터에 포함되지 않으므로 안전합니다.

Rate-limit 감지, OpenVEX JSON 조기 종료, idle shutdown(45s) 은 그대로 유지됩니다.

#### JSON 추출 (`extract_json_from_response`)

```
1. PTY \\r\\n → \\n 정규화
2. ```json\\n...``` 코드블록 탐지 (re.DOTALL)
3. json.JSONDecoder().raw_decode(text, pos): 각 { 위치에서 순차 파싱
   → Korean 텍스트의 {변수명} 같은 가짜 { 는 JSONDecodeError로 자동 건너뜀
   → greedy regex와 달리 중첩 brace를 정확히 처리
```

#### 보고서 추출 (`_extract_report_text`)

Gemini는 분석 과정(bash 코드블록, 단계별 설명)을 먼저 출력하고 마지막에 최종 보고서를 출력합니다. `_extract_report_text`는 `=====...===== CVE 분석 요약 보고서` 헤더부터 마지막 `=====...=====` 구분자까지만 추출합니다. `{CVE-ID}_report.md`에 저장되며 프론트엔드 "ANALYSIS DETAIL" 탭에 표시됩니다. `{CVE-ID}_gemini_yolo.md`에는 전체 원문이 저장됩니다.

### 파일 시스템 구조

```
storage/{job_id}/
├── firmware.img              # 원본 업로드 파일
├── extracted/                # binwalk 추출 결과 (rootfs 포함)
├── sbom.cdx.json             # CycloneDX SBOM
├── scan.json                 # grype 원본 출력
├── combined_vex.json         # 전체 CVE VEX 문서 (배치 완료 후 생성)
└── vex/
    ├── {CVE-ID}_vex.json        # CVE별 OpenVEX JSON (CVE 완료 시 즉시 생성)
    ├── {CVE-ID}_report.md       # CVE별 AI 분석 요약 보고서 (최종 섹션만)
    ├── {CVE-ID}_gemini_yolo.md  # Gemini 전체 응답 원문 (디버깅용)
    └── {CVE-ID}_pty_raw.log     # PTY 원시 출력 (ANSI 코드 포함, 디버깅용)
```

**중요**: `combined_vex.json`은 배치 전체 완료 후에만 생성됩니다. `/api/jobs/{id}/result` 엔드포인트는 분석 중에는 개별 `*_vex.json` + `*_report.md` 파일을 읽어 점진적으로 VEX 결과를 반환합니다 (`_load_vex` 폴백 로직). 이를 통해 `cve_done` 이벤트마다 프론트엔드가 `loadResult()`를 호출해 점진적 갱신이 가능합니다.

`rootfs_path`는 추출 후 DB에 저장되어 VEX 재분석(retry-vex) 시에도 동일 경로를 사용합니다. 대표 rootfs는 파일 수가 가장 많은 후보가 선택됩니다.

### DB 스키마

SQLite (`data/firmcore.db`). `get_db()` 비동기 컨텍스트 매니저로 접근합니다. 주요 테이블:
- `jobs` — job 메타데이터 및 집계 (총 CVE 수, 심각도별 카운트, not_affected 수 등)
- `job_events` — 파이프라인 이벤트 로그 (SSE 스트리밍의 원본 데이터)
- `stage_timings` — 단계별 경과 시간

### 프론트엔드

React + Vite + Tailwind. 핵심 훅:
- `useJobDetail.ts` — SSE 스트리밍 연결, `cve_done` 이벤트마다 `loadResult()` 호출해 VEX 탭 점진적 갱신, `after_id` 추적으로 재연결 시 중복 방지
- `useJobList.ts` — 잡 목록 폴링

**타입 정합성 주의**: `frontend/src/types/index.ts`의 필드명은 백엔드 Pydantic 모델(`backend/models/job.py`)과 정확히 일치해야 합니다. 예: `fix_version` (not `fixed_version`), `JobResult.id` (not `job_id`).

## 주요 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `MOCK_PIPELINE` | `false` | 전체 파이프라인 더미 데이터로 시뮬레이션 |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini 모델 (쉼표로 여러 개 지정 시 순서대로 폴백) |
| `VEX_GEMINI_TIMEOUT` | `1800` | CVE 하나당 Gemini CLI 타임아웃 (초, 기본 30분) |
| `VEX_CVE_DELAY` | `5` | CVE 간 딜레이 (Gemini rate limit 방지, 초) |
| `STORAGE_DIR` | `./storage` | 분석 결과 저장 경로 |
| `SBOM_BIN` | `./sbom_claude_scripts` | SBOM 생성 바이너리 경로 |

`VEX_GEMINI_OUTPUT_FORMAT` 환경변수는 더 이상 사용하지 않습니다. PTY 모드에서는 `--output-format` 플래그를 사용하지 않습니다.

## 사전 요구사항

- **binwalk** — 펌웨어 추출
- **grype** — CVE 스캔
- **Gemini CLI** (`npm install -g @google/gemini-cli`) — VEX 분석, Google 계정 OAuth로 인증 (`gemini` 한 번 실행해 로그인)
- **sbom_claude_scripts** — 프로젝트 루트에 바이너리 배치 필요
- **`~/.gemini/GEMINI.md`** — Gemini VEX 분석 시스템 프롬프트 (자율 에이전트 모드 지시). 이 파일은 gemini CLI가 어느 디렉토리에서 실행되든 자동으로 로드됩니다.

## 주의사항

### 프로세스 종료

`start.sh`를 Ctrl+C로 종료하면 `cleanup()`이 gemini 프로세스 그룹 전체를 SIGKILL합니다:

```bash
# start.sh의 kill_gemini_procs()
pgrep -f "bin/gemini" | while read pid; do
  pgid=$(ps -o pgid= -p "$pid" | tr -d ' ')
  kill -KILL -- "-$pgid"  # 프로세스 그룹 전체 종료
done
```

Gemini CLI는 `os.setsid()`로 새 세션을 생성하므로 부모 SIGINT가 전달되지 않습니다. PID가 아닌 **PGID** 기반으로 kill해야 합니다. 백엔드 lifespan shutdown도 `terminate_active_gemini_processes()`를 호출합니다.

`start.sh`에서 `set -e`는 제거된 상태입니다(`set -uo pipefail`만 사용). `cleanup()` 내부에서 `kill` 실패 시 스크립트가 중단되는 문제를 방지합니다.

### ELF 탐지

rootfs 정적 분석 시 `-executable` 퍼미션 기반 탐지는 불가 (추출 시 퍼미션 미보존). ELF 매직바이트(`\x7fELF`) 기반으로만 탐지해야 합니다. `~/.gemini/GEMINI.md` 시스템 프롬프트에 이 규칙이 명시되어 있습니다.

### Gemini Workspace 제한

Gemini CLI는 `cwd` 외부로 심볼릭 링크가 resolve되는 경로에 대해 Shell 도구 실행을 차단합니다:

```
Error executing tool run_shell_command: Path not in workspace: Attempted path resolves outside the allowed workspace
```

펌웨어 심볼릭 링크가 squashfs-root 외부(sibling 디렉토리)를 가리키는 경우 발생합니다. 현재 미해결 사항입니다.

### VEX 재분석

- `POST /api/jobs/{id}/retry-vex` — 완료되지 않은 CVE만 재실행 (이미 `_vex.json` 있는 CVE 건너뜀)
- `POST /api/jobs/{id}/retry-vex/{cve_id}` — 단일 CVE만 재실행

### JSON 추출 실패 시

Gemini가 응답을 완성하기 전에 프로세스가 종료되면 (LLM 토큰 중간 종료 등) JSON이 불완전해 `extract_json_from_response`가 실패합니다. 이 경우 `under_investigation` 폴백이 적용되며, `{CVE-ID}_gemini_yolo.md`에 원문이 저장되므로 내용 확인 후 retry-vex로 재실행할 수 있습니다.
# 지침 (Instructions)
- 모든 응답, 생각 과정, 중간 계획은 한국어로 작성하십시오.
- 특히 씽킹(Thinking) 과정과 코드 설명은 반드시 한국어여야 합니다.
