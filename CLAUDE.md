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

# 개발용 HMR 활성화 (파일 저장 시 uvicorn 재시작).  분석 중 코드 수정이
# 필요하지 않으면 끄는 것을 권장 — 재시작마다 Gemini subprocess 가 같이
# 죽어 분석이 중단된다.
FIRMCORE_RELOAD=1 ./start.sh

# 백엔드 단독 실행 (개발)
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8080

# 프론트엔드 단독 실행 (개발)
cd frontend
npm run dev

# TypeScript 타입 검사 (테스트 대용)
cd frontend && npx tsc --noEmit

# Python 문법 검사
python3 -c "import ast; ast.parse(open('backend/pipeline/vex.py').read())"

# VEX 결과 복구 (DB job_events 에서 누락된 _vex.json / _report.md 재생성)
cd backend && source .venv/bin/activate
python3 -m scripts.restore_vex_from_events <JOB_ID>
#   --dry-run    파일 쓰기 없이 시뮬레이션
#   --overwrite  기존 파일도 덮어쓰기 (기본: skip)
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
pipeline/runner.py  →  event_bus.broadcast()  →  인메모리 Queue (크기=1)
                                                         ↓
GET /api/jobs/{id}/stream  ←  DB 폴링 (after_id 기반 중복 방지)  ←  Queue 알림 수신
```

이벤트 본문은 항상 `job_events` DB 테이블이 source of truth입니다. `event_bus` 큐는 **크기 1 의 "깨우기 신호"** 만 전달합니다 — 이미 쌓인 신호가 있으면 `put_nowait` 가 조용히 drop 하고, SSE 제너레이터는 신호 하나로 `db_get_events(after_id=N)` 로 누적 이벤트를 batch 로 읽어옵니다. 큰 큐는 불필요하고 노이즈만 늘립니다.

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
```

**PTY 만으로는 부족 — TERM 을 반드시 주입해야 함**: Ink 는 rich 박스 렌더링을 켜기 위해 `isatty(stdout)` 뿐 아니라 유효한 `TERM` 값을 요구합니다. `start.sh` 의 `BACKEND_ENV` 에는 `TERM` 이 없어 uvicorn 상속 환경으로는 plain text 폴백으로 떨어집니다. `_launch_gemini_pty` 는:

```python
env = os.environ.copy()
if not env.get("TERM") or env["TERM"] == "dumb":
    env["TERM"] = "xterm-256color"
env.setdefault("COLORTERM", "truecolor")
env.setdefault("FORCE_COLOR", "1")
for ci_var in ("CI", "GITHUB_ACTIONS", "BUILDKITE"):
    env.pop(ci_var, None)  # non-interactive 모드로 오판하는 것 방지
```

**두 번째 함정 — bash 래퍼의 stdin 리다이렉트**: `_gemini_process_args` 는 시그널 트랩을 걸기 위해 `bash -c 'trap ...; "$@" <&0 & wait'` 로 감쌉니다. `<&0` 은 부모에게서 상속받은 fd 0(=PTY slave)을 명시적으로 유지시켜 bash 의 자동 `/dev/null` 리다이렉트를 무력화합니다. 없으면 `process.stdin.isTTY === false` 로 Ink 가 plain text 로 떨어집니다.

**세 번째 함정 — Gemini CLI v0.38.2 의 positional argument**: v0.38.2 부터는 CLI 인자로 준 프롬프트가 **자동 실행되지 않고** interactive 입력창에 프리필된 채 Enter 를 대기합니다:

```
ℹ Positional arguments now default to interactive mode.
  To run in non-interactive mode, use the --prompt (-p) flag.
```

`-p` 를 쓰면 Ink rich UI 가 꺼져 Shell 도구 박스가 사라지므로 대신 **PTY master fd 로 `\r\n` 을 자동 전송** 합니다 (`_read_pty` 의 initial prompt auto-submit). prefill `> {cve_id}` 가 viewport 에 보이면 감지 즉시 Enter 전송, 20초 fallback 타이머도 있습니다.

Gemini가 내장 Shell 도구로 `find`, `nm`, `readelf`, `strings`, `grep` 등을 rootfs 에서 직접 실행하며 **4단계 도달성·완화 분석**을 수행합니다:

1. **Library Level** — 취약 심볼 존재 + 버전 범위 확인 (`vulnerable_code_not_present` / `fixed`)
2. **Binary Level** — 취약 함수를 호출/링크하는 ELF 탐색 (`vulnerable_code_not_in_execute_path`)
3. **Attack Surface** — 원격 공격자 도달성: 리스너 심볼, auto-start, Web/CGI, SUID, CVE 전제 매칭 (`vulnerable_code_cannot_be_controlled_by_adversary`)
4. **Mitigation Check** — 컴파일 완화(PIE/NX/RELRO/Canary/FORTIFY) 가 CVE 공격 유형을 실질 차단하는지 → `exploitability_tier` 결정

`~/.gemini/GEMINI.md`가 전역 시스템 프롬프트로 자동 로드됩니다 (v4.0 — Attack-Surface + Mitigation Model). CLI 인자에는 `@filepath` 구문이 작동하지 않으므로 프롬프트 파일 내용을 직접 삽입하지 않고, task-specific 맥락만 인자로 전달합니다.

#### CVE 메타데이터 프롬프트 주입 (GoogleSearch 방지)

`run_vex_analysis_loop` 는 `_build_gemini_yolo_prompt` 를 통해 **grype 가 수집한 CVE 정보**(description, package, severity, fix_version, URLs 3개)를 프롬프트에 그대로 주입합니다. 그리고 **"웹 검색(GoogleSearch) 으로 다시 조회하지 말고 아래 정보를 그대로 사용"** 지시를 명시해 Gemini 가 CVE lookup 턴으로 쿼터를 낭비하지 않도록 합니다.

description 은 기본 **무제한** (`VEX_DESC_MAX_CHARS=0`). 실 데이터 기준(1240 CVE 표본) median 158자, max ~3900자 — Gemini context window 대비 미미하고, 잘리면 Gemini 가 GoogleSearch 한 번을 더 호출해 오히려 쿼터가 더 든다. 특정 API per-request 한도에 걸리면 환경변수로 조절.

#### Exploitability Tier (affected 의 서브 카테고리)

4단계 Mitigation Check 는 `affected` status 를 뒤집지 않습니다. OpenVEX status 는 그대로 두되 커스텀 확장 `exploitability_tier` 를 부여:

- **`standard`** — 일반 affected (시급 패치)
- **`low`** — CVE 공격 유형에 매칭되는 컴파일 완화 **전부 충족** (예: Stack BOF + Canary+NX+PIE 모두 O). 실전 exploit 난이도가 높아 패치 우선순위 하향 가능

Tier 적용 조건은 엄격 — Heap BOF / UAF / Logic bypass 류는 **컴파일 완화로 무효화 불가** 이므로 `low` 부여 금지. OpenVEX JSON 의 `impact_statement` 는 `[EXPLOITABILITY_TIER: LOW|STANDARD|NONE]` prefix 로 시작하고, `combined_vex.json` 에는 `x_firmcore_exploitability_tier` 확장 필드로 영속화됩니다.

프론트엔드 `VexBadge` 는 tier=low 일 때 `AFFECTED · LOW` (주황) 로, 그 외는 `AFFECTED` (빨강) 로 구분 표시.

#### PTY 출력 스트리밍 (pyte 가상 터미널 → 스크롤백 + 증분 방출)

Gemini CLI 는 Ink 기반으로 매 프레임마다 가시 영역 전체를 커서-업 ANSI 로 다시 그립니다. [pyte](https://pypi.org/project/pyte/) 가상 터미널로 PTY 바이트를 렌더링하고 스크롤백에 커밋된 라인만 방출해, 수동 터미널 실행과 동일한 로그 흐름(Shell 도구 박스, `✦` 분석 코멘트, 최종 보고서)만 남깁니다.

핵심 구현:

```python
class _GeminiScreen(pyte.HistoryScreen):
    """pyte 0.8.2 의 Stream 은 private CSI 시퀀스에 대해
    ``select_graphic_rendition(*params, private=True)`` 로 호출하는데
    Screen 기본 구현은 ``private`` 키워드를 받지 않는다. Ink/chalk 가
    컬러 팔레트에 private SGR 를 쓰므로 override 로 흡수해야 한다."""
    def select_graphic_rendition(self, *attrs, **_):
        super().select_graphic_rendition(*attrs)

pyte_screen = _GeminiScreen(columns=VEX_PTY_COLUMNS, lines=VEX_PTY_LINES,
                            history=10000, ratio=0.05)
```

뷰포트 크기(`VEX_PTY_COLUMNS=200` 기본) 는 `_launch_gemini_pty` 의 `TIOCSWINSZ` 와 일치시켜야 Ink 가 pyte 화면 밖으로 선을 그리지 않습니다. 200 cols 는 긴 grep 결과가 박스 안에서 **wrap 되지 않도록** 충분한 폭을 확보합니다.

**Chrome 필터 (`_CHROME_BLOCK`)**: 스크롤백으로 흘러들어간 프레임 장식(`▀▀▀`/`▄▄▄` 분리선, `YOLO Ctrl+Y`, `workspace (/directory)`, `no sandbox gemini-…` 푸터, Braille 스피너(U+2800..U+28FF) + "esc to cancel" 포함 라인) 전부 정규식으로 제거. Shell 박스의 `╭/╰/│` 는 필터에 포함되지 않아 안전합니다.

**Shell 박스 → 구분선 포맷** (`_emit_box`): 로그 가독성을 위해 Ink 의 ╭─...─╮ / │ / ╰─...─╯ 박스 프레임을 제거하고 경량 구분선으로 대체합니다:

```
─── Shell ──────────────────────────────────────────────
✓ Shell 실행 설명 한 줄
  find . -name "libz.so*" 결과 라인들
  추가 결과
──────────────────────────────────── end Shell ─────────
```

양 구분선 모두 "Shell" 텍스트를 포함해 순수 ──-only 라인을 걸러내는 `_CHROME_BLOCK` 필터(`^[▄▀─]{4,}\s*$`) 와 충돌하지 않습니다. WriteFile 박스는 body(숫자 diff) 를 완전히 생략하고 헤더 한 줄만 방출 — 이미 디스크에 저장된 OpenVEX JSON / report.md 를 로그에 반복 출력할 필요가 없습니다.

**증분 뷰포트 방출 (`_flush_viewport_incremental`) + 3-scan stability**: 뷰포트 전체를 스캔하되 **3 회 연속 동일한 라인만** 방출합니다 (`prev_viewport`, `prev_prev_viewport` 비교). 2-scan 까지는 "거의 완성된" partial fragment 가 빠져나갈 수 있었지만 3-scan 이면 Gemini streaming 이 안정된 후 나옵니다. 바닥 `VEX_PTY_UI_TAIL_LINES` (기본 4) 라인은 Ink 임시 UI(스피너/입력창/푸터) 로 간주해 제외되고, idle shutdown / OpenVEX 완료 시 `_flush_viewport()` 가 마지막에 한 번 떠올립니다.

**Pre-submit suppression**: Enter 자동 전송 전까지는 `pre_submit_suppress[0] == True` 로 모든 `_emit_*` 경로에서 즉시 return — Gemini 배너, `ℹ Positional arguments...` 안내, 프리필된 프롬프트 박스가 로그에 노출되지 않습니다. 해제는 viewport 에 **`✦` 가 처음 등장한 시점**(= Gemini 가 자기 응답을 쓰기 시작) 으로 지연시켜, 그 사이 viewport → history 로 밀려나는 초기 UI 잔상도 `emitted_hashes` poisoning 으로 완전히 차단합니다.

**Markdown heading prefix-merge**: `_emit_line` 의 pending-stream prefix 비교 시 `*`/`#` 마커를 제거한 상태로 비교 — Ink 의 Markdown renderer 가 `**1단계: ...` 를 먼저 렌더했다가 안정화되면 `**` 를 제거하는 특성에서 fragment 가 두 번 방출되는 문제를 방지합니다.

**WriteFile diff suppression**: `^\s*\d+(?:\s|$)` 라인을 전역 차단. Gemini 가 WriteFile 완료 후 숫자-prefix 로 출력하는 diff preview 를 억제 — 우리 정상 출력에는 이 패턴이 없습니다(보고서 번호 리스트는 `1.` 포맷, 박스는 `│` 로 감쌈).

Rate-limit 감지, OpenVEX JSON 조기 종료, idle shutdown(45s) 은 그대로 유지됩니다.

#### 모델 선택 + Rate-limit 시 중단/재개 구조

OAuth 무료 Gemini Code Assist 는 Pro / Flash 가 각각 별도 분당·일일 쿼터를 가집니다. 기본값은 **auto 모드**(`GEMINI_MODEL=auto`) — `_gemini_process_args` 가 `auto`/`default` sentinel 을 만나면 `--model` 인자를 생략해 CLI 가 자체 default (Pro) 로 시작하고 쿼터 소진 시 Flash 로 자동 폴백하도록 맡깁니다.

**Rate-limit 감지**: `_is_gemini_rate_limit` 가 "Usage limit reached for ...", "Access resets at HH:MM GMT+9", "status 429" 등을 감지. 이 문자열은 Ink 가 특수 박스 글리프(`┏━┃┗`) 로 프레이밍할 수 있어 line-emit 경로로 걸러지지 않을 수 있으므로, `_read_pty` 가 매 chunk 마다 **accumulated 버퍼 최근 4 청크** 에 ANSI 스트립 후 체크합니다. 감지되면:

1. 배너에서 정확한 모델명(`usage limit reached for (\S+)`) 과 리셋 시간을 파싱
2. `[RATE_LIMIT] {model_label} 쿼터 소진 (Access resets at HH:MM GMT+9)` 예외 raise
3. **메인 루프가 `read_task.done()` + `exception()` 을 체크해 Gemini 프로세스 그룹을 SIGKILL** (이 체크가 없으면 read_task 가 죽어도 wait_task 는 살아있어 heartbeat 만 무한 출력)
4. `run_vex_analysis_loop` 가 `rate_limited` 이벤트 yield → `batch_rate_limited` → `_fail_job` 에서 `error_message` 에 `[RATE_LIMIT]` 마커 삽입
5. 프론트엔드 JobDetail 이 **호박색 Hourglass 알림 박스** 로 모델명/리셋시간을 표시하고 **Resume VEX** 버튼 노출

#### WriteFile 기반 artifact 저장 (스테이징 파일)

Gemini 의 `WriteFile` 도구는 `cwd` 바깥 경로 저장을 차단합니다. `cwd=rootfs_path` 로 실행하므로 `storage/<job>/vex/` 에 직접 쓸 수 없어, rootfs 루트에 hidden staging 파일로 저장하도록 프롬프트를 구성하고 분석 종료 후 정식 경로로 이동:

```python
vex_stage_rel    = f".firmcore_{cve_id}_vex.json"     # cwd-relative
report_stage_rel = f".firmcore_{cve_id}_report.md"
# 분석 종료 후: rootfs_path / stage_rel → output_dir / {CVE-ID}_{vex.json|report.md}
```

PTY 스트림 파싱은 폴백으로만 사용합니다 (WriteFile 결과가 없거나 파싱 실패 시). 정상 플로우는 디스크의 staging 파일에서 바로 읽어 `VexStatement` 를 구성.

Gemini 의 OpenVEX `@id` UUID 는 GEMINI.md 에서 **직접 작성한 v4 문자열 사용을 강제** — `uuidgen` / `python -c 'import uuid'` 등 Shell 호출 금지 (분석 turn 낭비). 마찬가지로 보고서/JSON WriteFile 완료 후 "분석 완료", "저장했습니다" 같은 후처리 해설도 금지.

### 파일 시스템 구조

```
storage/{job_id}/
├── firmware.img              # 원본 업로드 파일
├── extracted/                # binwalk 추출 결과 (rootfs 포함)
├── sbom.cdx.json             # CycloneDX SBOM
├── scan.json                 # grype 원본 출력
├── combined_vex.json         # 전체 CVE VEX 문서 (배치 완료 후 생성 / 재빌드)
└── vex/
    ├── {CVE-ID}_vex.json        # CVE별 OpenVEX JSON (CVE 완료 시 즉시 생성)
    │                            # x_firmcore_exploitability_tier 확장 필드 포함
    ├── {CVE-ID}_report.md       # CVE별 AI 분석 요약 보고서
    ├── {CVE-ID}_gemini_yolo.md  # Gemini 전체 응답 원문 (디버깅용)
    └── {CVE-ID}_pty_raw.log     # PTY 원시 출력 (ANSI 포함, 디버깅용)
```

**중요**: `/api/jobs/{id}/result` 엔드포인트는 분석 중에도 개별 `*_vex.json` / `*_report.md` 를 읽어 점진적으로 VEX 결과를 반환합니다 (`_load_vex` 폴백). top-level `affected_count` / `not_affected_count` / `under_investigation_count` 는 **DB 캐시 컬럼이 아닌 현재 시점 `cve_results` 에서 실시간 재계산** 합니다 — Resume/Retry 를 반복하면 runner 의 incremental 카운터가 0 부터 다시 시작해 stale 해지기 때문. `GET /api/jobs` 목록도 `_count_vex_statuses(storage_dir)` 헬퍼로 combined_vex.json 또는 vex/*_vex.json 파일을 직접 집계해 반환합니다.

`rootfs_path`는 추출 후 DB에 저장되어 VEX 재분석 시에도 동일 경로를 사용합니다. 대표 rootfs는 파일 수가 가장 많은 후보가 선택됩니다.

### DB 스키마

SQLite (`data/firmcore.db`). `get_db()` 비동기 컨텍스트 매니저. 주요 테이블:
- `jobs` — job 메타데이터 및 집계. **`affected_count` 등 집계 컬럼은 이제 authoritative 가 아님** — UI 표시는 실시간 재집계(위)를 사용하고 DB 캐시는 fallback 역할만.
- `job_events` — 파이프라인 이벤트 로그 (SSE 스트리밍의 원본 데이터). **VEX 복구의 source of truth** — `cve_done` 이벤트의 `cve_result` payload 에 CVE 별 전체 VEX 결과(vex_status, justification, vex_detail 30KB+, exploitability_tier) 가 영구 보관됨
- `stage_timings` — 단계별 경과 시간

### 프론트엔드

React + Vite + Tailwind. 핵심 훅:
- `useJobDetail.ts` — SSE 스트리밍 연결, **이벤트 기반 업데이트**. `cve_done` 이벤트의 `cve_result` patch 로 Optimistic UI 반영, 60초 fail-safe polling 만 유지 (이전 5초 주기 폴링 제거). `loadResult` 는 `loadingRef` 로 in-flight guard → SSE 재연결 시 backend 가 히스토리 재전송해도 fetch 1건으로 압축.
- `useJobs.ts` — 잡 목록 5초 polling (dashboard 용)

**탭 순서**: SBOM → Vulnerabilities → VEX Analysis → Pipeline Log. 기본 진입 탭은 **VEX Analysis** — 최종 산출물이 바로 보이도록. Pipeline Log 는 개발/디버깅 용도로 마지막.

**VEX Analysis 탭 기능**:
- 상단 coverage (`analyzed / total · %`) + 상태별 필터 pills (AFFECTED, AFF·LOW, NOT AFFECTED, INVESTIGATING, FIXED, UNANALYZED) 각 건수 표시
- Sort dropdown: Severity (기본, 백엔드 `_select_cves_for_vex` 와 일치) / VEX status / CVE ID
- 각 CVE 행에 **Re-analyze** (단일) + **Resume from here** (이 CVE 부터 이하 재분석) 버튼

**LIVE VEX 뱃지** ([Badge.tsx](frontend/src/components/Badge.tsx)): `status === 'vex_analyzing'` 일 때 초록색 깜빡이는 점 + `LIVE VEX` 표시 (이전 `VEX AI` 라벨 대체).

**타입 정합성 주의**: `frontend/src/types/index.ts`의 필드명은 백엔드 Pydantic 모델(`backend/models/job.py`)과 정확히 일치해야 합니다. 예: `fix_version`, `JobResult.id`, `exploitability_tier`.

### 정렬 규칙 — 백엔드/프론트 일치

Resume from here 의 삭제 대상 CVE 가 화면과 어긋나지 않으려면 **백엔드 분석 순서와 UI 표시 순서가 동일** 해야 합니다. 이를 위해 양쪽 모두:

- **severity 만** 기준 (CRITICAL → UNKNOWN)
- 같은 severity 내에서는 **scan.json 원본 순서 유지** (Python `sorted` / JS `Array.prototype.sort` 모두 ES2019+ stable)

백엔드: [runner.py `_select_cves_for_vex`](backend/pipeline/runner.py), 프론트: [VulnerabilitiesTab](frontend/src/pages/JobDetail/VulnerabilitiesTab.tsx) 기본 정렬 + [VexAnalysisTab `sortCves`](frontend/src/pages/JobDetail/VexAnalysisTab.tsx). CVSS/EPSS/Risk tiebreaker 는 **사용자가 sort UI 로 명시 선택 시에만** 적용.

## 주요 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `MOCK_PIPELINE` | `false` | 전체 파이프라인 더미 데이터로 시뮬레이션 |
| `FIRMCORE_RELOAD` | `0` | `1` 이면 `./start.sh` 가 uvicorn `--reload` 포함 실행 (개발용). 분석 중 코드 수정은 분석을 끊어먹으니 평상시 꺼둔다 |
| `GEMINI_MODEL` / `GEMINI_MODELS` | `auto` | Gemini 모델. `auto`/`default` 면 `--model` 인자 생략 → CLI default(Pro) → 쿼터 소진 시 Flash 자동 폴백 |
| `VEX_GEMINI_TIMEOUT` | `1800` | CVE 하나당 Gemini CLI 타임아웃 (초, 30분) |
| `VEX_GEMINI_IDLE_SHUTDOWN` | `45` | PTY 출력이 시작된 뒤 idle 지속 시 강제 종료 임계치 (초) |
| `VEX_PTY_COLUMNS` / `VEX_PTY_LINES` | `200` / `80` | PTY/pyte viewport 크기. 200 cols 는 긴 grep 결과가 Shell 박스 안에서 wrap 되지 않도록 충분한 폭 |
| `VEX_PTY_UI_TAIL_LINES` | `4` | 증분 뷰포트 방출 시 Ink 임시 UI 영역으로 간주할 바닥 라인 수 |
| `VEX_EMIT_HASH_WINDOW` | `2000` | 증분 뷰포트 방출의 내용-해시 중복 필터가 유지할 최근 라인 수 |
| `VEX_DESC_MAX_CHARS` | `0` (무제한) | Gemini 프롬프트에 포함할 CVE description 최대 길이. 0=무제한 (권장). 잘리면 Gemini 가 GoogleSearch 로 재조회하는 비용이 더 큼 |
| `VEX_CVE_DELAY` | `5` | CVE 간 딜레이 (Gemini rate limit 방지, 초) |
| `STORAGE_DIR` | `./storage` | 분석 결과 저장 경로 |
| `SBOM_BIN` | `./sbom_claude_scripts` | SBOM 생성 바이너리 경로 |

더 이상 사용하지 않는 환경변수:
- `VEX_GEMINI_OUTPUT_FORMAT` — PTY 모드에서는 `--output-format` 을 주지 않습니다.
- `VEX_GEMINI_MODEL_RETRY_CYCLES`, `VEX_GEMINI_RATE_LIMIT_DEFAULT_WAIT`, `VEX_GEMINI_RATE_LIMIT_MAX_WAIT` — rate-limit 을 내부에서 재시도하지 않고 사용자 수동 Resume 구조로 바뀌었으므로 값이 무시됩니다.
- `VEX_SYSTEM_PROMPT`, `VEX_GEMINI_PROMPT_FILE` — 시스템 프롬프트는 `~/.gemini/GEMINI.md` 자동 로드만 사용합니다.

## 사전 요구사항

- **binwalk** — 펌웨어 추출
- **grype** — CVE 스캔
- **Gemini CLI** v0.38.2+ (`npm install -g @google/gemini-cli`) — Google 계정 OAuth 로 인증 (`gemini` 한 번 실행해 로그인)
- **sbom_claude_scripts** — 프로젝트 루트에 바이너리 배치
- **`~/.gemini/GEMINI.md`** (v4.0) — Gemini VEX 분석 시스템 프롬프트. Attack-Surface + Mitigation 4단계 모델, exploitability_tier 부여 규칙, WriteFile 경로 규약 등 포함. gemini CLI 가 어느 디렉토리에서 실행되든 자동 로드됩니다.

## 주의사항

### 프로세스 종료

`start.sh`를 Ctrl+C로 종료하면 `cleanup()`이 gemini 프로세스 그룹 전체를 SIGKILL:

```bash
pgrep -f "bin/gemini" | while read pid; do
  pgid=$(ps -o pgid= -p "$pid" | tr -d ' ')
  kill -KILL -- "-$pgid"
done
```

Gemini CLI는 `os.setsid()`로 새 세션을 만들므로 부모 SIGINT가 전달되지 않습니다. **PGID** 기반으로 kill해야 합니다. `start.sh` 는 `set -e` 없이 `set -uo pipefail` 만 사용해 cleanup 실패가 스크립트를 중단시키지 않도록 합니다.

**uvicorn `--reload` 와의 충돌**: `--reload` 는 파일 저장 때마다 uvicorn 워커를 교체하는데, 진행 중 Gemini subprocess 는 `PR_SET_PDEATHSIG(SIGTERM)` 으로 워커 사망 시 같이 죽습니다. VEX 분석 도중 백엔드 코드를 수정하면 분석이 중간에 kill 됩니다. 그래서 기본 `FIRMCORE_RELOAD=0` — 필요 시에만 `FIRMCORE_RELOAD=1 ./start.sh` 로 opt-in.

### ELF 탐지

rootfs 정적 분석 시 `-executable` 퍼미션 기반 탐지는 불가 (추출 시 퍼미션 미보존). ELF 매직바이트(`\x7fELF`) 기반으로만 탐지해야 합니다. GEMINI.md 시스템 프롬프트에 이 규칙이 명시되어 있습니다.

### Gemini Workspace 제한

Gemini CLI는 `cwd` 외부로 심볼릭 링크가 resolve되는 경로에 대해 Shell 도구 실행을 차단합니다:

```
Error executing tool run_shell_command: Path not in workspace: Attempted path resolves outside the allowed workspace
```

펌웨어 심볼릭 링크가 squashfs-root 외부(sibling 디렉토리)를 가리키는 경우 발생합니다. 현재 미해결 사항입니다.

### VEX 재분석 엔드포인트

네 개의 엔드포인트가 역할별로 구분됩니다:

- `POST /api/jobs/{id}/retry-vex` — **처음부터 다시**. `vex/` 디렉토리와 `combined_vex.json` 삭제 후 전체 CVE 재분석 → `run_vex_only`
- `POST /api/jobs/{id}/resume-vex` — **이어서 분석**. `vex/{CVE-ID}_vex.json` 이 이미 있는 CVE 는 skip, 남은 CVE 부터 → `run_vex_resume`
- `POST /api/jobs/{id}/resume-vex/{cve_id}` — **지정 CVE 부터 이하 재분석**. severity-only stable sort 순서로 `start_cve_id` 이상의 CVE 산출물 삭제 후 재분석 → `run_vex_resume_from`. 이전 CVE 결과는 그대로 보존
- `POST /api/jobs/{id}/retry-vex/{cve_id}` — **단일 CVE 만** → `run_vex_single`. scan.json 에서 실제 Vulnerability 메타데이터(description, package) 를 복원해 Gemini 프롬프트에 주입 (이 복원이 없으면 Gemini 가 "취약 컴포넌트 누락" 이라며 rootfs 를 무작정 뒤짐)
- `POST /api/jobs/{id}/cancel-vex` — 진행 중인 배치 취소 + 활성 Gemini 프로세스 그룹 SIGKILL

Resume 는 rate-limit 복구 외에도 중간 JSON 추출이 실패한 CVE 재시도 용도로 쓸 수 있습니다. 단, 폴백으로 `under_investigation` 이 저장되면 `{CVE-ID}_vex.json` 이 이미 존재해 resume 은 skip 하므로 이 경우엔 `retry-vex/{cve_id}` 단일 재분석을 사용하세요.

### JSON 추출 실패 시

Gemini 가 응답을 완성하기 전에 프로세스가 종료되면 JSON 이 불완전해 `extract_json_from_response` 가 실패합니다. 이 경우 `under_investigation` 폴백이 적용되며, `{CVE-ID}_gemini_yolo.md` 에 원문이 저장되므로 내용 확인 후 `retry-vex/{cve_id}` 로 재실행.

### VEX 결과 복구 — DB 가 truth

Resume from here 를 잘못 누르거나 Retry 를 반복하다 `vex/` 디렉토리의 _vex.json 파일이 의도치 않게 삭제될 수 있습니다. **DB `job_events` 테이블의 `cve_done` 이벤트는 `cve_result` payload 에 vex_status / justification / vex_detail(보고서 30KB+) / exploitability_tier 를 전부 담고 있어** source of truth 역할을 합니다. 디스크에서 지워져도 다음 스크립트로 복구:

```bash
cd backend && source .venv/bin/activate
python3 -m scripts.restore_vex_from_events <JOB_ID>
```

스크립트는 각 CVE 의 가장 최근 `cve_done` 이벤트에서 cve_result 를 꺼내 누락된 `_vex.json` / `_report.md` 를 재구성하고 `combined_vex.json` 을 재빌드합니다. 기존 파일은 기본 보존 (`--overwrite` 로 덮어쓰기 가능).

# 지침 (Instructions)
- 모든 응답, 생각 과정, 중간 계획은 한국어로 작성하십시오.
- 특히 씽킹(Thinking) 과정과 코드 설명은 반드시 한국어여야 합니다.
