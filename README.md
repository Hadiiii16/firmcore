# FirmCore — Firmware Vulnerability Analysis Platform

로컬 환경에서 실행되는 웹 기반 펌웨어 취약점 분석 플랫폼입니다.  
펌웨어 이미지를 업로드하면 자동으로 SBOM을 생성하고 CVE를 탐지하며,  
Gemini CLI 기반 AI가 실제 파일시스템을 직접 분석하여 false positive를 제거하고 OpenVEX 문서를 생성합니다.

---

## 분석 파이프라인

```
펌웨어 이미지 (업로드)
        │
        ▼
[1] extracting      binwalk로 rootfs 추출 (squashfs / UBI / cramfs 등 자동 감지)
        │            멀티 rootfs 지원 — 여러 파티션이 있을 경우 전체 탐색
        ▼
[2] sbom_generating  sbom_claude_scripts(syft 기반)로 CycloneDX SBOM 생성
        │            여러 rootfs가 있을 경우 컴포넌트 중복 제거 후 병합
        ▼
[3] scanning        grype로 CVE 스캔 (SBOM 기반)
        │
        ▼
[4] vex_analyzing   Gemini CLI + 정적분석으로 VEX 판정
        │            ┌─────────────────────────────────────────┐
        │            │  CVE별 3단계 도달성 분석                 │
        │            │  1) Library Level  — 취약 함수 존재 여부 │
        │            │  2) Binary Level   — ELF 링크 여부       │
        │            │  3) Config Level   — 런타임 활성화 여부   │
        │            └─────────────────────────────────────────┘
        │            결과: ① 분석 요약 보고서  ② OpenVEX JSON
        ▼
결과 대시보드 (React)
  · SBOM 컴포넌트 목록
  · CVE 목록 (심각도별 필터)
  · VEX 판정 결과 + AI 분석 리포트
```

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **실시간 진행 로그** | SSE(Server-Sent Events)로 각 단계별 진행 상황을 웹 UI에 스트리밍 |
| **VEX 단독 재실행** | 전체 파이프라인을 재실행하지 않고 VEX 분석만 다시 실행 (Retry VEX) |
| **AI 분석 리포트** | CVE별 3단계 도달성 분석 요약 보고서를 VEX JSON과 함께 저장 및 표시 |
| **멀티 rootfs 지원** | UBI + squashfs overlay 등 복잡한 펌웨어 구조 자동 처리 |
| **MOCK 모드** | Gemini/binwalk/grype 없이 전체 플로우를 더미 데이터로 시뮬레이션 |
| **보안 커맨드 필터** | Gemini가 생성한 쉘 명령어 중 위험 커맨드 자동 차단 |

---

## 사전 요구사항

### 시스템 도구

| 도구 | 설치 방법 | 용도 |
|------|-----------|------|
| **binwalk** | `pip install binwalk` 또는 `apt install binwalk` | 펌웨어 추출 |
| **grype** | [GitHub Releases](https://github.com/anchore/grype/releases) | CVE 스캔 |
| **Gemini CLI** | `npm install -g @google/gemini-cli` | AI VEX 분석 |
| **sbom_claude_scripts** | 프로젝트 루트에 바이너리 배치 | SBOM 생성 (syft 기반) |

> **Gemini CLI 인증**: API 키가 아닌 Google 계정(Gemini Advanced 구독)으로 OAuth 인증합니다.  
> 최초 실행 전 터미널에서 `gemini` 명령어를 한 번 실행하여 로그인해 두세요.

### 런타임

- Python 3.10+
- Node.js 18+ (nvm 사용 권장 — `start.sh`에서 자동 설치)

---

## 설치 및 실행

### 빠른 시작 (`start.sh`)

```bash
# 저장소 클론
git clone <repo-url> firmcore
cd firmcore

# sbom_claude_scripts 바이너리를 프로젝트 루트에 배치
cp /path/to/sbom_claude_scripts ./sbom_claude_scripts
chmod +x ./sbom_claude_scripts

# 환경 변수 설정 (선택 — Gemini 모델/턴 수 조정 시)
cp .env.example .env

# 서버 시작 (백엔드 :8080 + 프론트엔드 :5173)
./start.sh
```

#### start.sh 옵션

```bash
./start.sh                  # 백엔드 + 프론트엔드 동시 시작
./start.sh --mock           # MOCK 모드 (실제 도구 없이 테스트)
./start.sh --backend-only   # 백엔드만 시작
./start.sh --frontend-only  # 프론트엔드만 시작
```

### 수동 실행 (개발)

```bash
# 백엔드
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# 프론트엔드 (다른 터미널)
cd frontend
npm install
npm run dev
```

---

## 환경 변수

`.env` 파일 또는 셸 환경에서 설정합니다.

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `MOCK_PIPELINE` | `false` | `true`로 설정 시 전체 파이프라인을 더미 데이터로 시뮬레이션 |
| `STORAGE_DIR` | `./storage` | 분석 결과 저장 경로 |
| `SBOM_BIN` | `./sbom_claude_scripts` | SBOM 생성 바이너리 경로 |
| `GEMINI_MODEL` | `gemini-2.5-pro` | Gemini 모델 ID |
| `VEX_MAX_TURNS` | `15` | CVE당 최대 Gemini 대화 턴 수 |
| `VEX_COMMAND_TIMEOUT` | `300` | 쉘 명령어 실행 타임아웃 (초) |

---

## 디렉토리 구조

```
firmcore/
├── backend/
│   ├── main.py               # FastAPI 앱 진입점 + lifespan (DB 초기화)
│   ├── db.py                 # aiosqlite 연결 관리, 스키마(jobs/job_events), CRUD
│   ├── event_bus.py          # 인메모리 SSE 이벤트 버스
│   ├── api/
│   │   ├── upload.py         # POST /api/upload — 펌웨어 업로드 및 파이프라인 시작
│   │   └── jobs.py           # GET /api/jobs, SSE 스트림, 결과 조회, VEX 재실행
│   ├── models/
│   │   └── job.py            # Pydantic 모델 (JobResult, CveResult, SbomComponent 등)
│   └── pipeline/
│       ├── runner.py         # 파이프라인 오케스트레이터 (4단계 순차 실행)
│       ├── extractor.py      # binwalk 래퍼 — rootfs 추출 및 감지
│       ├── sbom.py           # sbom_claude_scripts 래퍼 — CycloneDX SBOM 생성
│       ├── scanner.py        # grype 래퍼 — CVE 스캔 및 파싱
│       ├── vex.py            # Gemini CLI 기반 VEX 분석 엔진
│       ├── mock.py           # MOCK_PIPELINE 모드용 더미 파이프라인
│       └── vex_system_prompt_v2.md  # Gemini 시스템 프롬프트
├── frontend/
│   └── src/
│       ├── api/client.ts     # API 클라이언트 (업로드, 잡 조회, SSE, VEX 재실행)
│       ├── hooks/
│       │   ├── useJobList.ts     # 잡 목록 폴링 훅
│       │   └── useJobDetail.ts   # SSE 스트리밍 + VEX 재실행 훅
│       ├── pages/
│       │   ├── Dashboard.tsx     # 잡 목록 대시보드
│       │   └── JobDetail/
│       │       ├── JobDetail.tsx         # 잡 상세 페이지
│       │       ├── VexAnalysisTab.tsx    # VEX 판정 + AI 분석 리포트 탭
│       │       ├── SbomTab.tsx           # SBOM 컴포넌트 탭
│       │       └── ScanTab.tsx           # CVE 스캔 결과 탭
│       └── types/index.ts    # TypeScript 타입 정의
├── storage/                  # 잡별 분석 결과 (자동 생성)
│   └── {job_id}/
│       ├── firmware.img      # 업로드된 원본 펌웨어
│       ├── extracted/        # binwalk 추출 결과 (rootfs 포함)
│       ├── sbom.cdx.json     # CycloneDX SBOM
│       ├── scan.json         # grype CVE 스캔 결과
│       ├── combined_vex.json # 전체 CVE OpenVEX 문서 (x_firmcore_report 포함)
│       └── vex/
│           ├── {CVE-ID}_vex.json       # CVE별 OpenVEX 문서
│           ├── {CVE-ID}_report.md      # CVE별 AI 분석 요약 보고서
│           ├── {CVE-ID}_analysis.md    # 전체 분석 컨텍스트
│           └── {CVE-ID}_turn_N.md      # 턴별 대화 기록
├── sbom_claude_scripts       # SBOM 생성 바이너리 (직접 배치)
├── start.sh                  # 원클릭 개발 서버 시작 스크립트
└── .env.example              # 환경 변수 예시
```

---

## API 엔드포인트

| Method | 경로 | 설명 |
|--------|------|------|
| `POST` | `/api/upload` | 펌웨어 업로드 및 분석 파이프라인 시작 |
| `GET` | `/api/jobs` | 잡 목록 조회 (`limit`, `offset` 쿼리 파라미터) |
| `GET` | `/api/jobs/{job_id}/stream` | SSE 실시간 진행 로그 스트리밍 |
| `GET` | `/api/jobs/{job_id}/result` | 분석 결과 조회 (SBOM + CVE + VEX 병합) |
| `POST` | `/api/jobs/{job_id}/retry-vex` | VEX 분석만 단독 재실행 |
| `GET` | `/health` | 헬스체크 |

### SSE 이벤트 타입

| 이벤트 | 설명 |
|--------|------|
| `stage_start` | 파이프라인 단계 시작 |
| `stage_progress` | 단계 진행률 및 로그 |
| `stage_complete` | 단계 완료 (경과 시간 포함) |
| `stage_error` | 단계 오류 |
| `job_complete` | 전체 파이프라인 완료 |
| `cve_start` | CVE 분석 시작 (index/total 포함) |
| `gemini_response` | Gemini 응답 수신 (턴별) |
| `executing_command` | Gemini가 생성한 쉘 명령어 실행 |
| `command_result` | 명령어 실행 결과 (차단 여부 포함) |
| `vex_complete` | CVE VEX 판정 완료 (status, report_text) |
| `vex_json_not_found` | Gemini 응답에서 OpenVEX JSON 추출 실패 → under_investigation fallback |
| `cve_done` | CVE 처리 완료 |
| `keepalive` | 연결 유지 신호 (10초 주기) |

---

## 잡 상태 흐름

```
pending
    │
    ▼
extracting         binwalk 추출
    │
    ▼
sbom_generating    SBOM 생성
    │
    ▼
scanning           CVE 스캔
    │
    ▼
vex_analyzing      AI VEX 분석  ◄── retry-vex 재진입 지점
    │
    ├── completed
    └── failed
```

---

## VEX 분석 상세

### Gemini CLI 연동 방식

- `gemini --model {GEMINI_MODEL} -p " "` 로 headless 실행
- 대화 이력을 stdin으로 전달 (최근 8턴 슬라이딩 윈도우)
- Gemini가 bash 코드 블록을 출력하면 추출하여 격리된 환경에서 실행
- 실행 결과를 다음 턴 입력에 포함하여 멀티턴 분석

### 보안 커맨드 필터

위험한 명령어 패턴(rm, dd, mkfs, curl 등 파일 수정/네트워크 요청)은 자동 차단됩니다.  
차단된 명령어는 로그에 `⛔ 차단:` 으로 표시됩니다.

### 출력 형식

Gemini는 CVE당 두 가지를 출력합니다:

1. **분석 요약 보고서** — 3단계 도달성 분석 결과를 자연어로 서술
2. **OpenVEX JSON** — `not_affected` / `affected` / `under_investigation` / `fixed` 판정

두 결과는 각각 `{CVE-ID}_report.md`와 `{CVE-ID}_vex.json`으로 저장되며,  
`combined_vex.json`의 `x_firmcore_report` 필드를 통해 웹 UI에서 표시됩니다.

---

## 라이선스

MIT
