#!/usr/bin/env bash
# FirmCore 로컬 개발 서버 시작 스크립트
# 사용법: ./start.sh [--mock] [--backend-only] [--frontend-only]
set -uo pipefail

# ── 색상 출력 ────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; GRAY='\033[0;90m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR ]${NC}  $*" >&2; }
sep()   { echo -e "${GRAY}──────────────────────────────────────────────${NC}"; }

# ── 인자 파싱 ─────────────────────────────────────────────────────────────────
MOCK=false
RUN_BACKEND=true
RUN_FRONTEND=true

for arg in "$@"; do
  case $arg in
    --mock)          MOCK=true ;;
    --backend-only)  RUN_FRONTEND=false ;;
    --frontend-only) RUN_BACKEND=false ;;
    --help|-h)
      echo "Usage: $0 [--mock] [--backend-only] [--frontend-only]"
      echo "  --mock           MOCK_PIPELINE=true (Gemini/binwalk/grype 없이 테스트)"
      echo "  --backend-only   백엔드만 실행"
      echo "  --frontend-only  프론트엔드만 실행"
      exit 0 ;;
    *) error "Unknown option: $arg"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

sep
echo -e "${GREEN}  FirmCore — Firmware Vulnerability Analyzer${NC}"
sep

# ── .env 로드 ─────────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | grep -v '^$' | xargs)
  ok ".env 로드 완료"
elif [[ -f .env.example ]]; then
  warn ".env 파일이 없습니다. .env.example을 복사합니다."
  cp .env.example .env
  warn "GEMINI_API_KEY를 .env에 설정하세요 (VEX 분석에 필요)"
fi

# ── Node.js 확인 및 nvm 자동 설치 ────────────────────────────────────────────
setup_node() {
  # nvm 로드 시도
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  if [[ -s "$NVM_DIR/nvm.sh" ]]; then
    # shellcheck disable=SC1090
    source "$NVM_DIR/nvm.sh"
  fi

  if command -v node &>/dev/null; then
    NODE_VER=$(node --version | sed 's/v//')
    NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
    if [[ $NODE_MAJOR -ge 18 ]]; then
      ok "Node.js v${NODE_VER} 확인"
      return 0
    else
      warn "Node.js v${NODE_VER}는 너무 오래됐습니다 (v18+ 필요). nvm으로 업그레이드합니다."
    fi
  else
    warn "Node.js가 없습니다. nvm으로 설치합니다."
  fi

  # nvm 설치
  if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
    info "nvm 설치 중..."
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
    source "$NVM_DIR/nvm.sh"
  fi

  info "Node.js 20 설치 중..."
  nvm install 20 --no-progress
  nvm use 20
  ok "Node.js $(node --version) 준비 완료"
}

# ── Python venv 확인 및 의존성 설치 ──────────────────────────────────────────
setup_python() {
  if [[ ! -d backend/.venv ]]; then
    info "Python 가상환경 생성 중..."
    python3 -m venv backend/.venv
  fi

  # shellcheck disable=SC1091
  source backend/.venv/bin/activate

  info "Python 패키지 확인 중..."
  pip install -q -r backend/requirements.txt
  ok "Python 의존성 준비 완료"
}

# ── sbom_claude_scripts 실행 권한 확인 ───────────────────────────────────────
setup_sbom_bin() {
  SBOM_BIN="${SBOM_BIN:-$SCRIPT_DIR/sbom_claude_scripts}"
  if [[ -f "$SBOM_BIN" ]]; then
    if [[ ! -x "$SBOM_BIN" ]]; then
      chmod +x "$SBOM_BIN"
      ok "sbom_claude_scripts 실행 권한 부여"
    else
      ok "sbom_claude_scripts 준비 완료"
    fi
  else
    warn "sbom_claude_scripts 바이너리가 없습니다: $SBOM_BIN"
    warn "SBOM 단계는 건너뛰거나 --mock 모드를 사용하세요."
  fi
}

# ── 포트 충돌 해결 ───────────────────────────────────────────────────────────
kill_port() {
  local port=$1
  local pids
  pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    warn "포트 ${port}가 사용 중입니다. 기존 프로세스를 종료합니다. (PID: $pids)"
    echo "$pids" | xargs kill -9 2>/dev/null || true
    sleep 1
    ok "포트 ${port} 해제 완료"
  fi
}

# ── storage 디렉토리 생성 ─────────────────────────────────────────────────────
mkdir -p storage
ok "storage/ 디렉토리 확인"

# ── 백엔드 시작 ───────────────────────────────────────────────────────────────
start_backend() {
  info "백엔드 설정 중..."
  setup_python
  setup_sbom_bin

  source backend/.venv/bin/activate

  BACKEND_ENV=(
    "MOCK_PIPELINE=$( $MOCK && echo true || echo false )"
    "SBOM_BIN=${SBOM_BIN:-$SCRIPT_DIR/sbom_claude_scripts}"
    "STORAGE_DIR=$SCRIPT_DIR/storage"
    "PATH=$PATH"
    "HOME=$HOME"
  )

  if [[ -n "${GEMINI_API_KEY:-}" ]]; then
    BACKEND_ENV+=("GEMINI_API_KEY=$GEMINI_API_KEY")
  fi

  kill_port 8080

  sep
  if $MOCK; then
    info "백엔드 시작 (MOCK 모드) → http://localhost:8080"
  else
    info "백엔드 시작 → http://localhost:8080"
  fi

  env "${BACKEND_ENV[@]}" \
    uvicorn main:app \
      --host 0.0.0.0 \
      --port 8080 \
      --reload \
      --reload-dir "$SCRIPT_DIR/backend" \
      --app-dir "$SCRIPT_DIR/backend" \
      --log-level info \
    &
  BACKEND_PID=$!
  echo $BACKEND_PID > /tmp/firmcore_backend.pid

  # 백엔드 헬스체크 대기
  info "백엔드 준비 대기 중..."
  for i in $(seq 1 20); do
    if curl -sf http://localhost:8080/health &>/dev/null; then
      ok "백엔드 준비 완료 (${i}초)"
      break
    fi
    sleep 1
    if [[ $i -eq 20 ]]; then
      error "백엔드 시작 실패 (20초 초과)"
      exit 1
    fi
  done
}

# ── 프론트엔드 시작 ───────────────────────────────────────────────────────────
start_frontend() {
  info "프론트엔드 설정 중..."
  setup_node

  kill_port 5173

  cd "$SCRIPT_DIR/frontend"

  if [[ ! -d node_modules ]]; then
    info "npm 패키지 설치 중..."
    npm install --legacy-peer-deps
    ok "npm 패키지 설치 완료"
  else
    ok "node_modules 이미 존재 (스킵)"
  fi

  sep
  info "프론트엔드 시작 → http://localhost:5173"

  npm run dev &
  FRONTEND_PID=$!
  echo $FRONTEND_PID > /tmp/firmcore_frontend.pid

  cd "$SCRIPT_DIR"
}

# ── 종료 핸들러 ───────────────────────────────────────────────────────────────
_CLEANUP_DONE=false

kill_gemini_procs() {
  # gemini 프로세스와 그 프로세스 그룹 전체를 종료
  # pgrep으로 PID 목록 수집 후 각각의 pgid로 kill
  local pids
  pids=$(pgrep -f "bin/gemini" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    warn "잔여 Gemini 프로세스 종료: $(echo "$pids" | tr '\n' ' ')"
    while IFS= read -r pid; do
      # 프로세스 그룹 전체 종료 (gemini가 setsid로 새 세션 생성하므로 pgid 필요)
      local pgid
      pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
      if [[ -n "$pgid" && "$pgid" != "0" ]]; then
        kill -KILL -- "-$pgid" 2>/dev/null || true
      else
        kill -KILL "$pid" 2>/dev/null || true
      fi
    done <<< "$pids"
  fi
}

cleanup() {
  # 중복 실행 방지 (bash에서 bool 비교는 문자열로)
  [[ "$_CLEANUP_DONE" == "true" ]] && return
  _CLEANUP_DONE=true

  echo ""
  sep
  info "서버 종료 중... (잠시 기다려 주세요)"

  # ── 백엔드 종료 (graceful → lifespan이 Gemini 정리) ────────────────────────
  if [[ -f /tmp/firmcore_backend.pid ]]; then
    BACKEND_PID=$(cat /tmp/firmcore_backend.pid)
    rm -f /tmp/firmcore_backend.pid
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
      info "백엔드 종료 신호 전송 (PID: $BACKEND_PID)"
      kill -TERM "$BACKEND_PID" 2>/dev/null || true
      # 최대 10초 대기: uvicorn lifespan이 Gemini 프로세스를 정리하는 시간
      for i in $(seq 1 10); do
        kill -0 "$BACKEND_PID" 2>/dev/null || break
        sleep 1
      done
      # 아직 살아있으면 강제 종료
      if kill -0 "$BACKEND_PID" 2>/dev/null; then
        warn "백엔드 응답 없음 — 강제 종료"
        kill -KILL "$BACKEND_PID" 2>/dev/null || true
        # 워커 프로세스도 함께 정리
        pkill -KILL -P "$BACKEND_PID" 2>/dev/null || true
      fi
    fi
  fi

  # ── 프론트엔드 종료 ────────────────────────────────────────────────────────
  if [[ -f /tmp/firmcore_frontend.pid ]]; then
    FRONTEND_PID=$(cat /tmp/firmcore_frontend.pid)
    rm -f /tmp/firmcore_frontend.pid
    if kill -0 "$FRONTEND_PID" 2>/dev/null; then
      kill -TERM "$FRONTEND_PID" 2>/dev/null || true
      sleep 1
      kill -KILL "$FRONTEND_PID" 2>/dev/null || true
      pkill -KILL -P "$FRONTEND_PID" 2>/dev/null || true
    fi
  fi

  # ── 잔여 Gemini 프로세스 강제 종료 (보험) ─────────────────────────────────
  kill_gemini_procs

  ok "종료 완료"
  exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# ── 실행 ─────────────────────────────────────────────────────────────────────
$RUN_BACKEND  && start_backend
$RUN_FRONTEND && start_frontend

sep
ok "FirmCore 실행 중"
if $MOCK; then
  echo -e "  ${YELLOW}모드${NC}         : MOCK (실제 파이프라인 없이 시뮬레이션)"
fi
if $RUN_FRONTEND; then
  echo -e "  ${CYAN}프론트엔드${NC}   : http://localhost:5173"
fi
if $RUN_BACKEND; then
  echo -e "  ${CYAN}백엔드 API${NC}   : http://localhost:8080"
  echo -e "  ${CYAN}Swagger UI${NC}   : http://localhost:8080/api/docs"
fi
echo -e "  ${GRAY}종료${NC}         : Ctrl+C"
sep

wait
