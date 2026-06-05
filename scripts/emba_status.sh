#!/usr/bin/env bash
# emba_status — FirmCore 잡의 EMBA 진행 상태를 한 화면에 요약.
#
# 모든 산출물이 Ubuntu native (``storage/<JOB>/emba_logs/``) 에 떨어지므로
# WSL 간 호출/9P bridge 같은 우회는 없다.
#
# 사용법:
#   bash ~/firmcore/scripts/emba_status.sh           # 가장 최근 활성 잡
#   bash ~/firmcore/scripts/emba_status.sh <JOB>     # ULID substring 매칭
#   bash ~/firmcore/scripts/emba_status.sh -w        # watch 모드 (2초마다 갱신)
#
# 출력:
#   1. 잡 디렉토리 + firmware
#   2. emba.log 마지막 8줄 (모듈 진행)
#   3. 완료된 모듈 (p##/s##/f##) 목록
#   4. 산출물 핵심 파일 (SBOM / scan.json / vex 등)
#   5. 활성 EMBA docker 컨테이너
#   6. 상태 판정 (분석 중 / 완료 / 멈춤)

set -uo pipefail

STORAGE="${STORAGE_DIR:-/home/ktdevice/firmcore/storage}"

usage() {
  sed -n '2,18p' "$0"
  exit 0
}

# ── 인자 ────────────────────────────────────────────────────────────────────
WATCH=0
JOB_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--watch) WATCH=1; shift ;;
    -h|--help)  usage ;;
    *)          JOB_ARG="$1"; shift ;;
  esac
done

if (( WATCH )); then
  exec watch -n 2 -c "bash $0 ${JOB_ARG:-}"
fi

# ── 잡 디렉토리 결정 ────────────────────────────────────────────────────────
if [[ -n "$JOB_ARG" ]]; then
  JOB_DIR=$(ls -d "$STORAGE"/*"$JOB_ARG"*/ 2>/dev/null | head -1)
  if [[ -z "$JOB_DIR" ]]; then
    echo "ERROR: '$JOB_ARG' 와 매칭되는 잡 디렉토리 없음 ($STORAGE/)"
    exit 1
  fi
else
  # 가장 최근 mtime — emba_logs 존재하는 잡 우선, 없으면 그냥 최신 storage 디렉토리
  JOB_DIR=$(ls -dt "$STORAGE"/*/emba_logs 2>/dev/null | head -1)
  if [[ -n "$JOB_DIR" ]]; then
    JOB_DIR=$(dirname "$JOB_DIR")
  else
    JOB_DIR=$(ls -dt "$STORAGE"/*/ 2>/dev/null | head -1)
  fi
fi
JOB_DIR="${JOB_DIR%/}"

if [[ -z "$JOB_DIR" || ! -d "$JOB_DIR" ]]; then
  echo "활성 잡 없음 ($STORAGE/ 비어있음)"
  exit 0
fi

JOB_ID=$(basename "$JOB_DIR")
LOG_DIR="$JOB_DIR/emba_logs"
EMBA_LOG="$LOG_DIR/emba.log"

# ── 헤더 ────────────────────────────────────────────────────────────────────
sep() { printf '─%.0s' {1..70}; echo; }
sep
echo " EMBA Status — $JOB_ID"
sep

# (1) 잡 디렉토리 + firmware
echo "▶ Storage : $JOB_DIR"
echo "▶ Log dir : $LOG_DIR"
FW=$(ls "$JOB_DIR"/firmware.* 2>/dev/null | head -1)
[[ -n "$FW" ]] && echo "▶ Firmware: $(basename "$FW") ($(stat -c '%s' "$FW" 2>/dev/null) bytes)"

# (2) emba.log 마지막 라인
echo
sep
echo " EMBA log — last 8 lines"
sep
if [[ -f "$EMBA_LOG" ]]; then
  tail -8 "$EMBA_LOG" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g'
else
  echo "  (emba.log 아직 생성 전 — EMBA 가 초기화 단계일 수 있음)"
fi

# (3) 완료된 모듈
echo
sep
echo " 완료된 모듈 (디렉토리 단위)"
sep
if [[ -d "$LOG_DIR" ]]; then
  shopt -s nullglob
  MODS=()
  for d in "$LOG_DIR"/{p,s,f}*_*/; do
    [[ -d "$d" ]] && MODS+=("$(basename "$d")")
  done
  shopt -u nullglob
  if (( ${#MODS[@]} > 0 )); then
    printf '  %s\n' "${MODS[@]}"
    echo
    echo "  총 ${#MODS[@]} 개 모듈"
  else
    echo "  (모듈 디렉토리 없음 — 의존성 체크 단계일 수 있음)"
  fi
else
  echo "  (log_dir 미존재 — EMBA 시작 전)"
fi

# (4) FirmCore 산출물 (storage 직속)
echo
sep
echo " FirmCore 산출물 (storage/<job>/)"
sep
for f in sbom.raw.json sbom.fix.json sbom.cdx.json sbom.cdx.audit.json \
         cpe_mapper.log scan.json combined_vex.json; do
  if [[ -f "$JOB_DIR/$f" ]]; then
    SZ=$(stat -c '%s' "$JOB_DIR/$f" 2>/dev/null)
    printf "  ✓ %-25s %10s bytes\n" "$f" "$SZ"
  else
    printf "  · %-25s (아직 없음)\n" "$f"
  fi
done
# VEX CVE 개수
if [[ -d "$JOB_DIR/vex" ]]; then
  VEX_N=$(ls "$JOB_DIR/vex"/*_vex.json 2>/dev/null | wc -l)
  printf "  ✓ %-25s %d files\n" "vex/" "$VEX_N"
fi

# (5) EMBA log_dir 내부 핵심 파일
echo
sep
echo " EMBA 내부 산출물 (emba_logs/)"
sep
for f in \
  "SBOM/EMBA_cyclonedx_sbom.json" \
  "f15_cyclonedx_sbom.txt" \
  "s08_main_package_sbom.txt" \
  "p15_ubi_extractor.txt" \
  "p50_binwalk_extractor.txt" \
  "html-report/index.html"; do
  if [[ -f "$LOG_DIR/$f" ]]; then
    SZ=$(stat -c '%s' "$LOG_DIR/$f" 2>/dev/null)
    printf "  ✓ %-42s %10s bytes\n" "$f" "$SZ"
  else
    printf "  · %-42s (아직 없음)\n" "$f"
  fi
done

# (6) Docker 컨테이너 — Ubuntu 자체 docker daemon
echo
sep
echo " Docker — EMBA 컨테이너"
sep
docker ps -a --filter "name=emba-emba" \
  --format "  {{.Names}}\t{{.Status}}\t{{.RunningFor}}" 2>&1 | head -10

# (7) 진행 추정
echo
sep
ACTIVE_CT=$(docker ps --filter "name=emba-emba-run" --format "{{.Names}}" 2>/dev/null | wc -l)
if (( ACTIVE_CT > 0 )); then
  echo " 상태: 🟢 분석 진행 중 (active container $ACTIVE_CT 개)"
elif [[ -f "$LOG_DIR/html-report/index.html" ]] && [[ -f "$JOB_DIR/sbom.cdx.json" ]]; then
  echo " 상태: ✅ EMBA + SBOM 후처리 완료"
elif [[ -f "$EMBA_LOG" ]] && grep -q "Test ended" "$EMBA_LOG" 2>/dev/null; then
  echo " 상태: ✅ EMBA 종료 (emba.log 의 'Test ended' 확인) — FirmCore 후속 단계 진행 중일 수 있음"
elif [[ -d "$LOG_DIR" ]]; then
  echo " 상태: ⚠ 활성 컨테이너 없음 + html-report 미생성 — 멈췄거나 실패 가능성"
else
  echo " 상태: ⏳ EMBA 시작 전"
fi
sep

# (8) DB 의 잡 상태 (있으면)
if command -v sqlite3 &>/dev/null && [[ -f /home/ktdevice/firmcore/data/firmcore.db ]]; then
  DB_STATUS=$(sqlite3 /home/ktdevice/firmcore/data/firmcore.db \
    "SELECT status || ' (' || COALESCE(current_stage,'?') || ')' FROM jobs WHERE id='$JOB_ID';" 2>/dev/null)
  [[ -n "$DB_STATUS" ]] && echo " DB 상태: $DB_STATUS"
fi
