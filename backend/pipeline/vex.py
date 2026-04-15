"""
vex.py — Gemini CLI + 정적 분석 기반 자동화 VEX 분석기

"Gemini가 분석 명령어 추천 → 백엔드가 rootfs에서 실행 → 결과를 Gemini에 피드백"
하는 멀티턴 루프로 OpenVEX 문서를 자동 생성합니다.

시스템 프롬프트 로드 우선순위:
  1. VEX_SYSTEM_PROMPT 환경변수 경로
  2. 프로젝트 루트 / vex_system_prompt_v2.md
  3. 프로젝트 루트 / vex_system_prompt.md
  4. 내장 기본 프롬프트 (fallback)

Usage:
    async for event in run_vex_analysis_loop(cve_id, rootfs_path, product_info, output_dir):
        match event["type"]:
            case "gemini_response":   print(event["content"][:120])
            case "executing_command": print(f"$ {event['command']}")
            case "command_result":    print(event["result"][:200])
            case "vex_complete":      save(event["vex_document"])
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_TURNS = int(os.environ.get("VEX_MAX_TURNS", "15"))
COMMAND_TIMEOUT = int(os.environ.get("VEX_COMMAND_TIMEOUT", "300"))  # seconds per shell command
GEMINI_TIMEOUT = 300        # seconds per Gemini CLI call
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
MAX_CMD_OUTPUT_CHARS = 3000  # truncate per command result sent back to Gemini

# CVE 간 딜레이 (Gemini rate limit 방지)
CVE_INTER_DELAY = int(os.environ.get("VEX_CVE_DELAY", "5"))  # seconds between CVEs

# 요청 제한 재시도: 지수 백오프 (30s, 60s, 120s)
_RATE_LIMIT_BACKOFF = [30, 60, 120]

# ANSI 이스케이프 코드 제거 (대화형 CLI 출력 정제용)
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)

# ---------------------------------------------------------------------------
# Security: command blacklist
# ---------------------------------------------------------------------------
# rootfs 바깥 탈출, 네트워크 접근, 파일시스템 파괴 등 위험 패턴
_BLACKLIST_RULES: list[tuple[str, str]] = [
    (r"\brm\s+-[^\s]*[rf]",    "파일 삭제 명령 (rm -rf)"),
    (r"\bdd\b",                 "디스크 덤프/쓰기 (dd)"),
    (r"\bmkfs\b",               "파일시스템 포맷 (mkfs)"),
    (r"\bwget\b",               "네트워크 다운로드 (wget)"),
    (r"\bcurl\b",               "네트워크 요청 (curl)"),
    (r"\bchmod\b",              "권한 변경 (chmod)"),
    (r"\bchown\b",              "소유자 변경 (chown)"),
    (r"\bmount\b",              "마운트 명령 (mount)"),
    (r"\bumount\b",             "마운트 해제 (umount)"),
    (r"\biptables\b",           "방화벽 설정 (iptables)"),
    (r"\bsudo\b",               "권한 상승 (sudo)"),
    (r"\bsu\s",                 "사용자 전환 (su)"),
    (r"\bnc\b.*-[el]",          "Netcat 리스너"),
    (r"\beval\b",               "동적 코드 실행 (eval)"),
    (r"(?<!\d)(?<!2)>\s*/dev/(?!null)",  "/dev 장치 쓰기"),
    (r"\|\s*(?:sh|bash|zsh)\b", "파이프를 셸로 전달"),
    (r"[;&]\s*rm\b",            "체인 후 rm 실행"),
    (r"\.\.[\\/]\.\.[\\/]",    "경로 탈출 (../../)"),
    (r"\bpython[23]?\s+-[cm]\b","Python 모듈/코드 실행"),
]
_BLACKLIST_PATTERNS = [
    (re.compile(pat, re.IGNORECASE), reason)
    for pat, reason in _BLACKLIST_RULES
]

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    returncode: int
    elapsed: float          # seconds
    blocked: bool = False
    block_reason: Optional[str] = None


@dataclass
class VexStatement:
    cve_id: str
    status: str             # not_affected | affected | under_investigation
    justification: Optional[str]
    # vulnerable_code_not_present | vulnerable_code_not_in_execute_path |
    # inline_mitigations_already_exist | None
    impact_statement: str
    analysis_turns: int = 0
    report_text: str = ""   # 분석 요약 보고서 (OpenVEX JSON 앞의 텍스트)


@dataclass
class VexResult:
    vex_document_path: Path
    statements: list[VexStatement] = field(default_factory=list)
    not_affected_count: int = 0
    affected_count: int = 0
    under_investigation_count: int = 0


# ---------------------------------------------------------------------------
# System prompt loading
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_CACHE: Optional[str] = None


def _load_system_prompt() -> str:
    global _SYSTEM_PROMPT_CACHE
    if _SYSTEM_PROMPT_CACHE is not None:
        return _SYSTEM_PROMPT_CACHE

    candidates = [
        Path(os.environ.get("VEX_SYSTEM_PROMPT", "")),
        Path(__file__).parent / "vex_system_prompt_v2.md",
        Path(__file__).parent / "vex_system_prompt.md",
    ]
    for path in candidates:
        if path and path.is_file():
            _SYSTEM_PROMPT_CACHE = path.read_text(encoding="utf-8")
            logger.info("VEX 시스템 프롬프트 로드: %s", path)
            return _SYSTEM_PROMPT_CACHE

    logger.warning(
        "vex_system_prompt_v2.md 를 찾을 수 없습니다. 내장 기본 프롬프트 사용."
    )
    _SYSTEM_PROMPT_CACHE = _DEFAULT_SYSTEM_PROMPT
    return _SYSTEM_PROMPT_CACHE


# 시스템 프롬프트 파일이 없을 경우 사용할 최소 내장 프롬프트
_DEFAULT_SYSTEM_PROMPT = """\
당신은 임베디드 펌웨어 정적 분석 기반의 VEX(Vulnerability Exploitability eXchange) \
생성 전문가입니다. CVE 코드와 대상 소프트웨어를 입력받으면, 해당 취약점이 실제 \
rootfs 환경에서 도달 가능(Reachable)한지를 3단계로 체계적으로 검증하고, \
최종적으로 OpenVEX 형식의 문서를 생성합니다.

핵심 원칙:
- "존재 ≠ 취약": 라이브러리에 취약 코드가 있어도, 실행 경로에서 호출되지 않으면 영향 없음
- 3단계 도달 가능성 분석(Library → Binary → Configuration)을 순서대로 수행
- 각 단계에서 "없음"이 확인되면 즉시 VEX 판정으로 넘어감

분석 환경 특이사항:
- 분석 대상은 임베디드 펌웨어 rootfs (MIPS/ARM 아키텍처 등)
- 호스트에서 정적 분석 (nm, readelf, strings, file 등 사용)
- 파일 권한이 보존되지 않을 수 있으므로 ELF 매직바이트(\x7fELF) 기반 탐지 필수
- -executable, -perm +x 등 권한 기반 탐지 옵션 사용 금지

응답 규칙:
- 한 번에 하나의 단계 명령어만 제공 (단계별 순차 분석)
- 명령어는 반드시 ```bash 코드블록으로 제공
- 최종 판단이 완료되면 OpenVEX JSON을 ```json 코드블록으로 응답에 포함
- OpenVEX JSON 컨텍스트: https://openvex.dev/ns/v0.2.0

VEX 상태값:
- not_affected / vulnerable_code_not_present: 라이브러리에 취약 코드 없음
- not_affected / vulnerable_code_not_in_execute_path: 코드 있으나 호출 경로 없음
- not_affected / inline_mitigations_already_exist: 호출 경로 있으나 모든 설정 레이어에서 비활성화
- affected: 1~3단계 모두 취약 조건 충족
- under_investigation: 결론이 불분명하여 추가 분석 필요

한국어로 응답해주세요.
"""


# ---------------------------------------------------------------------------
# Command extraction
# ---------------------------------------------------------------------------


def extract_commands_from_response(response: str) -> list[str]:
    """
    Gemini 응답의 ```bash 코드블록에서 실행할 스크립트를 추출합니다.

    규칙:
    - ```bash 또는 ```sh 블록 하나를 스크립트 하나로 취급
    - 블록 내 주석(#), 빈 줄은 그대로 유지 (bash가 처리)
    - 멀티라인 while/if/for 구문을 줄 단위로 쪼개지 않음
    """
    commands: list[str] = []
    block_re = re.compile(r"```(?:bash|sh)\n(.*?)```", re.DOTALL)

    for match in block_re.finditer(response):
        script = match.group(1).strip()
        if script:
            commands.append(script)

    return commands


# ---------------------------------------------------------------------------
# Security check
# ---------------------------------------------------------------------------


def _check_command_safety(cmd: str) -> tuple[bool, Optional[str]]:
    """
    명령어가 안전한지 검사합니다.

    Returns
    -------
    (is_safe, block_reason)
    """
    for pattern, reason in _BLACKLIST_PATTERNS:
        if pattern.search(cmd):
            return False, reason
    return True, None


# ---------------------------------------------------------------------------
# Command execution in rootfs
# ---------------------------------------------------------------------------


async def execute_command_in_rootfs(
    cmd: str,
    rootfs_path: str,
) -> CommandResult:
    """
    rootfs_path를 cwd로 설정하여 명령어를 실행합니다.

    Parameters
    ----------
    cmd:
        실행할 shell 명령어.
    rootfs_path:
        rootfs 디렉토리 경로 (cwd로 사용). str 타입.

    Returns
    -------
    CommandResult
        실행 결과. blocked=True 이면 보안 차단된 명령어.
    """
    # ── 보안 검사 ─────────────────────────────────────────────────────────
    is_safe, block_reason = _check_command_safety(cmd)
    if not is_safe:
        logger.warning("[VEX] 명령어 차단: %.80s ← %s", cmd, block_reason)
        return CommandResult(
            command=cmd,
            stdout="",
            stderr=f"[보안 차단] {block_reason}",
            returncode=-1,
            elapsed=0.0,
            blocked=True,
            block_reason=block_reason,
        )

    # ── rootfs 경로 존재 확인 ─────────────────────────────────────────────
    if not Path(rootfs_path).exists():
        return CommandResult(
            command=cmd,
            stdout="",
            stderr=f"[오류] rootfs 경로 없음: {rootfs_path}",
            returncode=-1,
            elapsed=0.0,
        )

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=rootfs_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # 분석 도구(nm, strings, readelf, find, grep, file, head)만 허용
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin",
                "HOME": "/tmp",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except OSError as exc:
        return CommandResult(
            command=cmd,
            stdout="",
            stderr=f"[실행 오류] {exc}",
            returncode=-1,
            elapsed=time.monotonic() - start,
        )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=COMMAND_TIMEOUT,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return CommandResult(
            command=cmd,
            stdout="",
            stderr=f"[타임아웃] {COMMAND_TIMEOUT}초 초과",
            returncode=-1,
            elapsed=time.monotonic() - start,
        )

    return CommandResult(
        command=cmd,
        stdout=stdout_b.decode(errors="replace"),
        stderr=stderr_b.decode(errors="replace"),
        returncode=proc.returncode or 0,
        elapsed=time.monotonic() - start,
    )


# ---------------------------------------------------------------------------
# Gemini caller (CLI headless 모드, 매 턴 단일 호출)
# ---------------------------------------------------------------------------

# 히스토리 슬라이딩 윈도우: 최근 N턴만 전달 (시스템프롬프트 + 이전 대화 크기 제한)
HISTORY_WINDOW = int(os.environ.get("VEX_HISTORY_WINDOW", "8"))  # 최근 8개 메시지 (4턴)


def _serialize_history_for_cli(history: list[dict]) -> str:
    """대화 히스토리를 gemini CLI stdin 형식으로 직렬화합니다. (슬라이딩 윈도우 적용)"""
    # 슬라이딩 윈도우: 가장 최근 HISTORY_WINDOW 개 메시지만 사용
    windowed = history[-HISTORY_WINDOW:] if len(history) > HISTORY_WINDOW else history
    parts = []
    for msg in windowed:
        role = "User" if msg["role"] == "user" else "Assistant"
        parts.append(f"[{role}]: {msg['content']}")
    return "\n\n".join(parts)


async def call_gemini(
    history: list[dict],
    new_message: str,
    cve_id: str,
    turn: int,
) -> str:
    """
    gemini CLI를 headless 모드(-p)로 호출하여 응답을 반환합니다.

    히스토리를 stdin으로 전달하고 새 메시지를 -p 인자로 넘깁니다.
    슬라이딩 윈도우를 적용해 최근 HISTORY_WINDOW 개 메시지만 전송합니다.
    """
    gemini_bin = shutil.which("gemini")
    if not gemini_bin:
        raise RuntimeError(
            "gemini CLI를 찾을 수 없습니다.\n"
            "  설치: npm install -g @google/gemini-cli\n"
            "  로그인: gemini  (첫 실행 시 Google 계정 인증)"
        )

    # stdin: 기존 대화 히스토리 (슬라이딩 윈도우)
    stdin_text = _serialize_history_for_cli(history) if history else ""
    stdin_bytes = stdin_text.encode("utf-8") if stdin_text else None

    deadline = time.monotonic() + GEMINI_TIMEOUT
    heartbeat_logged_at = time.monotonic()

    logger.info("[VEX] %s Turn %d — gemini 호출 (히스토리 %d개 메시지, 창 %d개)",
                cve_id, turn, len(history), min(len(history), HISTORY_WINDOW))

    proc = await asyncio.create_subprocess_exec(
        gemini_bin,
        "--model", GEMINI_MODEL,
        "--yolo",
        "-p", new_message,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # heartbeat 로그를 찍으면서 응답 대기
    async def _wait_with_heartbeat():
        nonlocal heartbeat_logged_at
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise RuntimeError(f"gemini 응답 타임아웃 ({GEMINI_TIMEOUT}초)")
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes),
                    timeout=min(30.0, remaining),
                )
                return stdout_b, stderr_b
            except asyncio.TimeoutError:
                now = time.monotonic()
                total_waited = now - (deadline - GEMINI_TIMEOUT)
                logger.info("[VEX] %s Turn %d — Gemini 응답 대기 중... (%.0fs 경과)",
                            cve_id, turn, total_waited)
                heartbeat_logged_at = now
                stdin_bytes_ref = None  # communicate는 한 번만 가능 → 재시도 불가

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes),
            timeout=GEMINI_TIMEOUT,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"gemini 응답 타임아웃 ({GEMINI_TIMEOUT}초)")

    response = stdout_b.decode("utf-8", errors="replace").strip()

    if proc.returncode != 0 and not response:
        stderr_text = stderr_b.decode("utf-8", errors="replace").strip()
        err_msg = stderr_text or f"종료 코드 {proc.returncode}"
        if "429" in err_msg or "quota exceeded" in err_msg.lower():
            raise RuntimeError(f"[RATE_LIMIT] {err_msg}")
        raise RuntimeError(f"gemini 오류: {err_msg}")

    logger.info("[VEX] %s Turn %d — 응답 수신 (%d chars)", cve_id, turn, len(response))
    return response


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def extract_json_from_response(response: str) -> Optional[dict]:
    """
    Gemini 응답에서 OpenVEX JSON 블록을 추출합니다.

    탐색 순서:
    1. ```json 코드블록 내 JSON
    2. 응답 전체에서 { ... } 직접 파싱 (openvex.dev 컨텍스트 존재 여부로 검증)
    """
    # 1. ```json 코드블록
    for match in re.finditer(r"```json\n(.*?)```", response, re.DOTALL):
        try:
            data = json.loads(match.group(1))
            if _is_openvex(data):
                return data
        except json.JSONDecodeError:
            continue

    # 2. 응답 내 raw JSON 오브젝트 탐색 (greedy → 가장 큰 블록 우선)
    for match in re.finditer(r"\{[\s\S]*\}", response):
        try:
            data = json.loads(match.group(0))
            if _is_openvex(data):
                return data
        except json.JSONDecodeError:
            continue

    return None


def _is_openvex(data: dict) -> bool:
    ctx = data.get("@context", "")
    return isinstance(ctx, str) and "openvex.dev" in ctx


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _format_results_for_gemini(
    commands: list[str],
    results: list[CommandResult],
) -> str:
    """명령어 실행 결과를 Gemini 다음 턴 메시지로 포맷합니다."""
    parts: list[str] = ["다음은 명령어 실행 결과입니다:\n"]

    for cmd, result in zip(commands, results):
        parts.append(f"```\n$ {cmd}\n```")
        if result.blocked:
            parts.append(f"> [보안 차단됨] {result.block_reason}\n")
            continue

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        rc = result.returncode

        # 타임아웃 명시적 처리
        if rc == -1 and "[타임아웃]" in stderr:
            parts.append(
                f"> ⏱ 명령 타임아웃 ({COMMAND_TIMEOUT}초 초과): 전수 조사 명령이 너무 오래 걸렸습니다.\n"
                f"> 더 좁은 범위를 대상으로 하는 명령으로 대체하거나,\n"
                f"> find 결과를 특정 디렉토리(usr/lib, usr/bin 등)로 한정해주세요.\n"
            )
            parts.append(f"> 실행 시간: {result.elapsed:.2f}s\n")
            continue

        # 셸 오류(rc=1,2 등)는 명확히 표시
        if rc not in (0, None) and not stdout:
            err_detail = stderr[:500] if stderr else f"종료 코드 {rc} (출력 없음)"
            parts.append(f"> ⚠ 명령 실패 (rc={rc}): {err_detail}")
            parts.append(f"> 실행 시간: {result.elapsed:.2f}s\n")
            continue

        combined = stdout or stderr or "(출력 없음 — 검색 결과 없음. 조건에 맞는 항목이 존재하지 않음을 의미합니다)"
        if len(combined) > MAX_CMD_OUTPUT_CHARS:
            combined = combined[:MAX_CMD_OUTPUT_CHARS] + "\n... (이하 생략됨)"

        parts.append(f"```\n{combined}\n```")
        if rc not in (0, None):
            parts.append(f"> 종료 코드: {rc}\n")
        parts.append(f"> 실행 시간: {result.elapsed:.2f}s\n")

    parts.append(
        "\n위 결과를 바탕으로 분석을 계속 진행해주세요. "
        "다음 분석 단계의 명령어가 필요하면 ```bash 블록으로 제공하고, "
        "충분한 증거가 모였으면 OpenVEX JSON을 생성해주세요."
    )
    return "\n".join(parts)


def _extract_statement_from_vex(
    cve_id: str,
    vex_doc: dict,
    turns_used: int,
) -> VexStatement:
    """OpenVEX 문서에서 VexStatement를 추출합니다."""
    stmts = vex_doc.get("statements", [])
    if stmts:
        s = stmts[0]
        return VexStatement(
            cve_id=cve_id,
            status=s.get("status", "under_investigation"),
            justification=s.get("justification"),
            impact_statement=s.get("impact_statement", ""),
            analysis_turns=turns_used,
        )
    return VexStatement(
        cve_id=cve_id,
        status="under_investigation",
        justification=None,
        impact_statement="OpenVEX statements 파싱 실패",
        analysis_turns=turns_used,
    )


# ---------------------------------------------------------------------------
# Core: multi-turn VEX analysis loop
# ---------------------------------------------------------------------------


async def run_vex_analysis_loop(
    cve_id: str,
    rootfs_path: Path,
    product_info: dict,
    output_dir: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    단일 CVE에 대한 멀티턴 VEX 분석 루프.

    Parameters
    ----------
    cve_id:
        분석할 CVE ID (예: "CVE-2021-44228").
    rootfs_path:
        extractor.py가 탐지한 rootfs 디렉토리.
    product_info:
        {"name": str, "version": str} 형태의 제품 정보.
    output_dir:
        분석 결과 저장 디렉토리 (예: storage/{job_id}/vex/).

    Yields
    ------
    {"type": "gemini_response", "turn": int, "content": str}
    {"type": "executing_command", "command": str}
    {"type": "command_result", "command": str, "result": str, "returncode": int, "blocked": bool}
    {"type": "vex_complete", "vex_document": dict, "vex_path": str, "statement": VexStatement}
    {"type": "error", "message": str}
    {"type": "max_turns_reached", "cve_id": str}
    """
    system_prompt = _load_system_prompt()
    output_dir.mkdir(parents=True, exist_ok=True)

    product_name = product_info.get("name", "unknown_product")
    product_version = product_info.get("version", "unknown")

    # ── 초기 사용자 메시지 ────────────────────────────────────────────────
    initial_message = (
        f"{cve_id} 취약점을 분석해줘.\n\n"
        f"대상 제품: {product_name} {product_version}\n"
        f"rootfs 위치: {rootfs_path}  (모든 명령어는 이 디렉토리를 cwd로 실행됨)\n\n"
        "이 rootfs에서 해당 CVE가 실제로 Exploitable한지 단계별로 분석해줘. "
        "먼저 1단계-A 명령어부터 시작해줘."
    )

    # ── 대화 히스토리 (시스템 프롬프트 포함, 슬라이딩 윈도우로 전달) ─────
    # 첫 메시지: 시스템 프롬프트를 시스템 역할로 삽입
    history: list[dict] = [
        {"role": "user", "content": f"[시스템 지시사항]\n{system_prompt.strip()}"},
        {"role": "assistant", "content": "네, 이해했습니다. 분석을 시작하겠습니다."},
        {"role": "user", "content": initial_message},
    ]

    for turn in range(MAX_TURNS):
        # 현재 턴의 새 메시지 (히스토리의 마지막 user 메시지)
        new_message = history[-1]["content"]
        # 전달할 히스토리는 마지막 메시지 제외 (call_gemini 내부에서 슬라이딩 윈도우 적용)
        history_ctx = history[:-1]

        logger.info("[VEX] %s Turn %d — Gemini 호출", cve_id, turn + 1)
        yield {"type": "stage_progress", "stage": "vex_analyzing",
               "log": f"🤖 [{cve_id}] Turn {turn + 1} — Gemini 응답 대기 중..."}

        try:
            response = await call_gemini(
                history=history_ctx,
                new_message=new_message,
                cve_id=cve_id,
                turn=turn + 1,
            )
        except Exception as exc:
            msg = str(exc)
            logger.error("[VEX] %s", msg)
            # rate limit 재시도
            if "[RATE_LIMIT]" in msg:
                backoff = _RATE_LIMIT_BACKOFF[min(turn, len(_RATE_LIMIT_BACKOFF) - 1)]
                logger.warning("[VEX] rate limit — %d초 대기 후 재시도", backoff)
                yield {"type": "stage_progress", "stage": "vex_analyzing",
                       "log": f"⚠ rate limit — {backoff}초 대기 후 재시도"}
                await asyncio.sleep(backoff)
                try:
                    response = await call_gemini(
                        history=history_ctx,
                        new_message=new_message,
                        cve_id=cve_id,
                        turn=turn + 1,
                    )
                except Exception as exc2:
                    yield {"type": "error", "message": f"Gemini 호출 실패 (Turn {turn + 1}): {exc2}"}
                    return
            else:
                yield {"type": "error", "message": f"Gemini 호출 실패 (Turn {turn + 1}): {msg}"}
                return

        yield {"type": "gemini_response", "turn": turn + 1, "content": response}
        logger.info("[VEX] %s Turn %d: %d chars", cve_id, turn + 1, len(response))

        # 히스토리에 응답 추가
        history.append({"role": "assistant", "content": response})

        # 턴별 응답 파일 저장
        (output_dir / f"{cve_id}_turn_{turn + 1}.md").write_text(
            f"# {cve_id} — Turn {turn + 1}\n\n{response}\n",
            encoding="utf-8",
        )

        # ── OpenVEX JSON 감지 → 완료 ─────────────────────────────────
        if "openvex.dev" in response:
            vex_doc = extract_json_from_response(response)
            if vex_doc:
                statement = _extract_statement_from_vex(cve_id, vex_doc, turn + 1)
                report_text = _extract_report_text(response)
                statement.report_text = report_text

                vex_path = output_dir / f"{cve_id}_vex.json"
                vex_path.write_text(
                    json.dumps(vex_doc, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                report_path = output_dir / f"{cve_id}_report.md"
                if report_text:
                    report_path.write_text(
                        f"# {cve_id} 분석 요약 보고서\n\n{report_text}\n",
                        encoding="utf-8",
                    )
                    logger.info("[VEX] 분석 보고서 저장: %s", report_path.name)

                _save_analysis_summary(
                    cve_id=cve_id,
                    product_info=product_info,
                    history=history,
                    statement=statement,
                    output_dir=output_dir,
                )
                yield {
                    "type": "vex_complete",
                    "cve_id": cve_id,
                    "status": statement.status,
                    "report_text": report_text,
                    "report_path": str(report_path) if report_text else None,
                    "vex_document": vex_doc,
                    "vex_path": str(vex_path),
                    "statement": statement,
                }
                return

        # ── bash 명령어 추출 및 실행 ─────────────────────────────────
        commands = extract_commands_from_response(response)

        if not commands:
            next_user_msg = (
                "응답에 ```bash 코드블록 명령어가 포함되지 않았습니다. "
                "다음 분석 단계의 명령어를 ```bash 블록으로 제공해주세요. "
                "또는 분석이 완료되었다면 OpenVEX JSON을 ```json 블록으로 출력해주세요."
            )
            history.append({"role": "user", "content": next_user_msg})
            continue

        cmd_results: list[CommandResult] = []
        for cmd in commands:
            yield {"type": "executing_command", "command": cmd}
            result = await execute_command_in_rootfs(cmd, str(rootfs_path))

            full_out = (result.stdout or "").strip()
            if result.blocked:
                logger.info("[VEX CMD] 차단: %s", cmd[:100])
            elif result.returncode not in (0, None) and not full_out:
                logger.info("[VEX CMD] 실패 (rc=%d): %s",
                            result.returncode, (result.stderr or "")[:200])
            else:
                lines = full_out.splitlines()
                logger.info("[VEX CMD] rc=%d, %d줄 출력:", result.returncode, len(lines))
                for line in lines:
                    logger.info("[VEX OUT] %s", line)
                if not lines:
                    logger.info("[VEX OUT] (출력 없음)")

            yield {
                "type": "command_result",
                "command": cmd,
                "result": result.stdout[:2000],
                "returncode": result.returncode,
                "blocked": result.blocked,
            }
            cmd_results.append(result)

        # ── 다음 턴 메시지 (명령어 결과 전송) ────────────────────────
        next_user_msg = _format_results_for_gemini(commands, cmd_results)
        history.append({"role": "user", "content": next_user_msg})

    # ── 최대 턴 초과: under_investigation으로 마무리 ───────────────────────
    logger.warning("[VEX] %s 최대 턴(%d) 도달, under_investigation 처리", cve_id, MAX_TURNS)
    yield {"type": "max_turns_reached", "cve_id": cve_id}

    fallback_doc = _build_fallback_vex(cve_id, product_info)
    vex_path = output_dir / f"{cve_id}_vex.json"
    vex_path.write_text(
        json.dumps(fallback_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    fallback_stmt = VexStatement(
        cve_id=cve_id,
        status="under_investigation",
        justification=None,
        impact_statement=f"최대 분석 턴({MAX_TURNS})에 도달하여 결론이 나지 않았습니다. 수동 검토가 필요합니다.",
        analysis_turns=MAX_TURNS,
    )
    yield {
        "type": "vex_complete",
        "cve_id": cve_id,
        "status": fallback_stmt.status,
        "vex_document": fallback_doc,
        "vex_path": str(vex_path),
        "statement": fallback_stmt,
    }


# ---------------------------------------------------------------------------
# Batch analysis
# ---------------------------------------------------------------------------


async def analyze_cve_batch(
    cves: list[str],
    rootfs_path: Path,
    product_info: dict,
    output_dir: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    CVE 목록을 순차 처리하는 배치 분석기.

    Yields
    ------
    {"type": "batch_start", "total": int}
    {"type": "cve_start", "cve_id": str, "index": int, "total": int, "progress_pct": float}
    (run_vex_analysis_loop 의 모든 이벤트)
    {"type": "cve_done", "cve_id": str, "status": str, "index": int, "total": int}
    {"type": "batch_complete", "vex_result": VexResult}
    """
    total = len(cves)
    vex_dir = output_dir / "vex"
    vex_dir.mkdir(parents=True, exist_ok=True)

    yield {"type": "batch_start", "total": total}
    statements: list[VexStatement] = []

    for idx, cve_id in enumerate(cves, start=1):
        # CVE 간 딜레이: 첫 번째 CVE 이후부터 적용 (rate limit 방지)
        if idx > 1 and CVE_INTER_DELAY > 0:
            await asyncio.sleep(CVE_INTER_DELAY)
        progress_pct = round((idx - 1) / total * 100, 1)
        yield {
            "type": "cve_start",
            "cve_id": cve_id,
            "index": idx,
            "total": total,
            "progress_pct": progress_pct,
        }

        last_statement: Optional[VexStatement] = None

        async for event in run_vex_analysis_loop(
            cve_id=cve_id,
            rootfs_path=rootfs_path,
            product_info=product_info,
            output_dir=vex_dir,
        ):
            yield event
            if event["type"] == "vex_complete":
                last_statement = event.get("statement")

        if last_statement is None:
            last_statement = VexStatement(
                cve_id=cve_id,
                status="under_investigation",
                justification=None,
                impact_statement="분석 중 오류가 발생하여 결론을 내리지 못했습니다.",
                analysis_turns=0,
            )

        statements.append(last_statement)
        yield {
            "type": "cve_done",
            "cve_id": cve_id,
            "status": last_statement.status,
            "index": idx,
            "total": total,
        }

    # ── Combined VEX 생성 ─────────────────────────────────────────────────
    combined_doc = _build_combined_vex(product_info, statements)
    combined_path = output_dir / "combined_vex.json"
    combined_path.write_text(
        json.dumps(combined_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    not_affected = sum(1 for s in statements if s.status == "not_affected")
    affected = sum(1 for s in statements if s.status == "affected")
    under_inv = sum(1 for s in statements if s.status == "under_investigation")

    yield {
        "type": "batch_complete",
        "vex_result": VexResult(
            vex_document_path=combined_path,
            statements=statements,
            not_affected_count=not_affected,
            affected_count=affected,
            under_investigation_count=under_inv,
        ),
    }


# ---------------------------------------------------------------------------
# File output helpers
# ---------------------------------------------------------------------------


def _extract_report_text(response: str) -> str:
    """
    Gemini 최종 응답에서 분석 요약 보고서 텍스트를 추출합니다.
    OpenVEX JSON 블록(```json ... ```) 이전의 텍스트가 보고서입니다.
    """
    # ```json 블록이 시작되기 전까지의 텍스트
    json_block_start = response.find("```json")
    if json_block_start > 0:
        report = response[:json_block_start].strip()
    else:
        # JSON 블록 없이 { 로 시작하는 raw JSON인 경우
        brace_start = response.find('{"@context"')
        if brace_start > 0:
            report = response[:brace_start].strip()
        else:
            report = ""
    return report


def _save_analysis_summary(
    cve_id: str,
    product_info: dict,
    history: list[dict],
    statement: VexStatement,
    output_dir: Path,
) -> None:
    """분석 전체 대화를 마크다운 파일로 저장합니다."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"# {cve_id} VEX 분석 보고서\n",
        f"| 항목 | 값 |",
        f"|------|-----|",
        f"| 제품 | {product_info.get('name', 'unknown')} {product_info.get('version', '')} |",
        f"| 분석일 | {now} |",
        f"| 최종 판정 | **{statement.status}** |",
        f"| Justification | {statement.justification or 'N/A'} |",
        f"| 분석 턴 수 | {statement.analysis_turns} |",
        f"\n## Impact Statement\n\n{statement.impact_statement}\n",
        "---\n",
        "## 전체 대화 히스토리\n",
    ]
    for i, msg in enumerate(history, start=1):
        role = "**사용자**" if msg["role"] == "user" else "**Gemini 분석가**"
        lines.append(f"### Turn {i} — {role}\n")
        lines.append(msg["content"])
        lines.append("\n---\n")

    (output_dir / f"{cve_id}_analysis.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def _build_fallback_vex(cve_id: str, product_info: dict) -> dict:
    """분석 미완료 시 under_investigation VEX 문서를 생성합니다."""
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "FirmCore VEX Analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "name": cve_id,
                },
                "products": [
                    {
                        "@id": (
                            f"pkg:generic/{product_info.get('name', 'firmware')}"
                            f"@{product_info.get('version', 'unknown')}"
                        ),
                    }
                ],
                "status": "under_investigation",
                "impact_statement": (
                    f"Automated VEX analysis reached maximum turn limit ({MAX_TURNS}) "
                    "without a conclusive result. Manual review is required."
                ),
            }
        ],
    }


def _build_combined_vex(
    product_info: dict,
    statements: list[VexStatement],
) -> dict:
    """모든 CVE 분석 결과를 하나의 OpenVEX 문서로 병합합니다."""
    product_id = (
        f"pkg:generic/{product_info.get('name', 'firmware')}"
        f"@{product_info.get('version', 'unknown')}"
    )
    openvex_stmts: list[dict] = []

    for s in statements:
        stmt: dict = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{s.cve_id}",
                "name": s.cve_id,
            },
            "products": [{"@id": product_id}],
            "status": s.status,
            "impact_statement": s.impact_statement,
        }
        # affected 상태에는 justification 미포함 (OpenVEX 스펙)
        if s.justification and s.status not in ("affected", "under_investigation"):
            stmt["justification"] = s.justification
        # 분석 요약 보고서 포함 (확장 필드)
        if s.report_text:
            stmt["x_firmcore_report"] = s.report_text
        openvex_stmts.append(stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "FirmCore VEX Analyzer",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": openvex_stmts,
    }


def rebuild_combined_vex_from_dir(
    product_info: dict,
    vex_dir: Path,
    output_dir: Path,
) -> Path:
    """
    vex_dir 내의 모든 {cve_id}_vex.json 파일을 읽어
    combined_vex.json을 재빌드합니다.

    단일 CVE 재분석 또는 resume 완료 후 호출합니다.
    """
    statements: list[VexStatement] = []

    for vex_file in sorted(vex_dir.glob("*_vex.json")):
        try:
            doc = json.loads(vex_file.read_text(encoding="utf-8"))
            for stmt_dict in doc.get("statements", []):
                cve_id = stmt_dict.get("vulnerability", {}).get("name", "")
                if not cve_id:
                    continue
                stmt = VexStatement(
                    cve_id=cve_id,
                    status=stmt_dict.get("status", "under_investigation"),
                    justification=stmt_dict.get("justification"),
                    impact_statement=stmt_dict.get("impact_statement", ""),
                    analysis_turns=stmt_dict.get("x_firmcore_turns", 0),
                    report_text=stmt_dict.get("x_firmcore_report", ""),
                )
                statements.append(stmt)
        except Exception as exc:
            logger.warning("VEX 파일 파싱 실패, 건너뜀: %s (%s)", vex_file, exc)

    if not statements:
        logger.warning("rebuild_combined_vex_from_dir: 읽을 VEX 파일 없음")
        combined_path = output_dir / "combined_vex.json"
        return combined_path

    combined_doc = _build_combined_vex(product_info, statements)
    combined_path = output_dir / "combined_vex.json"
    combined_path.write_text(
        json.dumps(combined_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info("combined_vex.json 재빌드 완료: %d개 statement", len(statements))
    return combined_path
