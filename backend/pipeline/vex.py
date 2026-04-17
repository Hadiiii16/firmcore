"""
vex.py — Gemini CLI autonomous VEX analyzer

Gemini CLI is invoked with --yolo and cwd=rootfs_path so it can run
find/readelf/nm/strings/grep commands directly through its built-in Shell tool.
The backend streams CLI stdout/stderr as stage_progress events and extracts the
final OpenVEX JSON from the complete response.

System prompt load priority:
  1. VEX_SYSTEM_PROMPT env var path
  2. pipeline dir / vex_system_prompt_v3.md
  3. pipeline dir / vex_system_prompt_v2.md
  4. pipeline dir / vex_system_prompt.md
  5. Built-in default prompt (fallback)

Usage:
    async for event in run_vex_analysis_loop(cve_id, rootfs_path, product_info, output_dir):
        match event["type"]:
            case "stage_progress": print(event["log"])
            case "vex_complete":   save(event["vex_document"])
"""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import json
import logging
import os
import pty
import re
import shutil
import signal
import struct

import pyte


class _GeminiScreen(pyte.HistoryScreen):
    """HistoryScreen tolerant of private-CSI SGR kwargs.

    pyte 0.8.2's stream unconditionally passes ``private=True`` for private
    CSI sequences, but ``select_graphic_rendition`` declares only ``*attrs``.
    Gemini CLI (Ink / chalk) emits private SGRs as part of its color
    palette, which would otherwise crash the feed after the first byte.
    """

    def select_graphic_rendition(self, *attrs: int, **_: Any) -> None:  # type: ignore[override]
        super().select_graphic_rendition(*attrs)
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


def _get_env(name: str, default: str) -> str:
    """Read config from process env, then repo .env for local uvicorn runs."""
    value = os.environ.get(name)
    if value is not None:
        return value

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return default

    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, raw_value = raw.split("=", 1)
            if key.strip() == name:
                return raw_value.strip().strip('"').strip("'")
    except OSError:
        return default

    return default


GEMINI_TIMEOUT = int(_get_env("VEX_GEMINI_TIMEOUT", "1800"))  # seconds per Gemini CLI call (30min default)
# Model pinning: drop "auto"/"default" sentinels so they never reach the CLI.
# Falling back to the CLI default silently swaps us onto Flash, which then
# makes "Pro rate-limit → resume" logic unreachable.
_RAW_GEMINI_MODELS = [
    model.strip()
    for model in _get_env(
        "GEMINI_MODELS",
        _get_env("GEMINI_MODEL", "gemini-2.5-pro"),
    ).split(",")
    if model.strip()
]
GEMINI_MODELS = [
    m for m in _RAW_GEMINI_MODELS if m.lower() not in {"auto", "default"}
]
if not GEMINI_MODELS:
    GEMINI_MODELS = ["gemini-2.5-pro"]
GEMINI_MODEL = GEMINI_MODELS[0]
# Pro 에서 rate-limit 에 걸리면 즉시 중단하고 사용자가 resume 하도록 한다.
# 내부 자동 재시도는 하지 않으므로 retry cycle 은 1 로 고정(환경변수 무시).
GEMINI_MODEL_RETRY_CYCLES = 1
GEMINI_HEARTBEAT_INTERVAL = int(_get_env("VEX_GEMINI_HEARTBEAT_INTERVAL", "30"))
GEMINI_STREAM_LOG_CHARS = int(_get_env("VEX_GEMINI_STREAM_LOG_CHARS", "800"))
# Force-terminate gemini after this many seconds of PTY silence once output
# has begun.  With `<&0` in the bash wrapper gemini's Ink UI keeps stdin open
# and never exits on its own after the final response — we detect completion
# by idleness instead.
GEMINI_IDLE_SHUTDOWN_S = int(_get_env("VEX_GEMINI_IDLE_SHUTDOWN", "45"))

# CVE 간 딜레이 (Gemini rate limit 방지)
CVE_INTER_DELAY = int(os.environ.get("VEX_CVE_DELAY", "5"))  # seconds between CVEs

# 요청 제한 재시도: 에러 메시지에서 retry 시간을 파싱 못 했을 때 사용하는 기본 대기.
# Pro 모델처럼 단일 모델만 쓸 때, rate-limit 에 걸리면 다음 쿼터가 회복될 때까지
# 대기하기 위해 충분히 길게 잡는다.  필요하면 환경변수로 튠.
_RATE_LIMIT_DEFAULT_WAIT = int(_get_env("VEX_GEMINI_RATE_LIMIT_DEFAULT_WAIT", "3600"))
_RATE_LIMIT_MAX_WAIT = int(_get_env("VEX_GEMINI_RATE_LIMIT_MAX_WAIT", "3600"))
_RATE_LIMIT_MIN_WAIT = 30

# 에러 메시지에 섞여 있는 "retry in 1m 23s" / "retryDelay: 35s" /
# "try again in 5 minutes" 등에서 대기 초 수를 뽑는다.
_RETRY_DELAY_RE = re.compile(
    r"(?:retry[\s_-]?(?:delay|in|after)|try\s+again\s+in|retryafter)"
    r"\s*[:=]?\s*"
    r"(?:(\d+)\s*h(?:ours?|rs?)?\s*)?"
    r"(?:(\d+)\s*m(?:in(?:utes?)?)?\s*)?"
    r"(?:(\d+(?:\.\d+)?)\s*s(?:ec(?:onds?)?)?)?",
    re.IGNORECASE,
)


def _parse_retry_delay(text: Optional[str]) -> Optional[int]:
    """Extract a retry-delay hint (seconds) from a Gemini rate-limit message.

    Returns ``None`` if no duration can be parsed.  Clamped to
    ``[_RATE_LIMIT_MIN_WAIT, _RATE_LIMIT_MAX_WAIT]`` by the caller.
    """
    if not text:
        return None
    for match in _RETRY_DELAY_RE.finditer(text):
        hours, minutes, seconds = match.groups()
        if not any((hours, minutes, seconds)):
            continue
        total = 0
        if hours:
            total += int(hours) * 3600
        if minutes:
            total += int(minutes) * 60
        if seconds:
            total += int(float(seconds))
        if total > 0:
            return total
    return None

# ANSI 이스케이프 코드 제거
# - CSI:  \x1B [ <params> <final>       — cursor moves, colors, etc.
# - OSC:  \x1B ] <payload> (BEL | ST)   — terminal title, hyperlinks
#   The default _ANSI_ESCAPE regex only consumed 2 bytes for OSC (ESC + ']'),
#   leaking the payload (e.g. "0;✦ Working…") into the log.
_ANSI_OSC = re.compile(r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)")
_ANSI_CSI = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ANSI_OTHER = re.compile(r"\x1B[@-Z\\-_]")  # 2-byte escapes (not CSI/OSC)


def _strip_ansi(text: str) -> str:
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_CSI.sub("", text)
    return _ANSI_OTHER.sub("", text)


def _is_gemini_rate_limit(text: str) -> bool:
    lowered = text.lower()
    return (
        "status 429" in lowered
        or "code 429" in lowered
        or "resource_exhausted" in lowered
        or "model_capacity_exhausted" in lowered
        or "no capacity available" in lowered
        or "quota exceeded" in lowered
        or "ratelimitexceeded" in lowered
    )


_ACTIVE_GEMINI_PROCS: set[asyncio.subprocess.Process] = set()


def _setup_gemini_subprocess() -> None:
    """Start Gemini in a new session and ask Linux to signal it if we die."""
    os.setsid()
    try:
        libc = ctypes.CDLL(None)
        pr_set_pdeathsig = 1
        libc.prctl(pr_set_pdeathsig, signal.SIGTERM)
    except Exception:
        pass


def _gemini_process_args(gemini_bin: str, prompt: str, model: str) -> list[str]:
    """Build gemini CLI args without --output-format (matches manual --yolo execution)."""
    gemini_args = [gemini_bin]
    if model and model.lower() not in {"auto", "default"}:
        gemini_args.extend(["--model", model])
    gemini_args.append("--yolo")
    gemini_args.append(prompt)

    return [
        "bash",
        "-c",
        (
            "trap 'kill -TERM -- -$$ 2>/dev/null || true; wait' TERM INT HUP; "
            # <&0: preserve inherited stdin (the PTY).  Without it bash redirects
            # background job stdin to /dev/null, so gemini (Ink) sees no TTY on
            # stdin and falls back to non-interactive plain-text mode — Shell
            # tool result boxes (╭│╰) then never reach the PTY.
            '"$@" <&0 & child=$!; wait "$child"; exit $?'
        ),
        "gemini-runner",
        *gemini_args,
    ]


async def _launch_gemini_pty(
    gemini_bin: str,
    prompt: str,
    model: str,
    rootfs_path: Path,
    log_path: Path,
) -> tuple[asyncio.subprocess.Process, asyncio.StreamReader, asyncio.BaseTransport]:
    """Launch gemini with a real PTY so it behaves like manual execution.

    Returns (proc, reader, transport).  The caller must close transport when done.
    Raw output is also tee'd to log_path for debugging.
    """
    master_fd, slave_fd = pty.openpty()

    # Wide terminal so gemini doesn't wrap lines (200 cols)
    winsize = struct.pack("HHHH", 50, 200, 0, 0)
    fcntl.ioctl(slave_fd, 0x5414, winsize)  # TIOCSWINSZ

    # Without TERM gemini (Ink) falls back to plain-text output and the
    # Shell-tool result boxes (╭│╰) never reach the PTY.
    env = os.environ.copy()
    if not env.get("TERM") or env["TERM"] == "dumb":
        env["TERM"] = "xterm-256color"
    env.setdefault("COLORTERM", "truecolor")
    env.setdefault("FORCE_COLOR", "1")
    for ci_var in ("CI", "GITHUB_ACTIONS", "BUILDKITE"):
        env.pop(ci_var, None)

    proc = await asyncio.create_subprocess_exec(
        *_gemini_process_args(gemini_bin, prompt, model),
        cwd=str(rootfs_path),
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        preexec_fn=_setup_gemini_subprocess,
    )
    os.close(slave_fd)  # parent doesn't need the slave end

    # Make master non-blocking so asyncio can read it
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=1 << 20)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(
        lambda: protocol,
        os.fdopen(master_fd, "rb", buffering=0),
    )

    return proc, reader, transport


async def _terminate_process_group(
    proc: asyncio.subprocess.Process,
    cve_id: str,
    reason: str,
) -> None:
    """Terminate Gemini and any tools it spawned in the same process group."""
    if proc.returncode is not None:
        return

    log = logger.info if reason.startswith("OpenVEX complete") else logger.warning
    log("[VEX] %s terminating Gemini process group: %s", cve_id, reason)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception as exc:
        logger.warning("[VEX] %s failed to SIGTERM process group: %s", cve_id, exc)
        try:
            proc.terminate()
        except ProcessLookupError:
            return

    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        logger.warning("[VEX] %s Gemini process group ignored SIGTERM; sending SIGKILL", cve_id)

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception as exc:
        logger.warning("[VEX] %s failed to SIGKILL process group: %s", cve_id, exc)
        try:
            proc.kill()
        except ProcessLookupError:
            return

    try:
        await proc.wait()
    except ProcessLookupError:
        pass


async def terminate_active_gemini_processes(reason: str = "cancel requested") -> int:
    """Terminate every Gemini process currently owned by this backend process."""
    procs = list(_ACTIVE_GEMINI_PROCS)
    for proc in procs:
        await _terminate_process_group(proc, "active", reason)
    return len(procs)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


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
        Path(__file__).parent / "vex_system_prompt_v3.md",
        Path(__file__).parent / "vex_system_prompt_v2.md",
        Path(__file__).parent / "vex_system_prompt.md",
    ]
    for path in candidates:
        if path and path.is_file():
            _SYSTEM_PROMPT_CACHE = path.read_text(encoding="utf-8")
            logger.info("VEX 시스템 프롬프트 로드: %s", path)
            return _SYSTEM_PROMPT_CACHE

    logger.warning(
        "vex_system_prompt_v3.md 를 찾을 수 없습니다. 내장 기본 프롬프트 사용."
    )
    _SYSTEM_PROMPT_CACHE = _DEFAULT_SYSTEM_PROMPT
    return _SYSTEM_PROMPT_CACHE


def _gemini_prompt_file() -> Path:
    """Prompt file referenced with Gemini CLI's @file syntax."""
    configured = os.environ.get("VEX_GEMINI_PROMPT_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(__file__).parent / "vex_system_prompt_v3.md").resolve()


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
- 파일 권한이 보존되지 않을 수 있으므로 ELF 매직바이트(\\x7fELF) 기반 탐지 필수
- -executable, -perm +x 등 권한 기반 탐지 옵션 사용 금지

VEX 상태값:
- not_affected / vulnerable_code_not_present: 라이브러리에 취약 코드 없음
- not_affected / vulnerable_code_not_in_execute_path: 코드 있으나 호출 경로 없음
- not_affected / inline_mitigations_already_exist: 호출 경로 있으나 모든 설정 레이어에서 비활성화
- affected: 1~3단계 모두 취약 조건 충족
- under_investigation: 결론이 불분명하여 추가 분석 필요

최종 응답에는 분석 요약 보고서와 OpenVEX JSON을 포함해. OpenVEX JSON은
반드시 ```json 코드블록 안에 출력하고, @context는
"https://openvex.dev/ns/v0.2.0" 를 사용해.

한국어로 응답해주세요.
"""


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def extract_json_from_response(response: str) -> Optional[dict]:
    """
    Gemini 응답에서 OpenVEX JSON 블록을 추출합니다.

    탐색 순서:
    1. ```json 코드블록 내 JSON  (\\r\\n / \\n 모두 허용)
    2. json.JSONDecoder().raw_decode()로 각 { 위치에서 순차 파싱
       — 첫 번째 {가 Korean 텍스트 안에 있어도 올바른 JSON 위치를 찾음
    """
    # PTY 출력의 \\r\\n → \\n 정규화 (코드블록 탐지용)
    normalized = response.replace("\r\n", "\n").replace("\r", "\n")
    variants = (
        normalized,
        _strip_tui_line_numbers(normalized),
        _reconstruct_tui_code_block(normalized),
    )

    # 1) ```json ... ``` 코드블록 탐지
    for text in variants:
        for match in re.finditer(r"```json\n(.*?)```", text, re.DOTALL):
            try:
                data = json.loads(match.group(1))
                if _is_openvex(data):
                    return data
            except json.JSONDecodeError:
                continue

    # 2) raw_decode: 각 { 위치에서 실제 JSON 파싱 시도
    #    — greedy regex 와 달리 중첩 brace를 정확히 처리하며,
    #      Korean 텍스트 내 { 는 json.JSONDecodeError 로 자연히 건너뜀
    decoder = json.JSONDecoder()
    for text in variants:
        idx = 0
        while True:
            pos = text.find("{", idx)
            if pos == -1:
                break
            try:
                data, end = decoder.raw_decode(text, pos)
                if isinstance(data, dict) and _is_openvex(data):
                    return data
                idx = end  # 이 JSON 블록 다음 위치부터 재탐색
            except json.JSONDecodeError:
                idx = pos + 1  # 이 { 는 JSON 시작이 아님 — 다음 { 탐색

    return None


def _strip_tui_line_numbers(text: str) -> str:
    """Remove Gemini TUI-rendered code block line numbers before JSON parsing.

    Gemini CLI pads numbers to a right-aligned gutter, so indentation after
    the digit can be more than one space (e.g. ``"   2   \\"@context\\""``).
    Match ``\\s+`` after the digit, not ``\\s``, otherwise only the first
    line (with a single space before ``{``) gets stripped and subsequent
    lines remain prefixed with their line numbers — JSON parse then fails.
    """
    return "\n".join(
        re.sub(r"^\s*\d+\s+(?=[\{\}\[\]\",A-Za-z_@-])", "", line)
        for line in text.splitlines()
    )


def _reconstruct_tui_code_block(text: str) -> str:
    """Undo Gemini TUI word-wrap in addition to stripping line-number gutters.

    When a long JSON string (e.g. ``impact_statement``) exceeds the terminal
    width, Gemini wraps it onto an extra line without a line number — only
    indentation padding. That injects an unescaped ``\\n`` into the string
    literal and breaks ``json.loads``. Here we treat unnumbered non-empty
    lines as continuations of the previous numbered line and merge them
    back with a single space separator.

    Bare numbered lines (``"       4"`` — a line-number gutter with no
    content, i.e. a visually blank row in the code block) are preserved
    as empty lines so the subsequent non-empty numbered line starts a new
    paragraph instead of being merged onto the previous one.
    """
    out: list[str] = []
    # Only merge a non-numbered line as a wrap-continuation when the previous
    # line was itself a code-block row (numbered or an earlier continuation).
    # Without this, unrelated TUI content that happens to appear before any
    # numbered code block (auth-spinner boxes, version banner, "Signed in
    # with Google", ...) would all be concatenated into one giant line.
    in_block = False
    for line in text.splitlines():
        m = re.match(r"^\s*\d+(?:\s+(.*))?$", line)
        if m:
            out.append(m.group(1) or "")
            in_block = True
        elif in_block and line.strip() and line.startswith("   "):
            out[-1] += " " + line.strip()
        else:
            out.append(line)
            if not line.strip():
                # blank line doesn't end the code block — next numbered line
                # may resume it; keep in_block as-is
                pass
            else:
                in_block = False
    return "\n".join(out)


# Chrome lines Gemini CLI draws around its live prompt — footer separators,
# sandbox/model tag, workspace path, shortcut hints, the input caret.  These
# occasionally survive the pyte scrollback emitter and also end up in the
# raw ``response`` accumulator, so we filter them here too.
_CHROME_LINE_RE = re.compile(
    r"Analyzing the CVE.*esc to cancel"
    r"|\?\s+for shortcuts"
    r"|YOLO\s+Ctrl\+[A-Z]"
    r"|GEMINI\.md file"
    r"|workspace\s*\(/directory\)"
    r"|no sandbox\s+gemini-"
    r"|\(Tab to focus\)"
    r"|\(Ctrl\+O to (?:show|hide)\)"
    r"|^\s*\*\s+Type your message"
    r"|^\s*~/\.\.\..+?\s+cliv\d+\s*$"
    # Gemini CLI startup chrome — auth spinner, version banner, upgrade
    # prompt, sandbox/model tag, "Positional arguments now default to
    # interactive mode" notice.
    r"|Waiting for authentication"
    r"|Gemini CLI v\d+\.\d+"
    r"|Signed in with Google"
    r"|Plan:\s*Gemini Code Assist"
    r"|Positional arguments now default to interactive"
    # Pure frame lines — any mix of whitespace, box-drawing characters
    # (corners, sides, horizontal dashes), the ▄/▀/▐/▌ block shades used
    # as footer separators, and UTF-8 replacement glyphs.
    r"|^[\s│╭╮╰╯┌┐└┘╔╗╚╝─━═━┃│▄▀▐▌█▗▖▘▝▚▞\ufffd]+$",
    re.IGNORECASE,
)


def clean_gemini_response(response: str) -> str:
    """Normalize a raw PTY-captured Gemini response for human reading.

    Input is expected to be already ANSI-stripped. Collapses TUI line-number
    gutters, rejoins word-wrapped rows, drops Gemini CLI chrome, and
    collapses runs of 3+ blank lines. Used both for the saved
    ``{cve}_gemini_yolo.md`` dump and as the input to
    ``_extract_report_text`` so the structured summary isn't hidden behind
    terminal framing.
    """
    text = _reconstruct_tui_code_block(response)
    kept: list[str] = []
    for line in text.splitlines():
        if line.strip() and _CHROME_LINE_RE.search(line):
            continue
        kept.append(line.rstrip())
    # Collapse consecutive duplicates (pyte captures every spinner animation
    # frame — ``⊶ Searching...``, ``⊷ Searching...`` — as separate rows) and
    # also merge any lines that only differ in their leading spinner glyph.
    _spinner = re.compile(r"^\s*[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏⠉⠏⠻⠽⡙⣹⊶⊷⊕⊖∙✓✗]\s*")
    _box_edge = re.compile(r"^[│\s]+|[│\s]+$")

    def _canon(s: str) -> str:
        # Strip outer box-edge padding, then an in-box spinner glyph.
        stripped = _box_edge.sub("", s)
        return _spinner.sub("", stripped).strip()
    # Gemini CLI streams each ``✦ ...`` comment character-by-character; pyte
    # captures every intermediate frame, producing ``✦ 1단계-A...`` rows that
    # get progressively longer.  We collapse a run of prefix-duplicate rows
    # by keeping only the longest one (the final string), using the spinner-
    # stripped canonical form for comparison.
    canonical_last: Optional[str] = None
    last_line_idx: Optional[int] = None
    deduped: list[str] = []
    MIN_PREFIX_OVERLAP = 16
    for ln in kept:
        canon = _canon(ln)
        if canon:
            if canonical_last is not None:
                if canon == canonical_last:
                    continue
                # growing-prefix animation: replace the previous entry
                overlap = min(len(canon), len(canonical_last))
                if overlap >= MIN_PREFIX_OVERLAP and (
                    canon.startswith(canonical_last)
                    or canonical_last.startswith(canon)
                ):
                    if len(canon) >= len(canonical_last):
                        if last_line_idx is not None:
                            deduped[last_line_idx] = ln
                        canonical_last = canon
                    # else: keep existing longer line, skip this shorter one
                    continue
            canonical_last = canon
            deduped.append(ln)
            last_line_idx = len(deduped) - 1
        else:
            # blank line — pass through without resetting canonical_last
            deduped.append(ln)
    # Collapse 3+ consecutive blank lines to a single blank.
    out: list[str] = []
    blanks = 0
    for ln in deduped:
        if ln:
            blanks = 0
            out.append(ln)
        else:
            blanks += 1
            if blanks <= 1:
                out.append(ln)
    return "\n".join(out).strip() + "\n"


def _is_openvex(data: dict) -> bool:
    ctx = data.get("@context", "")
    return isinstance(ctx, str) and "openvex.dev" in ctx


# ---------------------------------------------------------------------------
# VEX statement extraction
# ---------------------------------------------------------------------------


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
# Gemini CLI autonomous invocation
# ---------------------------------------------------------------------------


def _build_gemini_yolo_prompt(
    cve_id: str,
    product_info: dict,
    vex_json_rel: str,
    report_md_rel: str,
) -> str:
    """Build the task prompt sent to Gemini CLI.

    System instructions come from GEMINI.md which gemini auto-loads as project
    context.  This prompt only carries the task-specific parameters plus the
    cwd-relative output paths where Gemini must save the final artifacts via
    its WriteFile tool.  Gemini's WriteFile only allows paths inside the
    workspace (cwd = rootfs); the backend moves these staging files to
    ``vex/`` after the run completes.
    """
    product_name = product_info.get("name", "unknown_product")
    product_version = product_info.get("version", "unknown")

    return (
        f"@GEMINI.md 의 규칙을 엄격히 적용해서 {cve_id} 분석을 시작해. "
        f"대상 제품: {product_name} {product_version}. "
        "중간에 나에게 실행 여부나 결과를 묻지 말고, 네가 직접 내부 쉘(Shell) "
        "도구를 호출해서 명령어를 실행하고 그 결과 로그를 파싱하는 과정을 "
        "리포트가 완성될 때까지 무인 에이전트(Autonomous Agent) 모드로 끝까지 진행해.\n\n"
        "최종 산출물 저장 규칙 (반드시 지킬 것):\n"
        f"- WriteFile 도구로 OpenVEX JSON 을 작업공간(cwd) 루트의 다음 상대 경로에 저장: {vex_json_rel}\n"
        f"- WriteFile 도구로 분석 요약 보고서를 작업공간(cwd) 루트의 다음 상대 경로에 저장: {report_md_rel}\n"
        "- 경로는 cwd(현재 작업 디렉토리) 바로 아래의 파일명이다. 하위 디렉토리를 만들거나 "
        "`../` 같은 상위 경로를 쓰지 말 것. 작업공간 밖으로 쓰면 WriteFile 이 거부된다.\n"
        "- 두 파일을 저장한 뒤 Shell 도구로 `ls -l ./" + vex_json_rel + " ./" + report_md_rel + "` "
        "를 실행해 존재를 확인하고, 그 다음 화면에 요약 보고서만 평문으로 한 번 출력하고 종료할 것. "
        "OpenVEX JSON 은 화면에 출력하지 말고 파일로만 저장할 것."
    )


async def stream_gemini_yolo(
    prompt: str,
    rootfs_path: Path,
    cve_id: str,
    model: str = GEMINI_MODEL,
) -> AsyncGenerator[dict[str, Any], None]:
    """Run Gemini CLI with --yolo via PTY (matches manual execution exactly).

    Uses a real pseudo-terminal so gemini behaves identically to running it
    manually in a terminal.  No --output-format flag — plain text output is
    parsed by stripping ANSI codes and watching for shell command lines and
    OpenVEX JSON.  Raw PTY output is tee'd to a debug log file.

    Yields stage_progress events, then a sentinel:
      {"type": "_gemini_response", "response": <full plain-text response>}
    """
    gemini_bin = shutil.which("gemini")
    if not gemini_bin:
        raise RuntimeError(
            "gemini CLI not found. Install it with: npm install -g @google/gemini-cli"
        )
    if not rootfs_path.exists():
        raise RuntimeError(f"rootfs path does not exist: {rootfs_path}")

    model_label = model if model.lower() not in {"auto", "default"} else "auto"
    logger.info(
        "[VEX] %s invoking gemini model=%s --yolo in %s (PTY mode)",
        cve_id, model_label, rootfs_path,
    )

    # Raw PTY output log for debugging (ANSI codes intact)
    pty_log_path = rootfs_path.parent / "vex" / f"{cve_id}_pty_raw.log"
    pty_log_path.parent.mkdir(parents=True, exist_ok=True)

    proc, reader, transport = await _launch_gemini_pty(
        gemini_bin, prompt.strip(), model, rootfs_path, pty_log_path
    )
    _ACTIVE_GEMINI_PROCS.add(proc)

    started_at = time.monotonic()
    deadline = started_at + GEMINI_TIMEOUT

    accumulated: list[str] = []   # all stripped text (for OpenVEX JSON extraction)
    progress_q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    final_detected = False
    final_event = asyncio.Event()
    wait_task = asyncio.create_task(proc.wait())

    # PTY raw log file
    pty_log_fp = open(pty_log_path, "wb")  # noqa: WPS515

    # ── terminal emulator (pyte) ─────────────────────────────────────────
    # Gemini CLI is Ink-based: it redraws its entire visible area every
    # frame (input prompt, spinner, status bar) using cursor-movement ANSI.
    # Pure passthrough would repeat every frame hundreds of times.  Instead
    # we render the raw bytes through a virtual terminal and emit only
    # lines that have *scrolled out of the live viewport* — those are the
    # committed analysis output (Shell boxes, `✦` commentary, final
    # report).  This matches what you see scrolling up in a real terminal.
    pyte_screen = _GeminiScreen(
        columns=200, lines=50, history=10000, ratio=0.05,
    )
    pyte_feed = pyte.ByteStream(pyte_screen)
    emitted_history_count = 0
    last_emitted_line: Optional[str] = None
    # Chrome lines that sometimes survive into scrollback (workspace path,
    # shortcut hints, etc.).  Filter them when they appear.
    _CHROME_BLOCK = re.compile(
        r"^[▄▀─]{4,}\s*$"
        r"|Analyzing the CVE.*esc to cancel"
        r"|\?\s+for shortcuts"
        r"|YOLO\s+Ctrl\+[A-Z]"
        r"|GEMINI\.md file"
        r"|workspace\s*\(/directory\)"
        r"|no sandbox\s+gemini-"
        r"|\(Tab to focus\)"
        r"|\(Ctrl\+O to (?:show|hide)\)"
        r"|^\*\s+Type your message",
        re.IGNORECASE,
    )

    def _line_to_text(line_dict: Any) -> str:
        if not line_dict:
            return ""
        cols = sorted(line_dict.keys())
        return "".join(line_dict[c].data for c in cols).rstrip()

    async def _emit_line(text: str) -> None:
        nonlocal last_emitted_line
        stripped = text.strip()
        if stripped and _is_gemini_rate_limit(stripped):
            raise RuntimeError(f"[RATE_LIMIT] {stripped}")
        if stripped and _CHROME_BLOCK.search(text):
            return
        # Collapse consecutive identical blank lines — one is enough for
        # block spacing, more is just noise.
        if not stripped and last_emitted_line == "":
            return
        display = text
        if len(display) > GEMINI_STREAM_LOG_CHARS + 40:
            display = display[: GEMINI_STREAM_LOG_CHARS + 40] + "..."
        label = f"[{cve_id}] {display}" if stripped else f"[{cve_id}]"
        logger.info("[VEX] %s", label)
        await progress_q.put({
            "type": "stage_progress", "stage": "vex_analyzing",
            "log": label,
        })
        last_emitted_line = stripped

    async def _flush_new_scrollback() -> None:
        nonlocal emitted_history_count
        top_lines = list(pyte_screen.history.top)
        if len(top_lines) <= emitted_history_count:
            return
        new_lines = top_lines[emitted_history_count:]
        emitted_history_count = len(top_lines)
        for ln in new_lines:
            await _emit_line(_line_to_text(ln))

    def _viewport_text() -> str:
        """Dump non-trailing-empty lines from the live viewport."""
        rows = [_line_to_text(pyte_screen.buffer[r]) for r in range(pyte_screen.lines)]
        # strip trailing empties
        while rows and not rows[-1].strip():
            rows.pop()
        return "\n".join(rows)

    async def _flush_viewport() -> None:
        text = _viewport_text()
        if not text:
            return
        for row in text.split("\n"):
            await _emit_line(row)

    # ── PTY reader task ───────────────────────────────────────────────────

    async def _read_pty() -> None:
        nonlocal final_detected
        last_chunk_ts = time.monotonic()
        got_any_output = False
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                except asyncio.TimeoutError:
                    # Flush any new scrollback that accumulated since last chunk.
                    await _flush_new_scrollback()
                    # Gemini's Ink UI holds stdin open (via our `<&0` wrapper)
                    # and never exits cleanly.  If we've seen output and the
                    # PTY has been silent for GEMINI_IDLE_SHUTDOWN_S, force
                    # termination — response is already in `accumulated`.
                    idle = time.monotonic() - last_chunk_ts
                    if got_any_output and idle >= GEMINI_IDLE_SHUTDOWN_S:
                        logger.info(
                            "[VEX] %s PTY idle %.0fs after output; terminating gemini",
                            cve_id, idle,
                        )
                        final_event.set()
                        await _flush_viewport()
                        await progress_q.put({
                            "type": "stage_progress", "stage": "vex_analyzing",
                            "log": f"[{cve_id}] Gemini output idle {int(idle)}s; terminating",
                        })
                        asyncio.create_task(
                            _terminate_process_group(proc, cve_id, "idle shutdown")
                        )
                        return
                    continue
                if not chunk:
                    break

                last_chunk_ts = time.monotonic()
                got_any_output = True
                pty_log_fp.write(chunk)

                # Feed raw bytes (ANSI included) to the virtual terminal.
                try:
                    pyte_feed.feed(chunk)
                except Exception as exc:
                    logger.warning("[VEX] %s pyte feed error: %s", cve_id, exc)

                # Keep a raw-decoded copy for OpenVEX JSON detection.
                # We *cannot* strip ANSI per-chunk here: escape sequences like
                # ``\x1b[38;2;175;215;215m`` are split across chunk boundaries
                # when the PTY writer flushes mid-sequence.  A per-chunk strip
                # would leave the incomplete leading ``\x1b[38`` in the buffer
                # and emit the rest of the payload as plain text, corrupting
                # the JSON.  Keep chunks raw; strip the joined text below.
                accumulated.append(chunk.decode("utf-8", errors="replace"))

                # Emit any lines that scrolled into history this chunk.
                await _flush_new_scrollback()

                # OpenVEX detection on accumulated text (strip ANSI on the
                # *joined* buffer so split escapes are removed cleanly).
                if not final_detected:
                    full = _strip_ansi("".join(accumulated))
                    if extract_json_from_response(full) is not None:
                        final_detected = True
                        final_event.set()
                        await _flush_viewport()
                        await progress_q.put({
                            "type": "stage_progress", "stage": "vex_analyzing",
                            "log": f"[{cve_id}] OpenVEX JSON detected; stopping Gemini",
                        })
                        asyncio.create_task(
                            _terminate_process_group(proc, cve_id, "OpenVEX complete")
                        )
                        return
        finally:
            # One last flush of scrollback on EOF.
            try:
                await _flush_new_scrollback()
            except Exception:
                pass
            pty_log_fp.close()

    read_task = asyncio.create_task(_read_pty())

    try:
        while True:
            if (wait_task.done() or final_event.is_set()) and progress_q.empty() and read_task.done():
                break

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await _terminate_process_group(proc, cve_id, "timeout")
                raise RuntimeError(f"gemini CLI timed out after {GEMINI_TIMEOUT}s")

            timeout = 1.0 if final_event.is_set() else min(max(1, GEMINI_HEARTBEAT_INTERVAL), remaining)
            try:
                yield await asyncio.wait_for(progress_q.get(), timeout=timeout)
            except asyncio.TimeoutError:
                if final_event.is_set() and read_task.done():
                    break
                elapsed = int(time.monotonic() - started_at)
                logger.info("[VEX] %s Gemini CLI still running (%ss elapsed)", cve_id, elapsed)
                yield {
                    "type": "stage_progress", "stage": "vex_analyzing",
                    "log": f"[{cve_id}] Gemini CLI still running ({elapsed}s elapsed)",
                }

        if final_event.is_set() and not wait_task.done():
            try:
                await asyncio.wait_for(wait_task, timeout=5)
            except asyncio.TimeoutError:
                await _terminate_process_group(proc, cve_id, "OpenVEX complete force kill")

        if not read_task.done():
            read_task.cancel()
        await asyncio.gather(read_task, return_exceptions=True)

        transport.close()

        # Strip ANSI on the joined buffer (see note in _read_pty): per-chunk
        # stripping misses escapes split across PTY read boundaries.
        response = _strip_ansi("".join(accumulated)).strip()
        if not response and proc.returncode not in (0, None):
            raise RuntimeError(f"gemini exited with code {proc.returncode}")

        logger.info("[VEX] %s gemini response received (%d chars)", cve_id, len(response))
        yield {"type": "_gemini_response", "response": response}

    except asyncio.CancelledError:
        await _terminate_process_group(proc, cve_id, "cancelled")
        read_task.cancel()
        wait_task.cancel()
        transport.close()
        raise
    except Exception:
        await _terminate_process_group(proc, cve_id, "error")
        read_task.cancel()
        wait_task.cancel()
        transport.close()
        raise
    finally:
        _ACTIVE_GEMINI_PROCS.discard(proc)


# ---------------------------------------------------------------------------
# Core: single-shot VEX analysis loop (Gemini runs tools autonomously)
# ---------------------------------------------------------------------------


async def run_vex_analysis_loop(
    cve_id: str,
    rootfs_path: Path,
    product_info: dict,
    output_dir: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Analyze one CVE by delegating shell/tool execution to Gemini CLI itself.

    Gemini is invoked with --yolo and cwd=rootfs_path so it can autonomously
    run find/nm/readelf/strings/grep commands through its built-in Shell tool.
    The backend streams stdout/stderr as stage_progress events, then parses the
    final OpenVEX JSON from the accumulated response.

    Yields
    ------
    {"type": "stage_progress", "stage": "vex_analyzing", "log": str}
    {"type": "vex_complete", "cve_id": str, "status": str, "vex_document": dict,
     "vex_path": str, "statement": VexStatement, "report_text": str, "report_path": str|None}
    {"type": "error", "message": str}
    {"type": "vex_json_not_found", "cve_id": str}  # response had no OpenVEX JSON; fallback used
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    vex_path = (output_dir / f"{cve_id}_vex.json").resolve()
    report_path = (output_dir / f"{cve_id}_report.md").resolve()

    # Gemini's WriteFile only allows paths inside its workspace (cwd = rootfs),
    # so it can't touch output_dir directly.  We have Gemini save to staging
    # filenames at the workspace root, then move them into output_dir below.
    vex_stage_rel = f".firmcore_{cve_id}_vex.json"
    report_stage_rel = f".firmcore_{cve_id}_report.md"
    vex_stage_path = rootfs_path / vex_stage_rel
    report_stage_path = rootfs_path / report_stage_rel

    # Clear leftovers so the "did Gemini save it?" check below is meaningful.
    for leftover in (vex_path, report_path, vex_stage_path, report_stage_path):
        if leftover.exists():
            try:
                leftover.unlink()
            except OSError:
                pass

    prompt = _build_gemini_yolo_prompt(
        cve_id, product_info, vex_stage_rel, report_stage_rel
    )
    yield {
        "type": "stage_progress",
        "stage": "vex_analyzing",
        "log": f"[{cve_id}] Gemini CLI --yolo analysis started (models: {', '.join(GEMINI_MODELS)})",
    }

    response: Optional[str] = None
    # Pro 모델 고정 사용.  rate-limit 에 걸리면 자동 재시도/폴백하지 않고
    # rate_limited 이벤트를 emit 한 뒤 즉시 중단한다.  사용자가 /resume-vex
    # 로 수동 재개하는 구조(run_vex_resume) 로 연결된다.
    model = GEMINI_MODELS[0]
    yield {
        "type": "stage_progress",
        "stage": "vex_analyzing",
        "log": f"[{cve_id}] Gemini model attempt: {model}",
    }
    try:
        async for event in stream_gemini_yolo(prompt, rootfs_path, cve_id, model):
            if event.get("type") == "_gemini_response":
                response = event["response"]
            else:
                yield event
    except Exception as exc:
        msg = str(exc)
        if "[RATE_LIMIT]" in msg:
            retry_after = _parse_retry_delay(msg)
            yield {
                "type": "rate_limited",
                "cve_id": cve_id,
                "model": model,
                "message": msg,
                "retry_after": retry_after,
            }
            return
        yield {"type": "error", "message": f"Gemini CLI failed: {msg}"}
        return

    if response is None:
        yield {"type": "error", "message": "Gemini CLI finished without a response"}
        return

    # Clean PTY framing so the archived raw log stays human-readable.  The
    # authoritative VEX/report artifacts now come from Gemini's WriteFile tool
    # — parsing them out of the terminal stream is only a fallback.
    cleaned_response = clean_gemini_response(response)

    response_path = output_dir / f"{cve_id}_gemini_yolo.md"
    response_path.write_text(
        f"# {cve_id} Gemini CLI --yolo analysis\n\n{cleaned_response}",
        encoding="utf-8",
    )

    # ── Primary path: read artifacts Gemini saved via WriteFile into the
    # rootfs-relative staging files (workspace restriction workaround).
    vex_doc: Optional[dict] = None
    if vex_stage_path.exists():
        try:
            vex_doc = json.loads(vex_stage_path.read_text(encoding="utf-8"))
            logger.info("[VEX] %s OpenVEX loaded from WriteFile staging", cve_id)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "[VEX] %s WriteFile staging %s unreadable (%s); falling back to text extraction",
                cve_id, vex_stage_path.name, exc,
            )
            vex_doc = None

    # ── Fallback: extract from the terminal stream ───────────────────────
    if not vex_doc:
        vex_doc = extract_json_from_response(cleaned_response)
    if not vex_doc:
        vex_doc = extract_json_from_response(response)
    if not vex_doc:
        logger.warning("[VEX] %s no OpenVEX JSON found; using fallback", cve_id)
        yield {"type": "vex_json_not_found", "cve_id": cve_id}
        vex_doc = _build_fallback_vex(cve_id, product_info)

    statement = _extract_statement_from_vex(cve_id, vex_doc, 1)

    # ── Report: prefer Gemini's WriteFile staging, else extract ──────────
    report_text = ""
    if report_stage_path.exists():
        try:
            disk_text = report_stage_path.read_text(encoding="utf-8").strip()
            if disk_text:
                report_text = disk_text
                logger.info("[VEX] %s report loaded from WriteFile staging", cve_id)
        except OSError as exc:
            logger.warning(
                "[VEX] %s WriteFile staging report %s unreadable (%s); extracting from stream",
                cve_id, report_stage_path.name, exc,
            )

    if not report_text:
        report_text = _extract_report_text(cleaned_response)
    if not report_text and statement.impact_statement:
        report_text = statement.impact_statement
    statement.report_text = report_text

    # Clean up staging files so we don't pollute the rootfs between runs.
    for stage in (vex_stage_path, report_stage_path):
        if stage.exists():
            try:
                stage.unlink()
            except OSError:
                pass

    # Always (re)write the canonical files from the values we just resolved.
    # Gemini may have saved with different framing (e.g. no header) — we keep
    # a stable shape for the frontend and for re-runs.
    vex_path.write_text(
        json.dumps(vex_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if report_text:
        report_path.write_text(
            f"# {cve_id} analysis report\n\n{report_text}\n",
            encoding="utf-8",
        )
        logger.info("[VEX] 분석 보고서 저장: %s", report_path.name)

    _save_analysis_summary(
        cve_id=cve_id,
        product_info=product_info,
        history=[
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": response},
        ],
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
    cancel_marker = output_dir / ".cancel_vex"

    yield {"type": "batch_start", "total": total}
    statements: list[VexStatement] = []

    for idx, cve_id in enumerate(cves, start=1):
        if cancel_marker.exists():
            yield {"type": "batch_cancelled", "message": "VEX analysis cancelled"}
            return

        # CVE 간 딜레이: 첫 번째 CVE 이후부터 적용 (rate limit 방지)
        if idx > 1 and CVE_INTER_DELAY > 0:
            await asyncio.sleep(CVE_INTER_DELAY)

        if cancel_marker.exists():
            yield {"type": "batch_cancelled", "message": "VEX analysis cancelled"}
            return

        progress_pct = round((idx - 1) / total * 100, 1)
        yield {
            "type": "cve_start",
            "cve_id": cve_id,
            "index": idx,
            "total": total,
            "progress_pct": progress_pct,
        }

        last_statement: Optional[VexStatement] = None
        rate_limited_event: Optional[dict[str, Any]] = None

        async for event in run_vex_analysis_loop(
            cve_id=cve_id,
            rootfs_path=rootfs_path,
            product_info=product_info,
            output_dir=vex_dir,
        ):
            yield event
            if event["type"] == "vex_complete":
                last_statement = event.get("statement")
            elif event["type"] == "rate_limited":
                rate_limited_event = event

        if cancel_marker.exists():
            yield {"type": "batch_cancelled", "message": "VEX analysis cancelled"}
            return

        # Pro 모델 쿼터 소진: 배치를 중단하고 사용자가 /resume-vex 로 재개하게 함.
        if rate_limited_event is not None:
            yield {
                "type": "batch_rate_limited",
                "cve_id": cve_id,
                "index": idx,
                "total": total,
                "message": rate_limited_event.get("message"),
                "retry_after": rate_limited_event.get("retry_after"),
                "model": rate_limited_event.get("model"),
            }
            return

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
    Gemini 응답에서 최종 '분석 요약 보고서' 섹션만 추출합니다.

    Gemini는 분석 과정(bash 코드블록, 단계별 설명)을 먼저 출력하고,
    마지막에 '=== CVE 분석 요약 보고서 ===' 형태의 최종 보고서를 출력합니다.
    이 함수는 해당 섹션만 추출하여 저장/표시합니다.

    탐색 순서:
    1. '분석 요약 보고서' 헤더 이후 ~ JSON 블록 이전
    2. 헤더가 없으면 JSON 블록 직전 마지막 ===...=== 이후
    3. 위 모두 실패 시 빈 문자열
    """
    # JSON 블록 시작 위치 확정 (보고서의 끝 경계)
    end = response.find("```json")
    if end <= 0:
        end = response.find('{"@context"')
    text_before_json = response[:end].strip() if end > 0 else response.strip()

    # 1) '분석 요약 보고서' 키워드로 섹션 시작 탐지
    #    형식 A: === CVE 분석 요약 보고서 ===  (한 줄)
    #    형식 B: ===\n CVE 분석 요약 보고서\n===  (세 줄)
    _REPORT_HEADER = re.compile(
        r"={5,}[^\n]*\n?\s*CVE\s*분석\s*요약\s*보고서",
        re.IGNORECASE,
    )
    m = _REPORT_HEADER.search(text_before_json)
    if m:
        section = text_before_json[m.start():]
        # 보고서 끝: 마지막 '===...===' 구분자까지만 포함
        _SEP_END = re.compile(r"\n={5,}\s*\n?")
        # 두 번째 === 이후를 끝으로 (첫 번째는 시작 헤더의 하단 ===)
        sep_matches = list(_SEP_END.finditer(section))
        if len(sep_matches) >= 1:
            section = section[:sep_matches[-1].end()]
        return section.strip()

    # 2) 헤더 없이 '==='로 시작하는 마지막 큰 섹션 탐지
    _SEP = re.compile(r"^={5,}", re.MULTILINE)
    matches = list(_SEP.finditer(text_before_json))
    if len(matches) >= 2:
        section = text_before_json[matches[-2].start():]
        # 마지막 '===' 이후 내용 제거
        last = matches[-1].start() - matches[-2].start()
        tail_m = _SEP.search(section, last)
        if tail_m:
            section = section[:tail_m.end()]
        return section.strip()

    # 3) 아무것도 없으면 빈 문자열
    return ""


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
                    "Automated VEX analysis did not produce a conclusive result. "
                    "Manual review is required."
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
