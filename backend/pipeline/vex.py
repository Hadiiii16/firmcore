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
import json
import logging
import os
import re
import shutil
import signal
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
GEMINI_MODELS = [
    model.strip()
    for model in _get_env(
        "GEMINI_MODELS",
        _get_env("GEMINI_MODEL", "gemini-2.5-flash"),
    ).split(",")
    if model.strip()
]
if not GEMINI_MODELS:
    GEMINI_MODELS = ["gemini-2.5-flash"]
GEMINI_MODEL = GEMINI_MODELS[0]
GEMINI_MODEL_RETRY_CYCLES = int(_get_env("VEX_GEMINI_MODEL_RETRY_CYCLES", "2"))
GEMINI_HEARTBEAT_INTERVAL = int(_get_env("VEX_GEMINI_HEARTBEAT_INTERVAL", "30"))
GEMINI_STREAM_LOG_CHARS = int(_get_env("VEX_GEMINI_STREAM_LOG_CHARS", "800"))
GEMINI_CLI_MODE = _get_env("VEX_GEMINI_CLI_MODE", "interactive").strip().lower()
GEMINI_OUTPUT_FORMAT = _get_env("VEX_GEMINI_OUTPUT_FORMAT", "stream-json").strip().lower()

# CVE 간 딜레이 (Gemini rate limit 방지)
CVE_INTER_DELAY = int(os.environ.get("VEX_CVE_DELAY", "5"))  # seconds between CVEs

# 요청 제한 재시도: 지수 백오프 (30s, 60s, 120s)
_RATE_LIMIT_BACKOFF = [30, 60, 120]

# ANSI 이스케이프 코드 제거
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


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
    """Wrap Gemini so parent death or TERM kills the whole spawned process group."""
    gemini_args = [gemini_bin]
    if model and model.lower() not in {"auto", "default"}:
        gemini_args.extend(["--model", model])
    gemini_args.append("--yolo")
    if GEMINI_OUTPUT_FORMAT in {"json", "stream-json"}:
        gemini_args.extend(["--output-format", GEMINI_OUTPUT_FORMAT])
    if GEMINI_CLI_MODE == "headless":
        gemini_args.extend(["-p", prompt])
    else:
        # Matches the manual flow: gemini --yolo "@GEMINI.md ..."
        # Gemini stays interactive after the final answer; the caller stops it
        # once an OpenVEX document is detected in stdout.
        gemini_args.append(prompt)

    return [
        "bash",
        "-c",
        (
            "trap 'kill -TERM -- -$$ 2>/dev/null || true; wait' TERM INT HUP; "
            '"$@" & child=$!; wait "$child"; exit $?'
        ),
        "gemini-runner",
        *gemini_args,
    ]


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
    1. ```json 코드블록 내 JSON
    2. 응답 전체에서 { ... } 직접 파싱 (openvex.dev 컨텍스트 존재 여부로 검증)
    """
    variants = (response, _strip_tui_line_numbers(response))

    for match in re.finditer(r"```json\n(.*?)```", variants[0], re.DOTALL):
        try:
            data = json.loads(match.group(1))
            if _is_openvex(data):
                return data
        except json.JSONDecodeError:
            continue

    for text in variants[1:]:
        for match in re.finditer(r"```json\n(.*?)```", text, re.DOTALL):
            try:
                data = json.loads(match.group(1))
                if _is_openvex(data):
                    return data
            except json.JSONDecodeError:
                continue

    for text in variants:
        for match in re.finditer(r"\{[\s\S]*\}", text):
            try:
                data = json.loads(match.group(0))
                if _is_openvex(data):
                    return data
            except json.JSONDecodeError:
                continue

    return None


def _strip_tui_line_numbers(text: str) -> str:
    """Remove Gemini TUI-rendered code block line numbers before JSON parsing."""
    return "\n".join(
        re.sub(r"^\s*\d+\s(?=[\{\}\[\]\",A-Za-z_@-])", "", line)
        for line in text.splitlines()
    )


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
) -> str:
    """Build the task prompt sent to Gemini CLI.

    System instructions come from GEMINI.md which gemini auto-loads as project
    context.  This prompt only carries the task-specific parameters.
    """
    product_name = product_info.get("name", "unknown_product")
    product_version = product_info.get("version", "unknown")

    return (
        f"@GEMINI.md 의 규칙을 엄격히 적용해서 {cve_id} 분석을 시작해. "
        f"대상 제품: {product_name} {product_version}. "
        "중간에 나에게 실행 여부나 결과를 묻지 말고, 네가 직접 내부 쉘(Shell) "
        "도구를 호출해서 명령어를 실행하고 그 결과 로그를 파싱하는 과정을 "
        "리포트가 완성될 때까지 무인 에이전트(Autonomous Agent) 모드로 끝까지 진행해."
    )


async def stream_gemini_yolo(
    prompt: str,
    rootfs_path: Path,
    cve_id: str,
    model: str = GEMINI_MODEL,
) -> AsyncGenerator[dict[str, Any], None]:
    """Run Gemini CLI with --yolo in rootfs_path and stream progress events.

    When GEMINI_OUTPUT_FORMAT is stream-json, each stdout line is a JSON object.
    We parse those lines to extract:
      - assistant message content  → progress log + OpenVEX detection
      - tool_call (shell commands) → progress log showing what gemini is running
      - tool_result                → progress log showing command output
      - init                       → session info log
      - user message               → skipped (echo of our prompt)

    Yields stage_progress events, then a sentinel:
      {"type": "_gemini_response", "response": <extracted assistant content>}
    """
    gemini_bin = shutil.which("gemini")
    if not gemini_bin:
        raise RuntimeError(
            "gemini CLI not found. Install it with: npm install -g @google/gemini-cli"
        )

    if not rootfs_path.exists():
        raise RuntimeError(f"rootfs path does not exist: {rootfs_path}")

    use_stream_json = GEMINI_OUTPUT_FORMAT in {"json", "stream-json"}
    model_label = model if model.lower() not in {"auto", "default"} else "auto"
    logger.info(
        "[VEX] %s invoking gemini model=%s --yolo in %s (output-format=%s)",
        cve_id, model_label, rootfs_path, GEMINI_OUTPUT_FORMAT,
    )

    proc = await asyncio.create_subprocess_exec(
        *_gemini_process_args(gemini_bin, prompt.strip(), model),
        cwd=str(rootfs_path),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        preexec_fn=_setup_gemini_subprocess,
    )
    _ACTIVE_GEMINI_PROCS.add(proc)

    started_at = time.monotonic()
    deadline = started_at + GEMINI_TIMEOUT

    # assistant_content_parts: extracted assistant text (used as final response)
    # For plain-text mode this equals the full stdout; for stream-json it's only
    # the content fields from assistant/model messages.
    assistant_content_parts: list[str] = []
    # Buffer for assistant message chunks — flushed when a non-message event
    # arrives (tool_call, tool_result, done) so we emit one log per "thought"
    # instead of one per streaming delta.
    _pending_assistant: list[str] = []
    stderr_parts: list[str] = []
    progress_q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    final_detected = False
    final_event = asyncio.Event()

    async def _flush_assistant_buffer() -> None:
        """Emit buffered assistant text as a single progress event."""
        if not _pending_assistant:
            return
        combined = "".join(_pending_assistant)
        _pending_assistant.clear()
        compact = " ".join(combined.split())
        if not compact:
            return
        if len(compact) > GEMINI_STREAM_LOG_CHARS:
            compact = compact[:GEMINI_STREAM_LOG_CHARS] + "..."
        logger.info("[VEX] %s assistant: %s", cve_id, compact)
        await progress_q.put({
            "type": "stage_progress", "stage": "vex_analyzing",
            "log": f"[{cve_id}] {compact}",
        })

    # ── stream-json stdout parser ─────────────────────────────────────────

    async def _handle_json_line(line: str) -> None:
        """Parse one stream-json line and enqueue a progress event if relevant."""
        nonlocal final_detected
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Not a JSON line — treat as plain text (shouldn't happen in json mode)
            text = _strip_ansi(line).strip()
            if text:
                assistant_content_parts.append(text + "\n")
                await progress_q.put({
                    "type": "stage_progress", "stage": "vex_analyzing",
                    "log": f"[{cve_id}] {text[:GEMINI_STREAM_LOG_CHARS]}",
                })
            return

        obj_type = obj.get("type", "")

        if obj_type == "init":
            m = obj.get("model", "?")
            logger.info("[VEX] %s Gemini session started: model=%s", cve_id, m)
            await progress_q.put({
                "type": "stage_progress", "stage": "vex_analyzing",
                "log": f"[{cve_id}] Gemini session started (model: {m})",
            })

        elif obj_type == "message":
            role = obj.get("role", "")
            if role == "user":
                return  # skip echo of our own prompt

            content = obj.get("content", "")
            # content may be a list of parts (multimodal)
            if isinstance(content, list):
                content = "".join(
                    p.get("text", "") for p in content
                    if isinstance(p, dict)
                )
            if not isinstance(content, str) or not content:
                return

            assistant_content_parts.append(content)
            _pending_assistant.append(content)
            # OpenVEX JSON detection from accumulated assistant content
            if not final_detected and GEMINI_CLI_MODE != "headless":
                if extract_json_from_response("".join(assistant_content_parts)) is not None:
                    final_detected = True
                    final_event.set()
                    await _flush_assistant_buffer()
                    await progress_q.put({
                        "type": "stage_progress", "stage": "vex_analyzing",
                        "log": f"[{cve_id}] OpenVEX JSON detected; stopping Gemini",
                    })
                    asyncio.create_task(
                        _terminate_process_group(proc, cve_id, "OpenVEX complete")
                    )

        elif obj_type in ("tool_call", "tool_use"):
            # Flush any buffered assistant text before showing the tool call
            await _flush_assistant_buffer()
            tool = obj.get("tool", obj.get("name", ""))
            inp = obj.get("input", obj.get("parameters", {}))
            if isinstance(inp, dict):
                cmd = inp.get("command", inp.get("cmd", ""))
                log_msg = f"[{cve_id}] $ {cmd[:300]}" if cmd else \
                          f"[{cve_id}] tool:{tool}({str(inp)[:200]})"
            else:
                log_msg = f"[{cve_id}] tool:{tool}"
            logger.info("[VEX] %s %s", cve_id, log_msg)
            await progress_q.put({
                "type": "stage_progress", "stage": "vex_analyzing",
                "log": log_msg,
            })

        elif obj_type in ("tool_result", "function_result"):
            output = obj.get("output", obj.get("result", ""))
            if isinstance(output, str) and output.strip():
                compact = " ".join(output.strip().split())[:400]
                if compact:
                    await progress_q.put({
                        "type": "stage_progress", "stage": "vex_analyzing",
                        "log": f"[{cve_id}] → {compact}",
                    })

        elif obj_type == "error":
            await _flush_assistant_buffer()
            err = obj.get("message", obj.get("error", str(obj)))
            if _is_gemini_rate_limit(str(err)):
                raise RuntimeError(f"[RATE_LIMIT] {err}")
            await progress_q.put({
                "type": "stage_progress", "stage": "vex_analyzing",
                "log": f"[{cve_id}] Gemini error: {err}",
            })
        # Other types (usage, done, heartbeat, …) are silently ignored.

    # ── stdout reader ─────────────────────────────────────────────────────

    async def _read_stdout(stream: asyncio.StreamReader | None) -> None:
        nonlocal final_detected
        if stream is None:
            return
        if use_stream_json:
            # Line-buffered JSON parsing
            buf = ""
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    # Flush remaining line buffer
                    if buf.strip():
                        await _handle_json_line(buf.strip())
                    # Flush any remaining assistant text buffer
                    await _flush_assistant_buffer()
                    return
                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line:
                        await _handle_json_line(line)
                    if final_detected:
                        return  # terminate early after OpenVEX detected
        else:
            # Plain-text mode: strip ANSI, accumulate, detect OpenVEX
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    return
                text = _strip_ansi(chunk.decode("utf-8", errors="replace"))
                if not text:
                    continue
                assistant_content_parts.append(text)
                compact = " ".join(text.split())
                if compact:
                    if len(compact) > GEMINI_STREAM_LOG_CHARS:
                        compact = compact[:GEMINI_STREAM_LOG_CHARS] + "..."
                    logger.info("[VEX] %s stdout: %s", cve_id, compact)
                    await progress_q.put({
                        "type": "stage_progress", "stage": "vex_analyzing",
                        "log": f"[{cve_id}] {compact}",
                    })
                if not final_detected and GEMINI_CLI_MODE != "headless":
                    if extract_json_from_response("".join(assistant_content_parts)) is not None:
                        final_detected = True
                        final_event.set()
                        await progress_q.put({
                            "type": "stage_progress", "stage": "vex_analyzing",
                            "log": f"[{cve_id}] OpenVEX JSON detected; stopping Gemini",
                        })
                        asyncio.create_task(
                            _terminate_process_group(proc, cve_id, "OpenVEX complete")
                        )
                        return

    # ── stderr reader ─────────────────────────────────────────────────────

    async def _read_stderr(stream: asyncio.StreamReader | None) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            text = _strip_ansi(chunk.decode("utf-8", errors="replace"))
            if not text:
                continue
            stderr_parts.append(text)
            # Filter out noisy but expected startup banners
            if "YOLO mode is enabled" in text:
                continue
            compact = " ".join(text.split())
            if not compact:
                continue
            if len(compact) > GEMINI_STREAM_LOG_CHARS:
                compact = compact[:GEMINI_STREAM_LOG_CHARS] + "..."
            logger.info("[VEX] %s stderr: %s", cve_id, compact)
            await progress_q.put({
                "type": "stage_progress", "stage": "vex_analyzing",
                "log": f"[{cve_id}] stderr: {compact}",
            })
            if _is_gemini_rate_limit(text):
                await progress_q.put({
                    "type": "stage_progress", "stage": "vex_analyzing",
                    "log": f"[{cve_id}] Gemini capacity/rate limit detected",
                })
                await _terminate_process_group(proc, cve_id, "gemini rate limit")
                return

    stdout_task = asyncio.create_task(_read_stdout(proc.stdout))
    stderr_task = asyncio.create_task(_read_stderr(proc.stderr))
    wait_task = asyncio.create_task(proc.wait())

    try:
        while True:
            if wait_task.done() and progress_q.empty():
                break
            if final_event.is_set() and progress_q.empty():
                break

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await _terminate_process_group(proc, cve_id, "timeout")
                raise RuntimeError(f"gemini CLI timed out after {GEMINI_TIMEOUT}s")

            timeout = 1.0 if final_event.is_set() else min(max(1, GEMINI_HEARTBEAT_INTERVAL), remaining)
            try:
                yield await asyncio.wait_for(progress_q.get(), timeout=timeout)
            except asyncio.TimeoutError:
                if final_event.is_set():
                    break
                elapsed = int(time.monotonic() - started_at)
                logger.info("[VEX] %s Gemini CLI still running (%ss elapsed)", cve_id, elapsed)
                yield {
                    "type": "stage_progress",
                    "stage": "vex_analyzing",
                    "log": f"[{cve_id}] Gemini CLI still running ({elapsed}s elapsed)",
                }

        if final_event.is_set() and not wait_task.done():
            try:
                await asyncio.wait_for(wait_task, timeout=5)
            except asyncio.TimeoutError:
                await _terminate_process_group(proc, cve_id, "OpenVEX complete force kill")

        for task in (stdout_task, stderr_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        # response = accumulated assistant content (not raw stdout JSON)
        response = "".join(assistant_content_parts).strip()
        stderr_text = "".join(stderr_parts).strip()

        if proc.returncode != 0 and not response:
            if _is_gemini_rate_limit(stderr_text):
                raise RuntimeError(f"[RATE_LIMIT] {stderr_text}")
            raise RuntimeError(stderr_text or f"gemini exited with code {proc.returncode}")

        if _is_gemini_rate_limit(stderr_text):
            raise RuntimeError(f"[RATE_LIMIT] {stderr_text}")

        logger.info("[VEX] %s gemini response received (%d chars)", cve_id, len(response))
        yield {"type": "_gemini_response", "response": response}
    except asyncio.CancelledError:
        await _terminate_process_group(proc, cve_id, "cancelled")
        stdout_task.cancel()
        stderr_task.cancel()
        wait_task.cancel()
        raise
    except Exception:
        await _terminate_process_group(proc, cve_id, "error")
        stdout_task.cancel()
        stderr_task.cancel()
        wait_task.cancel()
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
    {"type": "max_turns_reached", "cve_id": str}   # when no OpenVEX JSON found
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    prompt = _build_gemini_yolo_prompt(cve_id, product_info)
    yield {
        "type": "stage_progress",
        "stage": "vex_analyzing",
        "log": f"[{cve_id}] Gemini CLI --yolo analysis started (models: {', '.join(GEMINI_MODELS)})",
    }

    response: Optional[str] = None
    last_rate_limit_error: Optional[str] = None
    retry_cycles = max(1, GEMINI_MODEL_RETRY_CYCLES)

    for cycle in range(retry_cycles):
        for model in GEMINI_MODELS:
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
                break
            except Exception as exc:
                msg = str(exc)
                if "[RATE_LIMIT]" in msg:
                    last_rate_limit_error = msg
                    yield {
                        "type": "stage_progress",
                        "stage": "vex_analyzing",
                        "log": f"[{cve_id}] Gemini capacity/rate limit on {model}; trying next model",
                    }
                    continue
                yield {"type": "error", "message": f"Gemini CLI failed: {msg}"}
                return

        if response is not None:
            break

        if cycle < retry_cycles - 1:
            backoff = _RATE_LIMIT_BACKOFF[min(cycle, len(_RATE_LIMIT_BACKOFF) - 1)]
            yield {
                "type": "stage_progress",
                "stage": "vex_analyzing",
                "log": (
                    f"[{cve_id}] All Gemini models are capacity/rate limited; "
                    f"retrying after {backoff}s"
                ),
            }
            await asyncio.sleep(backoff)

    if response is None and last_rate_limit_error:
        yield {
            "type": "error",
            "message": f"Gemini CLI capacity/rate limit on all configured models: {last_rate_limit_error}",
        }
        return

    if response is None:
        yield {"type": "error", "message": "Gemini CLI finished without a response"}
        return

    # Save full raw response
    response_path = output_dir / f"{cve_id}_gemini_yolo.md"
    response_path.write_text(
        f"# {cve_id} Gemini CLI --yolo analysis\n\n{response}\n",
        encoding="utf-8",
    )

    vex_doc = extract_json_from_response(response)
    if not vex_doc:
        logger.warning("[VEX] %s no OpenVEX JSON found; using fallback", cve_id)
        yield {"type": "max_turns_reached", "cve_id": cve_id}
        vex_doc = _build_fallback_vex(cve_id, product_info)
        statement = _extract_statement_from_vex(cve_id, vex_doc, 1)
    else:
        statement = _extract_statement_from_vex(cve_id, vex_doc, 1)

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

        async for event in run_vex_analysis_loop(
            cve_id=cve_id,
            rootfs_path=rootfs_path,
            product_info=product_info,
            output_dir=vex_dir,
        ):
            yield event
            if event["type"] == "vex_complete":
                last_statement = event.get("statement")

        if cancel_marker.exists():
            yield {"type": "batch_cancelled", "message": "VEX analysis cancelled"}
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
    Gemini 최종 응답에서 분석 요약 보고서 텍스트를 추출합니다.
    OpenVEX JSON 블록(```json ... ```) 이전의 텍스트가 보고서입니다.
    """
    json_block_start = response.find("```json")
    if json_block_start > 0:
        report = response[:json_block_start].strip()
    else:
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
