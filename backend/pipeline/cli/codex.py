"""OpenAI Codex CLI(v0.122+) 기반 VEX 분석 어댑터.

Gemini 경로와 달리 **PTY 가 필요 없다**. ``codex exec --json`` 이 stdout 을
JSONL 로 흘려주므로 line-by-line 파싱만으로 충분하다. Ink/pyte/Chrome 필터/
Shell 박스 재구성 등 Gemini 쪽에 쌓인 해킹은 전부 불필요.

최종 OpenVEX JSON 은 ``--output-schema`` 로 스키마를 강제하고
``--output-last-message`` 로 파일에 받아서 파싱한다. Gemini 의 ``WriteFile``
staging 규약(rootfs 에 .firmcore_*.json 을 두고 옮기는 방식)이 필요 없어
sandbox 를 ``read-only`` 로 유지해도 된다 — rootfs 오염 0.

외부 인터페이스는 ``run_vex_analysis_loop`` 쪽에서 호출하는 다음 async
generator 하나::

    async for evt in stream_codex_exec(prompt, rootfs_path, cve_id, model,
                                       output_dir, log_path):
        yield evt  # stage_progress / _codex_result / error 이벤트
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import signal
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

from .base import RateLimitError

logger = logging.getLogger(__name__)

# Gemini 경로가 쓰는 스트리머용 로거 — 백엔드 stdout 에 message 만 바로
# 출력해서 분석 진행을 터미널에서 실시간으로 확인할 수 있게 한다.  Codex
# 경로도 동일한 로거를 공유해 사용자가 엔진 구분 없이 같은 방식으로 로그를
# 읽을 수 있게 만든다.  (``pipeline.vex`` 모듈이 import 되면 이 로거에
# StreamHandler 가 붙는다.)
_stream_logger = logging.getLogger("pipeline.vex.stream")
if not _stream_logger.handlers:
    _stream_handler = logging.StreamHandler()
    _stream_handler.setFormatter(logging.Formatter("%(message)s"))
    _stream_logger.addHandler(_stream_handler)
    _stream_logger.propagate = False
    _stream_logger.setLevel(logging.INFO)

# ── 경로 상수 ───────────────────────────────────────────────────────────────

_PACKAGE_DIR = Path(__file__).resolve().parent
_OPENVEX_SCHEMA_PATH = _PACKAGE_DIR.parent / "openvex_schema.json"

# ── 환경변수 ────────────────────────────────────────────────────────────────

CODEX_BIN = os.environ.get("CODEX_BIN", "codex").strip() or "codex"
# 전체 wall-clock timeout (초). Gemini 의 VEX_GEMINI_TIMEOUT(1800) 과 동등.
CODEX_TIMEOUT = int(os.environ.get("VEX_CODEX_TIMEOUT", os.environ.get("VEX_GEMINI_TIMEOUT", "1800")))
# 진행 stdout 이 이 시간 동안 한 줄도 안 오면 hang 으로 간주하고 강제 종료.
CODEX_IDLE_SHUTDOWN_S = int(os.environ.get("VEX_CODEX_IDLE_SHUTDOWN", "180"))
# reasoning item 을 로그로 방출할지 (기본 False — 너무 verbose)
CODEX_LOG_REASONING = os.environ.get("VEX_CODEX_LOG_REASONING", "0") == "1"
# stderr 를 로그로 노출할지 (기본 True — rate-limit 메시지가 여기 올 수 있음)
CODEX_LOG_STDERR = os.environ.get("VEX_CODEX_LOG_STDERR", "1") == "1"
# command_execution aggregated_output 을 로그로 방출할 때 너무 길면 축약.
# rootfs 전체 파일 목록처럼 만 단위 라인이 오면 UI/로그 가독성이 붕괴됨.
# 전체 원문은 ``{CVE-ID}_codex_jsonl.log`` 에 남으므로 분석 자체에는 지장 없음.
CODEX_SHELL_OUTPUT_MAX_LINES = int(os.environ.get("VEX_CODEX_SHELL_MAX_LINES", "50"))
# Reasoning effort override — 설정 시 ``-c model_reasoning_effort=<value>``
# 로 주입해 ``~/.codex/config.toml`` 의 값(기본 medium)을 덮어쓴다.
# 허용 값: minimal / low / medium / high / xhigh.  비워두면 config.toml
# 설정을 그대로 상속(보통 "medium").
CODEX_REASONING_EFFORT = os.environ.get("CODEX_REASONING_EFFORT", "").strip().lower()
# Reasoning summary 상세도 (auto / concise / detailed / none).  detailed 로
# 두면 Codex 가 사고 과정 요약을 더 자주 방출하는데 로그가 길어진다.
CODEX_REASONING_SUMMARY = os.environ.get("CODEX_REASONING_SUMMARY", "").strip().lower()

# ── Rate-limit 감지 ─────────────────────────────────────────────────────────


def _is_codex_rate_limit(text: str) -> bool:
    """Codex / OpenAI 의 rate-limit 문자열 패턴.

    실데이터 수집 전 보수적인 substring 매칭. ``turn.failed`` 의 error 필드
    와 stderr 둘 다에서 호출된다. 1차 배포 후 샘플 수집해 보강한다.
    """
    if not text:
        return False
    lowered = text.lower()
    return (
        "rate_limit" in lowered
        or "rate limit" in lowered
        or "ratelimit" in lowered
        or "quota" in lowered
        or "status 429" in lowered
        or "code 429" in lowered
        or " 429" in lowered  # "HTTP 429" 등
        or "resource_exhausted" in lowered
        or "usage limit" in lowered
        or "too many requests" in lowered
        or "you have reached your" in lowered
    )


def _setup_codex_subprocess() -> None:
    """Gemini 쪽 _setup_gemini_subprocess 와 동일 — 새 세션 + PDEATHSIG.

    cleanup (Ctrl+C) 시 부모가 프로세스 그룹 SIGKILL 로 정리할 수 있어야 한다.
    Gemini 쪽 헬퍼를 import 하면 순환 참조가 생겨 동일 로직을 이 모듈에 복제.
    """
    os.setsid()
    try:
        libc = ctypes.CDLL(None)
        pr_set_pdeathsig = 1
        libc.prctl(pr_set_pdeathsig, signal.SIGTERM)
    except Exception:
        pass


# ── 로그 방출 helper ────────────────────────────────────────────────────────


def _mk_log_event(cve_id: str, line: str) -> dict[str, Any]:
    """``run_vex_analysis_loop`` 가 기대하는 stage_progress 이벤트 형태.

    SSE 로 프론트엔드에 보내는 동시에, Gemini 경로와 동일한 ``stream_logger``
    로 백엔드 stdout 에도 그대로 방출해 ``./start.sh`` 터미널에서 분석 진행을
    실시간으로 볼 수 있게 한다.
    """
    log_text = f"[{cve_id}] {line}"
    _stream_logger.info(log_text)
    return {
        "type": "stage_progress",
        "stage": "vex_analyzing",
        "log": log_text,
    }


def _format_shell_output_lines(output: str, exit_code: Optional[int]) -> list[str]:
    """Codex interactive TUI 의 ``└ output`` 스타일로 한 줄씩 분해.

    Codex 의 ``aggregated_output`` 은 전체 stdout 을 통째로 담으므로 라인별로
    쪼개 ``  <line>`` 로 prefix.  rootfs 전체 나열 같은 과다 출력은
    ``CODEX_SHELL_OUTPUT_MAX_LINES`` 로 축약해 로그 가독성을 보호한다.
    전체 원문은 ``_codex_jsonl.log`` 에 그대로 남아있다.
    """
    lines = output.rstrip("\n").splitlines() if output else []
    emitted: list[str] = []
    if not lines:
        # 출력이 비면 상태만 간단히
        if exit_code not in (0, None):
            emitted.append(f"  (exit {exit_code}, no output)")
        else:
            emitted.append("  (no output)")
        return emitted

    limit = max(CODEX_SHELL_OUTPUT_MAX_LINES, 10)
    if len(lines) <= limit:
        emitted.extend(f"  {ln}" for ln in lines)
    else:
        emitted.extend(f"  {ln}" for ln in lines[:limit])
        truncated = len(lines) - limit
        emitted.append(
            f"  … (+{truncated} more lines truncated; see _codex_jsonl.log)"
        )
    if exit_code not in (0, None):
        emitted.append(f"  (exit {exit_code})")
    return emitted


# ── JSONL 이벤트 dispatch ───────────────────────────────────────────────────


def _dispatch_jsonl_event(
    evt: dict[str, Any],
    cve_id: str,
    state: dict[str, Any],
) -> list[dict[str, Any]]:
    """단일 JSONL 이벤트를 처리해 0개 이상의 stage_progress 이벤트로 변환.

    ``state`` 는 호출자가 소유하는 mutable dict — rate-limit 감지 플래그,
    turn usage 같은 상태를 모아두는 용도. 부작용으로 ``state`` 를 갱신한다.

    rate-limit 감지 시 바로 ``RateLimitError`` 를 raise 한다.
    """
    t = evt.get("type", "")
    emitted: list[dict[str, Any]] = []

    if t == "thread.started":
        thread_id = evt.get("thread_id")
        if thread_id:
            emitted.append(_mk_log_event(cve_id, f"codex thread: {thread_id}"))
        return emitted

    if t == "turn.started":
        emitted.append(_mk_log_event(cve_id, "codex turn start"))
        return emitted

    if t == "turn.completed":
        usage = evt.get("usage") or {}
        emitted.append(_mk_log_event(
            cve_id,
            "codex turn complete — "
            f"tokens in={usage.get('input_tokens')} "
            f"cached={usage.get('cached_input_tokens')} "
            f"out={usage.get('output_tokens')}",
        ))
        state["turn_completed"] = True
        return emitted

    if t in ("turn.failed", "error"):
        # 스키마가 안정적이지 않으니 일단 이벤트 전체를 문자열화해서 scan
        err_payload = evt.get("error") or evt.get("message") or evt
        err_str = json.dumps(err_payload, ensure_ascii=False) if isinstance(err_payload, (dict, list)) else str(err_payload)
        if _is_codex_rate_limit(err_str):
            raise RateLimitError(
                engine="codex",
                model=state.get("model", ""),
                message=f"codex {t}: {err_str}",
            )
        raise RuntimeError(f"codex {t}: {err_str}")

    if t == "item.started":
        item = evt.get("item") or {}
        it = item.get("type")
        if it == "command_execution":
            # Codex interactive TUI 의 ``• Ran <cmd>`` 스타일.  시작 시점에
            # command 만 표시하고 결과는 item.completed 에서 방출.
            cmd = item.get("command") or "(?)"
            emitted.append(_mk_log_event(cve_id, f"• Ran: {cmd}"))
        elif it == "web_search":
            query = item.get("query") or ""
            emitted.append(_mk_log_event(cve_id, f"• Searching: {query}" if query else "• Searching the web"))
        # agent_message / reasoning 의 started 는 noisy 해서 스킵
        return emitted

    if t == "item.completed":
        item = evt.get("item") or {}
        it = item.get("type")
        if it == "agent_message":
            text = (item.get("text") or "").rstrip()
            if text:
                # Codex 인터랙티브 TUI 와 동일한 ``•`` bullet — Gemini 쪽의
                # ``✦`` 습관과 혼용하지 않고 엔진별 네이티브 스타일 유지.
                # 첫 줄만 ``•`` 를 붙이고 이어지는 줄은 들여쓰기로 계층 표현.
                lines = text.splitlines()
                first = True
                for line in lines:
                    if not line.strip():
                        emitted.append(_mk_log_event(cve_id, ""))
                        continue
                    prefix = "• " if first else "  "
                    emitted.append(_mk_log_event(cve_id, f"{prefix}{line}"))
                    first = False
        elif it == "reasoning":
            if CODEX_LOG_REASONING:
                text = (item.get("text") or item.get("summary") or "").strip()
                if text:
                    # 사고 과정 요약은 첫 줄 한 번만 방출 (본문 verbose 방지)
                    summary_line = text.splitlines()[0][:180]
                    emitted.append(_mk_log_event(cve_id, f"• Reasoning: {summary_line}"))
        elif it == "command_execution":
            output = item.get("aggregated_output") or ""
            exit_code = item.get("exit_code")
            # output 만 방출 (command 자체는 item.started 에서 이미 표시).
            # 최초 방출되는 output 라인에 ``└`` 를 prefix 해 명령과의 소속
            # 관계를 표시.
            lines = _format_shell_output_lines(output, exit_code)
            if lines:
                # 첫 줄은 ``└ `` 로 — Codex TUI 와 동일한 tree 마커
                first, *rest = lines
                emitted.append(_mk_log_event(cve_id, f"└{first[1:]}" if first.startswith(" ") else f"└ {first.lstrip()}"))
                for ln in rest:
                    emitted.append(_mk_log_event(cve_id, ln))
        elif it == "file_change":
            path = item.get("path") or "(?)"
            kind = (item.get("change_type") or item.get("kind") or "changed").lower()
            ins = item.get("insertions")
            dels = item.get("deletions")
            verb = {"add": "Added", "create": "Added", "modify": "Modified", "delete": "Deleted"}.get(kind, "Changed")
            stats = ""
            if ins is not None or dels is not None:
                stats = f" (+{ins or 0} -{dels or 0})"
            emitted.append(_mk_log_event(cve_id, f"• {verb}: {path}{stats}"))
        elif it == "mcp_tool_call":
            name = item.get("name") or item.get("tool") or "(?)"
            emitted.append(_mk_log_event(cve_id, f"• MCP tool: {name}"))
        elif it == "web_search":
            # started 에서 이미 "Searching" 을 방출했으므로 completed 는
            # 결과 요약 한 줄만.  results 필드가 있으면 상위 1-2건.
            query = item.get("query") or ""
            results = item.get("results") or []
            if results and isinstance(results, list):
                top = results[0]
                title = top.get("title") if isinstance(top, dict) else str(top)
                emitted.append(_mk_log_event(cve_id, f"• Searched: {query} → {title}"))
            else:
                emitted.append(_mk_log_event(cve_id, f"• Searched: {query}"))
        elif it == "plan_update":
            summary = item.get("summary") or item.get("title") or ""
            if summary:
                emitted.append(_mk_log_event(cve_id, f"• Plan: {summary}"))
        return emitted

    # 알려지지 않은 이벤트 — 로그에 남겨 이후 스키마 파악에 사용
    logger.debug("[codex] unknown JSONL event: %s", t)
    return emitted


# ── 최종 산출물 파싱 ────────────────────────────────────────────────────────


def _parse_codex_output(
    last_message_path: Path,
    cve_id: str,
) -> tuple[Optional[dict[str, Any]], str]:
    """``-o`` 파일에서 OpenVEX JSON + 보고서 md 를 분리.

    프롬프트에서 "최종 응답은 OpenVEX JSON 한 객체만" 으로 지시했으므로
    대부분의 경우 파일 내용은 유효한 JSON.  모델이 앞뒤로 텍스트를 붙였다면
    공용 ``extract_json_from_response`` 로 fenced block 추출을 시도한다
    (순환 import 회피를 위해 지연 import).

    JSON 을 끝내 추출하지 못하면 ``(None, "")`` 을 반환 — 상위 루프가
    ``vex_json_not_found`` 이벤트 + ``_build_fallback_vex`` 로 폴백하게
    만들기 위함. Gemini 경로와 동일한 회복 정책.

    반환: ``(vex_doc_or_None, report_text)``
    """
    try:
        raw = last_message_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger.warning("[codex] %s cannot read last_message file: %s", cve_id, exc)
        return None, ""
    if not raw:
        logger.warning("[codex] %s last_message file is empty", cve_id)
        return None, ""

    vex_doc: Optional[dict[str, Any]]
    try:
        vex_doc = json.loads(raw)
    except json.JSONDecodeError:
        from pipeline.vex import extract_json_from_response  # lazy import
        vex_doc = extract_json_from_response(raw)
        if not vex_doc:
            logger.warning(
                "[codex] %s output is not valid OpenVEX JSON (first 200 chars: %r) — "
                "상위 루프가 fallback VEX 로 처리",
                cve_id, raw[:200],
            )
            return None, ""

    report_text = ""
    stmts = vex_doc.get("statements") or []
    if stmts:
        first = stmts[0]
        # x_firmcore_report_md 확장 필드로 보고서를 JSON 안에 임베드하도록
        # 프롬프트가 유도.  추출 후엔 JSON 에서 제거해 보고서가 두 번
        # 저장되지 않게.
        if isinstance(first.get("x_firmcore_report_md"), str):
            report_text = first.pop("x_firmcore_report_md").strip()
    return vex_doc, report_text


# ── 메인 어댑터 ─────────────────────────────────────────────────────────────


async def stream_codex_exec(
    prompt: str,
    rootfs_path: Path,
    cve_id: str,
    model: str,
    output_dir: Path,
    log_path: Optional[Path] = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """Codex CLI 로 한 CVE 를 분석하며 stage_progress 이벤트를 yield.

    Gemini 쪽 ``stream_gemini_yolo`` 와 대응. 동일하게 분석 종료 시 내부
    sentinel 이벤트 ``{type: "_codex_result", vex_doc: dict, report_text: str}``
    을 한 번 yield 하고 끝난다. ``run_vex_analysis_loop`` 는 이 sentinel 을
    받아 ``_vex.json`` / ``_report.md`` 로 저장한다.

    rate-limit 발생 시 ``RateLimitError`` raise — 상위 attempt chain 이 다음
    spec 으로 폴백한다.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    last_message_path = (output_dir / f"{cve_id}_codex_last.json").resolve()
    # 이전 실행 잔존 파일 제거
    for stale in (last_message_path,):
        if stale.exists():
            try:
                stale.unlink()
            except OSError:
                pass

    # ── subprocess 인자 구성 ────────────────────────────────────────────
    # ``codex exec`` 는 approval-policy 플래그(``-a``) 를 지원하지 않는다
    # (interactive 모드 전용) — exec 는 항상 승인 prompt 없이 실행한다.
    # 샌드박스만 ``-s read-only`` 로 고정해 rootfs 쓰기를 차단한다.
    #
    # ``--output-schema`` 는 의도적으로 쓰지 않는다.  OpenAI Structured
    # Output 은 스키마에 매우 엄격한 제약(모든 object 가 ``additionalProperties:
    # false`` + 모든 property 가 ``required``) 을 요구해서 우리 OpenVEX
    # 스키마와 맞지 않고, 강제 적용 시 Codex 가 응답을 실패하는 리스크가 크다.
    # 대신 프롬프트(codex_prompt_override) 에서 "최종 응답은 OpenVEX JSON
    # 하나만" 을 명시하고, ``--output-last-message`` 로 저장된 마지막
    # agent_message 에서 ``extract_json_from_response`` 로 JSON 을 추출한다.
    args: list[str] = [
        CODEX_BIN, "exec",
        "--json",
        "--skip-git-repo-check",
        "--ephemeral",
        "-s", "read-only",
        "-C", str(rootfs_path),
        "-o", str(last_message_path),
        "--color", "never",
    ]
    # Codex CLI 에 ``-m`` 을 생략하는 sentinel 들.  ChatGPT OAuth 계정은
    # 명시 모델(``-m gpt-5-codex`` 등) 을 거부하고 CLI 기본 모델만 허용한다.
    _skip_m_sentinels = {"auto", "default", "codex-default", "codex-auto", ""}
    if model and model.lower() not in _skip_m_sentinels:
        args.extend(["-m", model])

    # ``~/.codex/config.toml`` 의 reasoning 설정을 env var 로 per-job 오버라이드.
    # 설정 시 ``-c`` 로 주입.  비워두면 config.toml 값(보통 medium) 그대로 사용.
    if CODEX_REASONING_EFFORT:
        args.extend(["-c", f'model_reasoning_effort="{CODEX_REASONING_EFFORT}"'])
    if CODEX_REASONING_SUMMARY:
        args.extend(["-c", f'model_reasoning_summary="{CODEX_REASONING_SUMMARY}"'])
    # prompt 는 stdin 으로 넘긴다 (매우 길어도 arg 한도에 안 걸림)
    args.append("-")

    # ── 환경변수 ────────────────────────────────────────────────────────
    env = os.environ.copy()
    # TERM 은 Codex 에 불필요하지만 이미 설정돼 있으면 그대로 둬도 무해.
    # CI 플래그가 있으면 non-interactive 로 떨어지는데 exec 모드에서는 상관 없음.
    env.setdefault("CODEX_HOME", os.path.expanduser("~/.codex"))

    yield _mk_log_event(
        cve_id,
        f"codex exec start — model={model or '(default)'} "
        f"sandbox=read-only rootfs={rootfs_path}",
    )

    # asyncio.StreamReader 의 기본 라인 버퍼(64KB) 는 Codex 의
    # ``item.completed{type:"command_execution"}`` 이벤트에 비해 매우 작다.
    # 이 이벤트는 실행된 Shell 의 **전체 stdout** 을 ``aggregated_output`` 에
    # 단일 JSONL 라인으로 담아 보내므로 ``rg --files .`` 나 ``find . -type f``
    # 같은 탐색이 수백 KB~수 MB 의 한 줄 JSON 을 만들 수 있다.  limit 을
    # 32MB 로 넉넉히 올려둔다.
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        preexec_fn=_setup_codex_subprocess,
        limit=32 * 1024 * 1024,
    )

    # prompt 쓰기 (close 해서 Codex 가 stdin EOF 인식)
    assert proc.stdin is not None
    try:
        proc.stdin.write(prompt.encode("utf-8"))
        await proc.stdin.drain()
    finally:
        proc.stdin.close()

    state: dict[str, Any] = {"model": model, "turn_completed": False, "idle_forced_kill": False}

    # stderr 를 비동기로 drain — 로그용 + 종료 후 rate-limit 재체크용
    stderr_chunks: list[bytes] = []

    async def _drain_stderr() -> None:
        assert proc.stderr is not None
        async for line in proc.stderr:
            stderr_chunks.append(line)

    stderr_task = asyncio.create_task(_drain_stderr())

    raw_jsonl_parts: list[str] = []  # debug 로그용
    last_stdout_ts = asyncio.get_running_loop().time()

    async def _readline_with_idle() -> Optional[bytes]:
        """stdout.readline 에 idle shutdown 로직을 얹는다."""
        nonlocal last_stdout_ts
        assert proc.stdout is not None
        while True:
            try:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=CODEX_IDLE_SHUTDOWN_S,
                )
            except asyncio.TimeoutError:
                # idle: 강제 종료
                state["idle_forced_kill"] = True
                logger.warning(
                    "[codex] %s idle for %ds — forcing shutdown",
                    cve_id, CODEX_IDLE_SHUTDOWN_S,
                )
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                return None
            if not line:
                return None
            last_stdout_ts = asyncio.get_running_loop().time()
            return line

    try:
        # Wall-clock timeout 은 매 루프 시작 시 polled.  Python 3.11+ 의
        # ``asyncio.timeout`` 대신 수동 체크 — 3.10 호환 유지.  세밀한
        # interrupt 는 ``_readline_with_idle`` 쪽의 idle shutdown 이
        # 이미 담당하므로 여기선 coarse-grained 로 충분.
        loop = asyncio.get_running_loop()
        start_ts = loop.time()
        timed_out = False
        while True:
            if loop.time() - start_ts > CODEX_TIMEOUT:
                timed_out = True
                break
            line = await _readline_with_idle()
            if line is None:
                break
            raw = line.decode("utf-8", errors="replace").rstrip("\n")
            if not raw.strip():
                continue
            raw_jsonl_parts.append(raw)
            try:
                evt = json.loads(raw)
            except json.JSONDecodeError:
                # JSONL 모드에선 한 줄 = 한 JSON 이 원칙이지만 color banner
                # 같은 비정상 라인이 올 수도.
                logger.debug("[codex] non-JSON line dropped: %s", raw[:200])
                continue
            # dispatch — RateLimitError 가 여기서 raise 될 수 있음
            for out_evt in _dispatch_jsonl_event(evt, cve_id, state):
                yield out_evt
        if timed_out:
            logger.warning("[codex] %s hit wall-clock timeout %ds", cve_id, CODEX_TIMEOUT)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            raise RuntimeError(f"codex CLI timed out after {CODEX_TIMEOUT}s")

        # ── 프로세스 종료 대기 + stderr drain 완료
        try:
            await asyncio.wait_for(proc.wait(), timeout=15)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            await proc.wait()

        await stderr_task

        stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        # ── raw JSONL 아카이브 (디버깅용, Gemini _pty_raw.log 와 동등)
        if log_path is not None:
            try:
                log_path.write_text("\n".join(raw_jsonl_parts) + "\n", encoding="utf-8")
            except OSError:
                logger.warning("[codex] failed to persist raw JSONL log: %s", log_path)

        # ── 실패 분류
        if proc.returncode != 0 or state["idle_forced_kill"]:
            if CODEX_LOG_STDERR and stderr_text.strip():
                # 상위로 올리기 전 stderr 를 마지막 stage_progress 로 노출
                for line in stderr_text.splitlines()[-20:]:
                    if line.strip():
                        yield _mk_log_event(cve_id, f"  stderr: {line.rstrip()}")
            if _is_codex_rate_limit(stderr_text):
                raise RateLimitError(
                    engine="codex",
                    model=model,
                    message=f"codex rate-limit (exit={proc.returncode}): {stderr_text.strip()[:400]}",
                )
            raise RuntimeError(
                f"codex exec failed (exit={proc.returncode}): "
                f"{stderr_text.strip()[:400] or '(no stderr)'}"
            )

        if not last_message_path.exists():
            raise RuntimeError(
                f"codex finished but {last_message_path.name} is missing — "
                f"schema likely rejected the response. stderr tail: "
                f"{stderr_text.strip()[-400:] or '(none)'}"
            )

        # ── 결과 파싱 후 sentinel 이벤트 yield
        vex_doc, report_text = _parse_codex_output(last_message_path, cve_id)
        yield {
            "type": "_codex_result",
            "vex_doc": vex_doc,
            "report_text": report_text,
            "raw_jsonl_path": str(log_path) if log_path else None,
        }

    finally:
        # 어떤 경로로 빠지든 프로세스와 stderr drain 태스크 정리
        if proc.returncode is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        if not stderr_task.done():
            stderr_task.cancel()
            try:
                await stderr_task
            except (asyncio.CancelledError, Exception):
                pass
