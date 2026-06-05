"""EMBA(Embedded Linux Analyzer) 기반 펌웨어 추출 + SBOM 생성 + CPE 후처리.

이 모듈은 FirmCore 의 ``extracting`` + ``sbom_generating`` 두 stage 를 단일
파이프라인으로 처리한다.  세부 흐름:

    1. EMBA 호출 (Ubuntu native, docker 모드)
       - ``default-sbom`` 프로파일로 펌웨어 추출 + CycloneDX SBOM 생성
       - 사용자(또는 백엔드 프로세스) 가 ``docker`` 그룹 멤버이면 sudo 불필요.
         EMBA wrapper 가 그 조건에서 자동으로 root 체크를 우회한다.
    2. fix_cpe.py (cpe_mapper venv 의 python 으로 호출)
       - EMBA SBOM 의 JSON repair + cpe 13-field 정규화 1차
    3. enrich_sbom.py (cwd=cpe_mapper)
       - NVD CPE 사전 + Top-1 결정 + 3 properties 병기 (deterministic)

EMBA 산출물 위치:
    - storage/<job>/emba_logs/                       — EMBA 가 직접 출력
    - storage/<job>/emba_logs/SBOM/EMBA_cyclonedx_sbom.json  — CycloneDX SBOM
    - storage/<job>/emba_logs/firmware/.../rootfs/   — 추출된 rootfs (VEX 분석 cwd)

UI 의 ``extracting`` stage 는 EMBA stdout 의 ``P##_`` 모듈 마커가 보일 동안,
``sbom_generating`` 은 ``S##_`` 첫 등장 시점부터 enrich 완료까지.

설계 결정 — Ubuntu native 직접 호출:
    이전 버전은 EMBA 가 Kali WSL 에 설치되어 있어 ``wsl.exe -d kali-linux``
    경유 호출 + ``/mnt/c/temp`` 윈도우 브릿지 + Kali↔Ubuntu cp 등 복잡한 흐름이
    필요했다.  현재는 Ubuntu WSL 자체에 EMBA 설치 → 단순 subprocess.exec 호출로
    충분하고 9P 통과/sync/staging 단계 모두 제거됨.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import re
import shlex
import shutil
import signal
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger(__name__)

# Gemini/Codex stream 과 동일한 logger — 백엔드 stdout 에 실시간 출력
_stream_logger = logging.getLogger("pipeline.vex.stream")
if not _stream_logger.handlers:
    _stream_handler = logging.StreamHandler()
    _stream_handler.setFormatter(logging.Formatter("%(message)s"))
    _stream_logger.addHandler(_stream_handler)
    _stream_logger.propagate = False
    _stream_logger.setLevel(logging.INFO)


# ── 환경변수 ────────────────────────────────────────────────────────────────


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


EMBA_BIN = _env("EMBA_BIN", "/home/ktdevice/work/emba/emba")
EMBA_PROFILE = _env("EMBA_PROFILE", "default-sbom")
EMBA_TIMEOUT = int(_env("EMBA_TIMEOUT", "7200"))  # 2h wall-clock

FIX_CPE_BIN = _env("FIX_CPE_BIN", "/home/ktdevice/fix_cpe.py")

CPE_MAPPER_DIR = _env("CPE_MAPPER_DIR", "/home/ktdevice/cpe_mapper")
CPE_MAPPER_PYTHON = _env("CPE_MAPPER_PYTHON", "/home/ktdevice/cpe_mapper/.venv/bin/python")
CPE_MAPPER_BACKEND = _env("CPE_MAPPER_BACKEND", "deterministic")
CPE_MAPPER_TIMEOUT = int(_env("CPE_MAPPER_TIMEOUT", "1800"))  # 30min


# ── EMBA stdout 마커 ───────────────────────────────────────────────────────
# ``[*] P02_firmware_bin_file_check`` 처럼 ``[*] `` 뒤에 모듈 ID 가 붙는다.
# ANSI 컬러는 stdin/stdout 이 pipe 일 때 EMBA 가 자동으로 끄긴 하지만 안전을
# 위해 strip.
_RE_ANSI = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_RE_P_MODULE = re.compile(r"\bP\d{2}_[A-Za-z0-9_]+")
_RE_S_MODULE = re.compile(r"\bS\d{2}_[A-Za-z0-9_]+")
# tqdm progress bar 출력 패턴 — ``enrich: 64%|████ | 312/486 [01:49<00:24, ...]``
# enrich_sbom.py 가 매 컴포넌트 단위로 \r in-place 갱신을 쏘는데 우리 reader
# 는 그걸 매 update 마다 한 줄로 받음 → 로그 뷰어가 한 화면 가득 누적됨.
# 백엔드에서 이 라인을 식별해 log 로는 안 보내고 progress(%) 만 추출해
# PipelineStepper 의 sbom_generating progress bar 에 반영한다.
_RE_TQDM_ENRICH = re.compile(r"enrich:\s+(\d+)%\|[^|]*\|\s*(\d+)/(\d+)")


def _strip_ansi(text: str) -> str:
    return _RE_ANSI.sub("", text)


def _resolve_profile_arg(profile: str) -> str:
    """EMBA ``-p`` 인자 정규화.

    EMBA 는 profile 인자를 단순 이름 (``default-sbom``) 으로 받지 않고,
    실제 파일 경로 (``./scan-profiles/default-sbom.emba``) 를 요구한다.
    사용자가 환경변수에 짧은 이름을 줘도 자동으로 변환해 준다.

    규칙::

        'default-sbom'                                   → './scan-profiles/default-sbom.emba'
        'default-sbom.emba'                              → './scan-profiles/default-sbom.emba'
        './scan-profiles/default-sbom.emba'              → 그대로
        '/abs/path/to/scan-profiles/default-sbom.emba'   → 그대로
    """
    profile = profile.strip()
    if profile.startswith(("/", "./", "../")):
        return profile
    name = profile if profile.endswith(".emba") else f"{profile}.emba"
    return f"./scan-profiles/{name}"


# ── 결과 파일 / 디렉토리 식별 ──────────────────────────────────────────────


def _find_emba_sbom(emba_log_dir: Path) -> Path:
    """EMBA log_dir 안에서 CycloneDX SBOM 위치 식별.

    검색 순서:
      1. ``<log_dir>/SBOM/EMBA_cyclonedx_sbom.json``  (사용자 검증된 위치)
      2. ``<log_dir>/f15_cyclonedx_sbom/*.json``       (F15 모듈 디렉토리)
      3. ``<log_dir>/**/*cyclonedx*.json`` 중 ``bomFormat: CycloneDX`` 인 첫 파일
    """
    candidates: list[Path] = [
        emba_log_dir / "SBOM" / "EMBA_cyclonedx_sbom.json",
    ]
    f15_dir = emba_log_dir / "f15_cyclonedx_sbom"
    if f15_dir.is_dir():
        candidates.extend(sorted(f15_dir.glob("*.json")))
        candidates.extend(sorted(f15_dir.glob("**/*.json")))
    candidates.extend(sorted(emba_log_dir.rglob("*cyclonedx*.json")))
    candidates.extend(sorted(emba_log_dir.rglob("*sbom*.json")))

    seen: set[Path] = set()
    for cand in candidates:
        if cand in seen or not cand.exists() or not cand.is_file():
            continue
        seen.add(cand)
        if "html-report" in cand.parts:
            continue
        try:
            head = cand.read_text(encoding="utf-8", errors="replace")[:400]
        except OSError:
            continue
        if '"bomFormat"' in head and "CycloneDX" in head:
            logger.info("[binXray] CycloneDX SBOM found: %s", cand)
            return cand

    # F15 가 "nothing reported" 면 SBOM 자체가 없음 — 명확한 진단 메시지
    f15_log = emba_log_dir / "f15_cyclonedx_sbom.txt"
    if f15_log.exists():
        try:
            f15_text = f15_log.read_text(encoding="utf-8", errors="replace")
            if "nothing reported" in f15_text.lower():
                raise FileNotFoundError(
                    "EMBA F15_cyclonedx_sbom: nothing reported — 추출 또는 "
                    "패키지 식별 단계가 실패해 SBOM 이 생성되지 않았습니다. "
                    f"binXray 로그 확인: {emba_log_dir}/emba.log"
                )
        except OSError:
            pass
    raise FileNotFoundError(
        f"binXray SBOM 생성 단계가 CycloneDX 출력을 만들지 못했습니다 (검색 위치: "
        f"{emba_log_dir}/SBOM/, f15_cyclonedx_sbom/, **/*cyclonedx*.json)"
    )


_ROOTFS_NAME_HINTS = ("squashfs-root", "rootfs", "filesystem-root", "fs")
_ROOTFS_SIG_DIRS = ("bin", "etc", "usr", "lib", "var")


def _find_emba_rootfs(emba_log_dir: Path) -> Optional[Path]:
    """EMBA 추출 결과에서 대표 rootfs 디렉토리 식별.

    여러 펌웨어 포맷별 패턴을 cover:
      - SquashFS: ``firmware/.../squashfs-root/``
      - UBI:      ``firmware/ubi_extracted/ubi_files/<seq>/rootfs/``
      - 일반:     ``firmware/.../{bin,etc,usr,lib}`` Linux 시그니처 디렉토리를
                  최소 3개 이상 가진 디렉토리.
    """
    firmware_dir = emba_log_dir / "firmware"
    if not firmware_dir.exists():
        return None

    candidates: list[tuple[int, Path]] = []

    # 1) 명시적 이름 매칭
    for name_hint in _ROOTFS_NAME_HINTS:
        for cand in firmware_dir.rglob(name_hint):
            if not cand.is_dir():
                continue
            children = list(cand.iterdir()) if cand.exists() else []
            if name_hint == "rootfs" and len(children) == 1 and children[0].is_dir():
                cand = children[0]
            try:
                count = sum(1 for _ in cand.rglob("*"))
            except (OSError, PermissionError):
                count = 0
            candidates.append((count, cand))

    # 2) Linux 시그니처 디렉토리 ≥3 개를 자식으로 가진 디렉토리
    for cand in firmware_dir.rglob("*"):
        if not cand.is_dir():
            continue
        try:
            children_names = {p.name for p in cand.iterdir() if p.is_dir()}
        except (OSError, PermissionError):
            continue
        sig_hits = len(children_names & set(_ROOTFS_SIG_DIRS))
        if sig_hits >= 3:
            try:
                count = sum(1 for _ in cand.rglob("*"))
            except (OSError, PermissionError):
                count = 0
            # 시그니처 매칭은 가장 신뢰도 높음 — 큰 가중치
            candidates.append((count + 1_000_000, cand))

    if not candidates:
        return None

    seen: set[Path] = set()
    dedup: list[tuple[int, Path]] = []
    for c, p in sorted(candidates, reverse=True):
        if p in seen:
            continue
        seen.add(p)
        dedup.append((c, p))
    return dedup[0][1] if dedup else None


# ── subprocess helper ─────────────────────────────────────────────────────


def _setup_subprocess() -> None:
    """새 세션 + PDEATHSIG — cleanup 시 부모와 함께 종료."""
    os.setsid()
    try:
        libc = ctypes.CDLL(None)
        pr_set_pdeathsig = 1
        libc.prctl(pr_set_pdeathsig, signal.SIGTERM)
    except Exception:
        pass


async def _chown_emba_logs(log_dir: Path) -> bool:
    """EMBA 가 컨테이너 안의 root(uid=0) 로 만든 파일/디렉토리를 host user
    소유로 변경.

    EMBA 의 일부 sub-process (kernel downloader 등) 는 컨테이너 안에서
    unprivileged user 로 동작해 host root 소유 디렉토리에 쓰기를 시도하다
    ``Permission denied`` 가 뜬다.  EMBA 본 분석에는 무해하지만, 이후
    FirmCore 의 ktdevice (uid=1000) 가 root 소유 파일을 정리/이동/덮어쓰기
    하려 할 때 권한 문제가 발생.

    호스트 sudo 없이 권한 변경하려면 docker 컨테이너(컨테이너 root = host root)
    를 한 번 띄워 ``chown -R <host_uid>:<host_gid> /logs`` 실행.  alpine 같은
    가벼운 image 면 1-2초.  EMBA image 이미 pull 되어 있으니 그걸 재활용.
    """
    if not log_dir.exists():
        return True
    uid_gid = f"{os.getuid()}:{os.getgid()}"
    # EMBA image 의 entrypoint 가 bash 라 직접 ``chown`` 을 명령으로 보지 못함.
    # ``--entrypoint chown`` 으로 명시 override.
    args = [
        "docker", "run", "--rm",
        "--entrypoint", "chown",
        "-v", f"{log_dir}:/logs",
        "embeddedanalyzer/emba:2.0.1a",
        "-R", uid_gid, "/logs",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode != 0:
            logger.warning(
                "[binXray] chown 실패 — rc=%d stderr=%s",
                proc.returncode, err.decode(errors="replace")[:200],
            )
            return False
        return True
    except (asyncio.TimeoutError, OSError) as exc:
        logger.warning("[binXray] chown 호출 예외: %s", exc)
        return False


def _emit(stage: str, prefix: str, line: str) -> dict[str, Any]:
    """stage_progress 이벤트 + stdout stream 출력."""
    msg = f"[{prefix}] {line}" if prefix else line
    _stream_logger.info(msg)
    return {"type": "stage_progress", "stage": stage, "log": msg}


# ── EMBA 호출 (Ubuntu native) ─────────────────────────────────────────────


async def _run_emba(
    firmware_path: Path,
    log_dir: Path,
    product_info: Optional[dict[str, str]] = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """EMBA 를 Ubuntu native subprocess 로 실행하며 stdout 을 stage_progress 로 흘림.

    ``product_info`` 의 name/version/vendor 가 EMBA 의 ``-X/-Y/-Z`` 메타데이터
    인자로 매핑된다 (SBOM 의 metadata.component 에 반영).  사용자는 docker 그룹
    멤버여야 하며 sudo 는 불필요.

    yields:
      {"type":"stage_progress", "stage":"extracting|sbom_generating", ...}
      {"type":"stage_transition", "from":"extracting", "to":"sbom_generating"}
      마지막: {"type":"emba_done"}  (성공)  또는  {"type":"error", ...}
    """
    info = product_info or {}
    fw_version = (info.get("version") or "unknown").strip() or "unknown"
    fw_vendor = (info.get("vendor") or "FirmCore").strip() or "FirmCore"
    fw_device = (info.get("name") or "firmware").strip() or "firmware"

    emba_dir = Path(EMBA_BIN).parent
    venv_activate = emba_dir / "external" / "emba_venv" / "bin" / "activate"
    profile_arg = _resolve_profile_arg(EMBA_PROFILE)

    # log_dir 은 EMBA 가 만들도록 비워둔다 (이미 있으면 EMBA 가 거부할 수도)
    if log_dir.exists():
        shutil.rmtree(log_dir, ignore_errors=True)

    # ── log_dir ACL 사전 셋업 (kernel_downloader Permission denied 회피) ──
    # EMBA 컨테이너 안에서 일부 sub-process 는 root 로, 일부는 uid 1000 으로
    # 동작한다 (host 의 ktdevice uid 와 같은 값).  S24 의 thread function
    # ``kernel_downloader`` 는 다른 process 가 만든 root:root 디렉토리에
    # tee 로 쓰려고 시도해 거부된다.  사용자가 직접 ``sudo`` 로 emba 를
    # 호출하면 host 의 디렉토리도 root 라 충돌 없지만, 우리 백엔드는 docker
    # 그룹 멤버십만으로 sudo 없이 동작하므로 owner mismatch 가 그대로 노출.
    #
    # log_dir 자체를 0777 + default ACL 로 만들어 EMBA 가 그 안에 만드는
    # 모든 sub-dir/file 이 모든 user 쓰기 가능하도록 한다.  분석 종료 후
    # ``_chown_emba_logs`` 가 host uid 로 정리.
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(log_dir, 0o777)
    except OSError:
        pass
    try:
        # -d (default ACL) 가 새로 만들어지는 모든 sub-item 에 자동 적용.
        # acl 패키지 없으면 setfacl 자체가 없어 FileNotFoundError → 무해.
        # mask::rwx 는 default ACL inheritance 시 group/other effective 권한이
        # mode 0755 같은 traditional permission 으로 mask 되지 않도록 유지.
        acl_proc = await asyncio.create_subprocess_exec(
            "setfacl", "-R", "-d", "-m", "u::rwx,g::rwx,o::rwx,m::rwx",
            str(log_dir),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(acl_proc.wait(), timeout=10)
    except (FileNotFoundError, asyncio.TimeoutError) as exc:
        logger.info("[binXray] setfacl skip (%s) — kernel_downloader Permission denied 노이즈가 노출될 수 있음", exc)

    emba_cmd = (
        # SKIP_KERNEL_DOWNLOAD=1 — EMBA 의 host-side kernel_downloader 비활성.
        # binXray 의 SBOM 프로파일은 S26 미사용이라 downloader 결과가 안 쓰이고,
        # host 의 ktdevice 가 컨테이너 root 디렉토리에 tee 하다 Permission denied
        # 가 반복 출력되는 노이즈만 만든다.
        f"export SKIP_KERNEL_DOWNLOAD=1 && "
        f"source {shlex.quote(str(venv_activate))} && "
        f"./{Path(EMBA_BIN).name} "
        f"-f {shlex.quote(str(firmware_path))} "
        f"-l {shlex.quote(str(log_dir))} "
        f"-p {shlex.quote(profile_arg)} "
        f"-X {shlex.quote(fw_version)} "
        f"-Y {shlex.quote(fw_vendor)} "
        f"-Z {shlex.quote(fw_device)} "
        f"-W -y -q"
    )
    args = ["bash", "-c", emba_cmd]

    yield _emit("extracting", "binXray",
                f"start: cd {emba_dir} && ./{Path(EMBA_BIN).name} "
                f"-p {profile_arg} -f {firmware_path.name} -l {log_dir.name} "
                f"-X {fw_version!r} -Y {fw_vendor!r} -Z {fw_device!r} -W -y -q")

    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(emba_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=_setup_subprocess,
        limit=8 * 1024 * 1024,
    )

    current_stage = "extracting"
    last_module: Optional[str] = None
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    timed_out = False

    # ── stdout 백그라운드 drain ─────────────────────────────────────────
    # EMBA 는 모듈마다 많은 라인을 빠르게 토하는데, 우리가 ``readline()``
    # 으로 한 줄 받고 yield → caller 가 DB insert + SSE broadcast 처리하는
    # 동안 다음 readline 이 지연된다.  그 시간에 EMBA 의 stdout pipe 가 차
    # write() 가 block 되어 **EMBA 자체 분석 속도가 느려진다**.  terminal
    # 직접 실행은 TTY 가 사실상 무제한 buffer 라 같은 backpressure 가 없다.
    #
    # 백그라운드 task 로 pipe 를 즉시 비우고 큐에 push → generator 는 큐에서
    # 꺼내 처리.  pipe 가 항상 drain 되므로 EMBA write 가 block 안 된다.
    line_queue: asyncio.Queue = asyncio.Queue(maxsize=50000)

    async def _drain() -> None:
        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                await line_queue.put(raw)
        finally:
            await line_queue.put(None)  # EOF 신호

    drain_task = asyncio.create_task(_drain())

    try:
        while True:
            if loop.time() - start_ts > EMBA_TIMEOUT:
                timed_out = True
                break
            try:
                raw = await asyncio.wait_for(line_queue.get(), timeout=300.0)
            except asyncio.TimeoutError:
                yield _emit(current_stage, "binXray", "(heartbeat — still working)")
                continue
            if raw is None:  # EOF
                break
            line = _strip_ansi(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
            if not line.strip():
                continue

            m_p = _RE_P_MODULE.search(line)
            m_s = _RE_S_MODULE.search(line)
            if m_s and current_stage == "extracting":
                yield {"type": "stage_transition", "from": "extracting", "to": "sbom_generating"}
                current_stage = "sbom_generating"
            if m_s:
                last_module = m_s.group(0)
            elif m_p:
                last_module = m_p.group(0)

            prefix = f"binXray {last_module}" if last_module else "binXray"
            yield _emit(current_stage, prefix, line)

        if timed_out:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            yield {"type": "error", "message": f"binXray SBOM 단계 timeout {EMBA_TIMEOUT}s"}
            return

        await asyncio.wait_for(proc.wait(), timeout=30)
        if proc.returncode != 0:
            yield {"type": "error", "message": f"binXray SBOM 단계 exit {proc.returncode}"}
            return
        yield {"type": "emba_done"}

    finally:
        if not drain_task.done():
            drain_task.cancel()
            try:
                await drain_task
            except (asyncio.CancelledError, Exception):
                pass
        if proc.returncode is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass


# ── fix_cpe.py ─────────────────────────────────────────────────────────────


async def _run_fix_cpe(
    sbom_in: Path,
    sbom_out: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """fix_cpe.py 로 SBOM JSON repair + cpe 13-field 1차 정규화.

    ``json-repair`` 의존성이 있어서 시스템 python3 이 아니라 cpe_mapper venv 의
    python 으로 실행한다 (enrich_sbom 과 같은 환경).
    """
    yield _emit("sbom_generating", "fix_cpe",
                f"start: {sbom_in.name} → {sbom_out.name}")

    args = [CPE_MAPPER_PYTHON, FIX_CPE_BIN, str(sbom_in), str(sbom_out)]
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=_setup_subprocess,
        limit=4 * 1024 * 1024,
    )
    assert proc.stdout is not None
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if line.strip():
            yield _emit("sbom_generating", "fix_cpe", line)
    await proc.wait()
    if proc.returncode != 0:
        yield {"type": "error", "message": f"fix_cpe.py exited {proc.returncode}"}
        return
    if not sbom_out.exists():
        yield {"type": "error", "message": f"fix_cpe.py 가 {sbom_out} 를 만들지 못했습니다"}
        return
    yield {"type": "fix_cpe_done"}


# ── enrich_sbom.py ────────────────────────────────────────────────────────


async def _run_enrich_sbom(
    sbom_in: Path,
    sbom_out: Path,
    log_path: Path,
) -> AsyncGenerator[dict[str, Any], None]:
    """enrich_sbom.py 로 NVD CPE 후보 → Top-1 결정 + 3 properties 병기.

    cwd 를 cpe_mapper 디렉토리로 고정해야 ``data/nvd_cpe.sqlite`` 등 상대 경로
    DB 가 정상 해결된다.  --input / --output 은 절대경로로 넘김.
    """
    yield _emit("sbom_generating", "enrich",
                f"start: {sbom_in.name} → {sbom_out.name} "
                f"(backend={CPE_MAPPER_BACKEND})")

    args = [
        CPE_MAPPER_PYTHON,
        "enrich_sbom.py",
        "--input", str(sbom_in),
        "--output", str(sbom_out),
        "--backend", CPE_MAPPER_BACKEND,
        "--log", str(log_path),
    ]
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    timed_out = False
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=CPE_MAPPER_DIR,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=_setup_subprocess,
        limit=4 * 1024 * 1024,
    )
    assert proc.stdout is not None
    last_pct_emitted = -1
    last_pct_emit_ts = 0.0
    try:
        while True:
            if loop.time() - start_ts > CPE_MAPPER_TIMEOUT:
                timed_out = True
                break
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=120.0)
            except asyncio.TimeoutError:
                yield _emit("sbom_generating", "enrich", "(heartbeat)")
                continue
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line.strip():
                continue

            # tqdm progress 라인 — 한 줄 안에 여러 \r 갱신이 누적될 수 있으므로
            # finditer 로 마지막 매칭을 잡는다.  매칭되면 log 미발사, stage_percent
            # 이벤트로만 변환해 PipelineStepper 의 진행률 bar 를 갱신.
            tqdm_matches = list(_RE_TQDM_ENRICH.finditer(line))
            if tqdm_matches:
                m = tqdm_matches[-1]
                try:
                    pct = int(m.group(1))
                    n = int(m.group(2))
                    total = int(m.group(3))
                except ValueError:
                    continue
                now = loop.time()
                # 1% 변동 + 1초 minimum interval — 너무 잦지 않게.  100% 는 항상 emit.
                if (pct != last_pct_emitted and (now - last_pct_emit_ts >= 1.0)) or pct >= 100:
                    last_pct_emitted = pct
                    last_pct_emit_ts = now
                    yield {
                        "type": "stage_percent",
                        "stage": "sbom_generating",
                        "progress": pct,
                        "label": f"enrich {n}/{total} ({pct}%)",
                    }
                continue

            yield _emit("sbom_generating", "enrich", line)

        if timed_out:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            yield {"type": "error", "message": f"enrich_sbom.py timeout {CPE_MAPPER_TIMEOUT}s"}
            return

        await asyncio.wait_for(proc.wait(), timeout=15)
        if proc.returncode != 0:
            yield {"type": "error", "message": f"enrich_sbom.py exited {proc.returncode}"}
            return
        if not sbom_out.exists():
            yield {"type": "error", "message": f"enrich_sbom.py 가 {sbom_out} 를 만들지 못했습니다"}
            return
        yield {"type": "enrich_done"}
    finally:
        if proc.returncode is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass


# ── 메인 orchestrator ─────────────────────────────────────────────────────


async def run_emba_extract_sbom(
    firmware_path: Path,
    storage_dir: Path,
    job_id: str,
    product_info: Optional[dict[str, str]] = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """EMBA + fix_cpe + enrich_sbom 전체 파이프라인.

    Parameters
    ----------
    firmware_path : Path
        Ubuntu storage 측 firmware.bin 절대경로.
    storage_dir : Path
        ``storage/<job>/`` 절대경로 — sbom.{raw,fix,cdx}.json / cpe_mapper.log /
        emba_logs/ 의 최종 저장 위치.  EMBA 가 ``-l`` 로 직접 ``emba_logs/`` 를
        만든다 (Ubuntu native ext4 — 9P 경유 없음).
    job_id : str
        ULID — 로그 prefix.
    product_info : dict, optional
        ``{"name": "P5G_Dongle_891", "version": "3.1.2", "vendor": "..."}``.
        EMBA 의 ``-X/-Y/-Z`` 메타데이터에 매핑.

    Yields
    ------
    stage_progress / stage_transition / emba_pipeline_complete / error
    """
    storage_dir = Path(storage_dir)
    firmware_path = Path(firmware_path).resolve()
    info = product_info or {}

    storage_log_dir = storage_dir / "emba_logs"
    yield _emit("extracting", "binXray",
                f"target: storage/{storage_dir.name}/emba_logs (Ubuntu native ext4)")

    # 1) EMBA 실행 — firmware + log_dir 모두 Ubuntu native
    emba_ok = False
    async for ev in _run_emba(firmware_path, storage_log_dir, product_info=info):
        if ev.get("type") == "emba_done":
            emba_ok = True
            break
        if ev.get("type") == "error":
            yield ev
            return
        yield ev
    if not emba_ok:
        yield {"type": "error", "message": "binXray SBOM 단계 종료 시그널을 받지 못함"}
        return

    # 1.5) emba_logs 안의 root 소유 파일을 host user 소유로 변경.
    #      EMBA sub-process 일부가 unprivileged user 로 동작해 권한이 섞이는데,
    #      이대로 두면 fix_cpe / VEX 단계에서 ktdevice 가 일부 파일을 못 만지는
    #      경우가 생긴다.  docker 한 번 띄워 chown -R 적용.
    yield _emit("sbom_generating", "binXray",
                "권한 보정: docker chown -R <host_uid>:<host_gid> /logs")
    await _chown_emba_logs(storage_log_dir)

    # 2) EMBA 산출물 식별 — sbom + rootfs
    try:
        emba_sbom = _find_emba_sbom(storage_log_dir)
    except FileNotFoundError as exc:
        yield {"type": "error", "message": str(exc)}
        return
    rootfs = _find_emba_rootfs(storage_log_dir)
    if rootfs is None:
        yield _emit("sbom_generating", "binXray",
                    "warning: rootfs 후보를 찾지 못함 — VEX cwd 가 비어있을 수 있음")
    else:
        yield _emit("sbom_generating", "binXray", f"rootfs identified: {rootfs}")

    # 3) EMBA SBOM → storage/<job>/sbom.raw.json
    sbom_raw = storage_dir / "sbom.raw.json"
    try:
        shutil.copy2(emba_sbom, sbom_raw)
    except OSError as exc:
        yield {"type": "error", "message": f"binXray SBOM 복사 실패: {exc}"}
        return
    yield _emit("sbom_generating", "binXray",
                f"sbom 복사 완료: {emba_sbom.name} → sbom.raw.json")

    # 4) SBOM 후처리 — fix_cpe + enrich_sbom + 통계 (별도 함수로 분리해
    #    Resume-from-SBOM 시 단독 호출 가능하게 한다).
    async for ev in run_sbom_post_processing(
        sbom_raw, storage_dir, rootfs_path=rootfs,
        emba_log_dir=storage_log_dir,
    ):
        yield ev


async def run_sbom_post_processing(
    sbom_raw: Path,
    storage_dir: Path,
    rootfs_path: Optional[Path] = None,
    emba_log_dir: Optional[Path] = None,
    bridge_dir: Optional[Path] = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """``sbom.raw.json`` 부터 fix_cpe + enrich_sbom 을 돌려 sbom.cdx.json 을 만든다.

    EMBA 추출/SBOM 생성이 무거운(20-60분) 단계라, 그 산출물이 이미 있는 경우
    후처리만 단독 재실행할 수 있도록 분리한 helper.  Resume-from-SBOM 흐름에서
    runner 가 직접 호출.

    Yields
    ------
    stage_progress / emba_pipeline_complete / error
    """
    storage_dir = Path(storage_dir)
    sbom_raw = Path(sbom_raw)
    if not sbom_raw.exists():
        yield {"type": "error", "message": f"sbom.raw.json 미존재: {sbom_raw}"}
        return

    # fix_cpe
    sbom_fix = storage_dir / "sbom.fix.json"
    async for ev in _run_fix_cpe(sbom_raw, sbom_fix):
        if ev.get("type") == "error":
            yield ev
            return
        if ev.get("type") == "fix_cpe_done":
            break
        yield ev

    # enrich_sbom
    sbom_cdx = storage_dir / "sbom.cdx.json"
    cpe_log = storage_dir / "cpe_mapper.log"
    async for ev in _run_enrich_sbom(sbom_fix, sbom_cdx, cpe_log):
        if ev.get("type") == "error":
            yield ev
            return
        if ev.get("type") == "enrich_done":
            break
        yield ev

    # 통계 — components + cpe status 분포
    component_count = 0
    cpe_status_counts: dict[str, int] = {}
    try:
        doc = json.loads(sbom_cdx.read_text(encoding="utf-8"))
        components = doc.get("components") or []
        component_count = len(components)
        for c in components:
            for prop in (c.get("properties") or []):
                if isinstance(prop, dict) and prop.get("name") == "EMBA:cpe_upstream:status":
                    v = prop.get("value", "unknown")
                    cpe_status_counts[v] = cpe_status_counts.get(v, 0) + 1
                    break
    except Exception as exc:
        logger.warning("[binXray] sbom.cdx.json 통계 추출 실패: %s", exc)

    yield _emit("sbom_generating", "enrich",
                f"summary: {component_count} components | "
                f"cpe status distribution: {cpe_status_counts}")

    yield {
        "type": "emba_pipeline_complete",
        "sbom_path": str(sbom_cdx),
        "sbom_raw_path": str(sbom_raw),
        "sbom_fix_path": str(sbom_fix),
        "rootfs_path": str(rootfs_path) if rootfs_path else None,
        "emba_log_dir": str(emba_log_dir) if emba_log_dir else None,
        "bridge_dir": str(bridge_dir) if bridge_dir else None,
        "component_count": component_count,
        "cpe_status_counts": cpe_status_counts,
    }
