"""VEX 분석 CLI 어댑터 공용 정의.

두 엔진(Gemini / Codex) 모두 같은 async-generator 시그니처로 한 CVE 를 분석하고,
쿼터 소진 시 ``RateLimitError`` 를 raise 해서 상위 ``run_vex_analysis_loop`` 가
다음 attempt 로 폴백하도록 만든다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal, Optional


# ── 기본 모델 상수 ──────────────────────────────────────────────────────────

# Gemini 측은 기존 환경변수 이름을 유지 (.env 의 GEMINI_MODEL 이 primary).
# Codex 측은 별도 env var 로 override 가능.
GEMINI_PRO_MODEL = "gemini-3-pro-preview"
GEMINI_FLASH_MODEL = "gemini-3-flash-preview"
# Codex 기본 모델은 ``codex-default`` sentinel — ``-m`` 플래그를 생략해서
# Codex CLI 가 계정 권한에 맞는 모델을 자동 선택하게 한다.  ChatGPT OAuth
# 계정(사용자의 ``~/.codex/auth.json``) 은 ``-m gpt-5-codex`` 같은 명시
# 모델명을 거부하므로 이 sentinel 을 기본으로 둔다.  API key 를 직접 쓰는
# 경우에는 ``CODEX_MODEL=gpt-5-codex`` 로 .env 에서 override 하면 된다.
CODEX_DEFAULT_MODEL = os.environ.get("CODEX_MODEL", "codex-default").strip() or "codex-default"


EngineName = Literal["gemini", "codex"]


@dataclass(frozen=True)
class AttemptSpec:
    """한 번의 VEX 분석 시도에 쓸 엔진/모델 조합.

    ``run_vex_analysis_loop`` 는 ``list[AttemptSpec]`` 을 순서대로 시도하고,
    각 attempt 가 ``RateLimitError`` 로 끝나면 다음 spec 으로 폴백한다.
    """

    engine: EngineName
    model: str


class RateLimitError(RuntimeError):
    """쿼터 소진으로 어댑터가 중단됐음을 상위에 알리는 예외.

    ``run_vex_analysis_loop`` 는 이 예외를 잡아 폴백 체인의 다음 attempt 로
    넘어가거나, 더 이상 폴백이 없으면 ``rate_limited`` 이벤트를 yield 한다.

    Gemini 쪽 기존 코드는 문자열 안에 ``[RATE_LIMIT]`` 마커를 넣는 방식으로
    rate-limit 을 구분한다 — 호환을 위해 이 예외의 ``str()`` 에도 마커를
    자동 포함시킨다. 상위 루프는 예외 타입 또는 마커 중 어느 쪽으로도 감지
    가능하다.
    """

    def __init__(
        self,
        engine: EngineName,
        model: str,
        message: str,
        retry_after: Optional[int] = None,
    ) -> None:
        self.engine = engine
        self.model = model
        self.retry_after = retry_after
        # Gemini 경로(stream_gemini_yolo) 는 예외 문자열의 ``[RATE_LIMIT]``
        # substring 으로 rate-limit 을 분기하는 레거시 코드가 있어서,
        # Codex rate-limit 도 동일 마커를 붙여 교차 호환시킨다.
        marker = "[RATE_LIMIT]"
        formatted = message if marker in message else f"{marker} {message}"
        super().__init__(formatted)


# ── Engine 판별 ─────────────────────────────────────────────────────────────


def resolve_engine_for_model(model: str) -> EngineName:
    """모델 이름 prefix 로 어떤 CLI 엔진을 쓸지 결정.

    Gemini: ``gemini-*`` / ``gemini``
    Codex : ``gpt-*`` / ``o3*`` / ``codex-*`` / ``chatgpt-*``

    판별 불가 시 ``ValueError``. OSS provider(llama-* 등) 를 쓰게 되면 이
    매핑을 확장해야 한다.
    """
    m = (model or "").strip().lower()
    if not m or m in {"auto", "default"}:
        # Gemini CLI 가 기본 자동 라우팅(Pro default) 이라 auto 는 gemini 로.
        return "gemini"
    if m.startswith("gemini"):
        return "gemini"
    if m.startswith("gpt-") or m.startswith("o3") or m.startswith("codex-") or m.startswith("chatgpt-"):
        return "codex"
    raise ValueError(f"Cannot infer engine from model name: {model!r}")


# ── Auto 체인 구성 ──────────────────────────────────────────────────────────
# 사용자가 특정 모델 override 를 주지 않고 GEMINI_MODEL=gemini-3-pro-preview
# (.env 기본값) 로 돌리면 다음 3단계 폴백 체인이 적용된다.
#
#   1) Gemini Pro  — 기본. 품질/속도 모두 최적.
#   2) Codex       — Pro 쿼터 소진 시 OpenAI Codex Pro 쿼터로 이어 분석.
#   3) Gemini Flash — Codex 마저 소진 시 Gemini Flash 로 배치 완료.
#
# 한 attempt 가 rate-limit 이 아닌 일반 실패로 끝나면 더 이상 폴백하지 않고
# 즉시 상위로 에러를 올린다 (폴백은 쿼터 사유 한정).

DEFAULT_AUTO_CHAIN: tuple[AttemptSpec, ...] = (
    AttemptSpec("gemini", GEMINI_PRO_MODEL),
    AttemptSpec("codex",  CODEX_DEFAULT_MODEL),
    AttemptSpec("gemini", GEMINI_FLASH_MODEL),
)


def build_default_attempt_chain() -> list[AttemptSpec]:
    return list(DEFAULT_AUTO_CHAIN)
