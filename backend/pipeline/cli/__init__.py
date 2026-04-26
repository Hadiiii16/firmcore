"""VEX 분석용 CLI 어댑터 모음.

FirmCore 는 Gemini CLI 와 OpenAI Codex CLI 를 **동일한 async-generator 인터페이스**
로 래핑해 ``run_vex_analysis_loop`` 가 attempt chain(Pro → Codex → Flash) 으로
폴백할 수 있게 한다. 각 어댑터의 구현은 ``gemini`` 용은 레거시 호환을 위해
``pipeline.vex`` 안에 그대로 남아 있고, ``codex`` 는 이 패키지의 ``codex.py``
에 신규 구현되어 있다.

외부에서 쓸 때는 다음만 import 하면 된다::

    from pipeline.cli import (
        AttemptSpec,
        RateLimitError,
        resolve_engine_for_model,
        build_default_attempt_chain,
    )
"""

from .base import (
    AttemptSpec,
    RateLimitError,
    resolve_engine_for_model,
    build_default_attempt_chain,
    DEFAULT_AUTO_CHAIN,
    GEMINI_PRO_MODEL,
    GEMINI_FLASH_MODEL,
    CODEX_DEFAULT_MODEL,
)

__all__ = [
    "AttemptSpec",
    "RateLimitError",
    "resolve_engine_for_model",
    "build_default_attempt_chain",
    "DEFAULT_AUTO_CHAIN",
    "GEMINI_PRO_MODEL",
    "GEMINI_FLASH_MODEL",
    "CODEX_DEFAULT_MODEL",
]
