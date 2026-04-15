from .extractor import ExtractResult, extract_firmware
from .sbom import SbomResult, generate_sbom
from .scanner import ScanResult, Vulnerability, scan_sbom
from .vex import (
    CommandResult,
    VexResult,
    VexStatement,
    analyze_cve_batch,
    call_gemini,
    execute_command_in_rootfs,
    extract_commands_from_response,
    run_vex_analysis_loop,
)

__all__ = [
    # extractor
    "ExtractResult",
    "extract_firmware",
    # sbom
    "SbomResult",
    "generate_sbom",
    # scanner
    "ScanResult",
    "Vulnerability",
    "scan_sbom",
    # vex
    "CommandResult",
    "VexResult",
    "VexStatement",
    "analyze_cve_batch",
    "call_gemini",
    "execute_command_in_rootfs",
    "extract_commands_from_response",
    "run_vex_analysis_loop",
]
