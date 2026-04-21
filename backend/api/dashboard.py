"""
api/dashboard.py — fleet-wide aggregation for the security-manager dashboard.

The main per-job UI already exposes scan / SBOM / VEX data via ``/api/jobs``.
This endpoint walks the *completed* jobs' storage directories once, merges
their ``scan.json`` + ``combined_vex.json`` contents, and returns rolled-up
numbers plus Top-N exposure tables so the dashboard can answer:

    "Across every firmware I've analyzed, which packages and CVEs do I
    actually need to act on first?"

The loaders ``_load_scan_results`` / ``_load_vex`` in ``api/jobs.py`` already
dedup within a single job; here we dedup across jobs as well.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

from fastapi import APIRouter

from db import db_list_jobs, get_db
from models import (
    DashboardSummary,
    FirmwareRef,
    TopCve,
    TopPackage,
)
from api.jobs import _load_scan_results, _load_vex  # reuse dedup parsers

logger = logging.getLogger(__name__)

router = APIRouter()

# Severity ordering is shared with the other layers — kept literal here to
# avoid a circular import with api.jobs.
_SEVERITY_RANK = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0,
    "NEGLIGIBLE": 0, "": 0,
}
_ACTIVE_STATUSES = {
    "extracting", "sbom_generating", "scanning", "vex_analyzing",
}
_TOP_N = 10


def _severity_label(rank: int) -> str:
    for label, r in _SEVERITY_RANK.items():
        if r == rank and label not in {"UNKNOWN", "NEGLIGIBLE", ""}:
            return label
    return "UNKNOWN"


@router.get("/summary", response_model=DashboardSummary)
async def dashboard_summary() -> DashboardSummary:
    async with get_db() as db:
        rows, total_jobs = await db_list_jobs(db, limit=1000, offset=0)

    active_jobs = sum(1 for r in rows if r.get("status") in _ACTIVE_STATUSES)
    completed_jobs = sum(1 for r in rows if r.get("status") == "completed")
    failed_jobs = sum(1 for r in rows if r.get("status") == "failed")

    # Job metadata lookup for FirmwareRef drill-down.
    job_meta: dict[str, dict[str, str]] = {
        r["id"]: {
            "filename": r.get("filename", ""),
            "product_name": r.get("product_name", "") or "",
            "product_version": r.get("product_version", "") or "",
        }
        for r in rows
    }

    # (name, version) → set of firmware (job_id) occurrences
    pkg_firmwares: dict[tuple[str, str], set[str]] = defaultdict(set)
    # (name, version) → set of CVE ids affecting this package
    pkg_cves: dict[tuple[str, str], set[str]] = defaultdict(set)
    # (name, version) → running max severity rank
    pkg_max_sev_rank: dict[tuple[str, str], int] = defaultdict(lambda: -1)
    # (name, version) → affected CVE count
    pkg_affected: dict[tuple[str, str], int] = defaultdict(int)
    # (name, version) → {job_id: #unique CVEs for this pkg in that firmware}
    pkg_fw_cves: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set),
    )

    # CVE id → {severity, package_name, firmware_count, affected_fw_count,
    #           max_cvss, max_epss, max_risk}
    cve_severity: dict[str, str] = {}
    cve_pkgs: dict[str, str] = {}
    cve_firmwares: dict[str, set[str]] = defaultdict(set)
    cve_affected_fw: dict[str, set[str]] = defaultdict(set)
    cve_max_cvss: dict[str, float] = {}
    cve_max_epss: dict[str, float] = {}
    cve_max_risk: dict[str, float] = {}
    # CVE id → {job_id: vex_status}  (per-firmware drill-down)
    cve_fw_status: dict[str, dict[str, str]] = defaultdict(dict)

    # Severity rollup (unique CVE × firmware)
    sev_rollup: dict[str, int] = defaultdict(int)
    # VEX rollup (unique CVE × firmware, summed as the per-firmware view sees it)
    affected_count = 0
    not_affected_count = 0
    under_investigation_count = 0
    unanalyzed_count = 0
    affected_with_fix_count = 0

    for r in rows:
        # scan.json 만 있으면 집계 가능하다.  status 가 ``completed`` 가
        # 아니어도 (vex_analyzing 진행 중 / failed 로 중단되었어도)
        # 이미 완료된 부분 분석 결과는 vex_map 에 반영되어 있으므로 대시
        # 보드에 노출해 준다.  ``pending`` / ``extracting`` / ``sbom_*`` /
        # ``scanning`` 상태는 아직 scan.json 이 없어 제외.
        status = r.get("status")
        if status in ("pending", "extracting", "sbom_generating", "scanning"):
            continue
        job_id = r["id"]
        storage_dir = Path(r["storage_dir"]) if r.get("storage_dir") else None
        if not storage_dir:
            continue
        if not (storage_dir / "scan.json").exists():
            continue

        scan = _load_scan_results(storage_dir, r.get("scan_result_path"))
        _, vex_map = _load_vex(storage_dir, r.get("combined_vex_path"))

        for v in scan:
            pkg_key = (v.get("package_name", ""), v.get("package_version", ""))
            cve_id = v.get("cve_id", "")
            if not cve_id:
                continue
            sev = (v.get("severity") or "UNKNOWN").upper()
            rank = _SEVERITY_RANK.get(sev, 0)

            # Per-package fleet aggregates
            pkg_firmwares[pkg_key].add(job_id)
            pkg_cves[pkg_key].add(cve_id)
            pkg_fw_cves[pkg_key][job_id].add(cve_id)
            if rank > pkg_max_sev_rank[pkg_key]:
                pkg_max_sev_rank[pkg_key] = rank

            # Per-CVE fleet aggregates
            cve_firmwares[cve_id].add(job_id)
            # Severity is intrinsic to the CVE, but we may see inconsistent
            # labels across vendors.  Keep the first seen, don't overwrite.
            cve_severity.setdefault(cve_id, sev)
            cve_pkgs.setdefault(cve_id, pkg_key[0])
            if v.get("cvss_base_score") is not None:
                cve_max_cvss[cve_id] = max(
                    cve_max_cvss.get(cve_id, -1.0), float(v["cvss_base_score"]),
                )
            if v.get("epss_score") is not None:
                cve_max_epss[cve_id] = max(
                    cve_max_epss.get(cve_id, -1.0), float(v["epss_score"]),
                )
            if v.get("risk_score") is not None:
                cve_max_risk[cve_id] = max(
                    cve_max_risk.get(cve_id, -1.0), float(v["risk_score"]),
                )

            # Severity rollup across (CVE, firmware) pairs (not unique CVE,
            # so three firmwares affected by the same critical = 3).
            sev_rollup[sev] += 1

            # VEX rollup
            vex = vex_map.get(cve_id) or {}
            status = (vex.get("status") or "unanalyzed").lower()
            cve_fw_status[cve_id][job_id] = status
            if status == "affected":
                affected_count += 1
                cve_affected_fw[cve_id].add(job_id)
                pkg_affected[pkg_key] += 1
                if v.get("fix_version"):
                    affected_with_fix_count += 1
            elif status == "not_affected":
                not_affected_count += 1
            elif status == "under_investigation":
                under_investigation_count += 1
            else:
                unanalyzed_count += 1

    def _pkg_firmware_refs(pkg_key: tuple[str, str]) -> list[FirmwareRef]:
        """drill-down list for a package — each firmware that carries it,
        with the number of CVEs found against that package in that image."""
        fw_cves = pkg_fw_cves[pkg_key]
        refs: list[FirmwareRef] = []
        for jid, cves in fw_cves.items():
            meta = job_meta.get(jid, {})
            refs.append(FirmwareRef(
                job_id=jid,
                filename=meta.get("filename", jid),
                product_name=meta.get("product_name", ""),
                product_version=meta.get("product_version", ""),
                cve_count=len(cves),
            ))
        # Most-affected firmware first.
        refs.sort(key=lambda f: (f.cve_count, f.filename), reverse=True)
        return refs

    def _cve_firmware_refs(cid: str) -> list[FirmwareRef]:
        """drill-down list for a CVE — each firmware where it was detected,
        with the per-firmware VEX verdict."""
        status_order = {
            "affected": 0, "under_investigation": 1, "unanalyzed": 2, "not_affected": 3,
        }
        refs: list[FirmwareRef] = []
        for jid, status in cve_fw_status.get(cid, {}).items():
            meta = job_meta.get(jid, {})
            refs.append(FirmwareRef(
                job_id=jid,
                filename=meta.get("filename", jid),
                product_name=meta.get("product_name", ""),
                product_version=meta.get("product_version", ""),
                vex_status=status,
            ))
        refs.sort(key=lambda f: (status_order.get(f.vex_status or "", 9), f.filename))
        return refs

    # ── Top packages: rank by (affected desc, cve_count desc, fw count desc)
    top_packages: list[TopPackage] = sorted(
        (
            TopPackage(
                package_name=name,
                package_version=version,
                firmware_count=len(pkg_firmwares[(name, version)]),
                cve_count=len(pkg_cves[(name, version)]),
                affected_count=pkg_affected[(name, version)],
                max_severity=_severity_label(pkg_max_sev_rank[(name, version)]),
                firmwares=_pkg_firmware_refs((name, version)),
            )
            for (name, version) in pkg_cves
        ),
        key=lambda p: (
            p.affected_count,
            p.cve_count,
            p.firmware_count,
            _SEVERITY_RANK.get(p.max_severity or "", 0),
        ),
        reverse=True,
    )[:_TOP_N]

    # ── Top CVEs: rank by (severity desc, affected_fw desc, fw_count desc,
    # risk desc)
    top_cves: list[TopCve] = sorted(
        (
            TopCve(
                cve_id=cid,
                severity=cve_severity.get(cid, "UNKNOWN"),
                firmware_count=len(cve_firmwares[cid]),
                affected_firmware_count=len(cve_affected_fw.get(cid, set())),
                package_name=cve_pkgs.get(cid, ""),
                max_cvss=cve_max_cvss.get(cid),
                max_epss=cve_max_epss.get(cid),
                max_risk=cve_max_risk.get(cid),
                firmwares=_cve_firmware_refs(cid),
            )
            for cid in cve_firmwares
        ),
        key=lambda c: (
            _SEVERITY_RANK.get(c.severity, 0),
            c.affected_firmware_count,
            c.firmware_count,
            c.max_risk or -1.0,
        ),
        reverse=True,
    )[:_TOP_N]

    return DashboardSummary(
        total_firmwares=completed_jobs,
        unique_components=len(pkg_firmwares),
        unique_cves=len(cve_firmwares),
        critical_cves=sev_rollup.get("CRITICAL", 0),
        high_cves=sev_rollup.get("HIGH", 0),
        medium_cves=sev_rollup.get("MEDIUM", 0),
        low_cves=sev_rollup.get("LOW", 0),
        affected_count=affected_count,
        not_affected_count=not_affected_count,
        under_investigation_count=under_investigation_count,
        unanalyzed_count=unanalyzed_count,
        pending_vex=under_investigation_count + unanalyzed_count,
        affected_with_fix=affected_with_fix_count,
        total_jobs=total_jobs,
        active_jobs=active_jobs,
        completed_jobs=completed_jobs,
        failed_jobs=failed_jobs,
        top_packages=top_packages,
        top_cves=top_cves,
    )
