import { useMemo, useState } from 'react'
import { ShieldAlert, Search, ChevronDown, ChevronUp } from 'lucide-react'
import { SeverityBadge, VexBadge } from '../../components/Badge'
import type { CveResult } from '../../types'

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']

type SortKey = 'severity' | 'cvss' | 'epss' | 'risk'

interface VulnerabilitiesTabProps {
  cves: CveResult[]
}

function fmtNum(n: number | null | undefined, digits = 1): string {
  if (n == null || Number.isNaN(n)) return '—'
  return n.toFixed(digits)
}

function fmtPct(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '—'
  return `${(n * 100).toFixed(1)}%`
}

// CVSS 0-10 color scale.  Uses the same band boundaries as NVD.
function cvssClass(score: number | null): string {
  if (score == null) return 'text-gray-600'
  if (score >= 9.0) return 'text-red-300'
  if (score >= 7.0) return 'text-orange-300'
  if (score >= 4.0) return 'text-amber-300'
  return 'text-blue-300'
}

// EPSS uses percentile cutoffs — ≥99th percentile is "actively exploited
// in the wild" territory, <50th is essentially noise.
function epssClass(pct: number | null): string {
  if (pct == null) return 'text-gray-600'
  if (pct >= 0.99) return 'text-red-300'
  if (pct >= 0.90) return 'text-orange-300'
  if (pct >= 0.50) return 'text-amber-300'
  return 'text-gray-500'
}

function CveRow({ cve }: { cve: CveResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <tr
        className="hover:bg-surface-800/40 transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-3">
          <SeverityBadge severity={cve.severity} />
        </td>
        <td className="px-3 py-3 font-mono text-sm text-accent-cyan">{cve.cve_id}</td>
        <td className="px-3 py-3 font-mono text-sm text-gray-300">{cve.package_name}</td>
        <td className="px-3 py-3 font-mono text-xs text-gray-500">{cve.package_version}</td>
        <td className={`px-3 py-3 font-mono text-xs ${cvssClass(cve.cvss_base_score)}`}>
          {fmtNum(cve.cvss_base_score)}
        </td>
        <td
          className={`px-3 py-3 font-mono text-xs ${epssClass(cve.epss_percentile)}`}
          title={
            cve.epss_score != null
              ? `EPSS: ${fmtPct(cve.epss_score)} (percentile ${fmtPct(cve.epss_percentile)})`
              : undefined
          }
        >
          {cve.epss_score != null ? fmtPct(cve.epss_score) : '—'}
        </td>
        <td className="px-3 py-3 font-mono text-xs text-gray-400">
          {fmtNum(cve.risk_score, 1)}
        </td>
        <td className="px-3 py-3">
          <VexBadge status={cve.vex_status} />
        </td>
        <td className="px-3 py-3 text-gray-600">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-surface-900/60">
          <td colSpan={9} className="px-6 pb-4 pt-2">
            <div className="space-y-3 text-sm text-gray-400">
              {cve.description && <p>{cve.description}</p>}

              {/* Metric grid — pulls out CVSS vector, EPSS detail, CWE list,
                  and fix version so they aren't buried in the body text. */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-2 text-xs font-mono">
                {cve.cvss_vector && (
                  <div>
                    <div className="text-gray-600">CVSS VECTOR</div>
                    <div className="text-gray-300 break-all">{cve.cvss_vector}</div>
                  </div>
                )}
                {cve.epss_score != null && (
                  <div>
                    <div className="text-gray-600">EPSS</div>
                    <div className={epssClass(cve.epss_percentile)}>
                      {fmtPct(cve.epss_score)}
                      <span className="text-gray-600">
                        {' '}
                        (p{fmtPct(cve.epss_percentile)})
                      </span>
                    </div>
                  </div>
                )}
                {cve.risk_score != null && (
                  <div>
                    <div className="text-gray-600">RISK (grype)</div>
                    <div className="text-gray-300">{fmtNum(cve.risk_score, 2)}</div>
                  </div>
                )}
                {cve.cwes.length > 0 && (
                  <div>
                    <div className="text-gray-600">CWE</div>
                    <div className="text-gray-300">{cve.cwes.join(', ')}</div>
                  </div>
                )}
                {cve.fix_version && (
                  <div>
                    <div className="text-gray-600">FIXED IN</div>
                    <div className="text-accent-green">{cve.fix_version}</div>
                  </div>
                )}
              </div>

              {cve.vex_justification && (
                <p className="font-mono text-xs">
                  Justification: <span className="text-gray-300">{cve.vex_justification}</span>
                </p>
              )}
              {cve.vex_detail && (
                <p className="text-xs text-gray-500 italic whitespace-pre-wrap">{cve.vex_detail}</p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function VulnerabilitiesTab({ cves }: VulnerabilitiesTabProps) {
  const [filter, setFilter] = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('severity')

  const counts: Record<string, number> = {}
  for (const c of cves) counts[c.severity] = (counts[c.severity] ?? 0) + 1

  const filtered = useMemo(() => {
    const list = cves.filter((c) => {
      if (sevFilter && c.severity !== sevFilter) return false
      if (filter) {
        const q = filter.toLowerCase()
        return (
          c.cve_id.toLowerCase().includes(q) ||
          c.package_name.toLowerCase().includes(q) ||
          c.cwes.some((w) => w.toLowerCase().includes(q))
        )
      }
      return true
    })
    return list.sort((a, b) => {
      if (sortKey === 'cvss') {
        return (b.cvss_base_score ?? -1) - (a.cvss_base_score ?? -1)
      }
      if (sortKey === 'epss') {
        return (b.epss_score ?? -1) - (a.epss_score ?? -1)
      }
      if (sortKey === 'risk') {
        return (b.risk_score ?? -1) - (a.risk_score ?? -1)
      }
      // Severity primary, then CVSS to break ties.
      const sevDiff = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
      if (sevDiff !== 0) return sevDiff
      return (b.cvss_base_score ?? -1) - (a.cvss_base_score ?? -1)
    })
  }, [cves, filter, sevFilter, sortKey])

  return (
    <div className="space-y-4">
      {/* Severity filter pills + sort */}
      <div className="flex items-center gap-2 flex-wrap">
        <ShieldAlert size={15} className="text-accent-purple" />
        <button
          onClick={() => setSevFilter(null)}
          className={`px-3 py-1 rounded-full text-xs font-mono transition-colors ${
            !sevFilter
              ? 'bg-surface-600 text-gray-200'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          ALL ({cves.length})
        </button>
        {SEV_ORDER.filter((s) => counts[s]).map((sev) => (
          <button
            key={sev}
            onClick={() => setSevFilter(sevFilter === sev ? null : sev)}
            className={`px-3 py-1 rounded-full text-xs font-mono transition-colors ${
              sevFilter === sev
                ? 'bg-surface-600 text-gray-200'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {sev} ({counts[sev]})
          </button>
        ))}

        <div className="ml-auto flex items-center gap-2">
          <select
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            className="bg-surface-800 border border-surface-600 rounded-lg px-2 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-accent-cyan"
          >
            <option value="severity">Sort: Severity</option>
            <option value="cvss">Sort: CVSS</option>
            <option value="epss">Sort: EPSS</option>
            <option value="risk">Sort: Risk</option>
          </select>
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search CVE / package / CWE..."
              className="bg-surface-800 border border-surface-600 rounded-lg pl-8 pr-3 py-1.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-accent-cyan w-56"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="border border-surface-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-700 bg-surface-800/50">
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider">SEV</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider">CVE</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider">PACKAGE</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VERSION</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider" title="CVSS v3 base score (0–10)">CVSS</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider" title="Exploit Prediction Scoring System — probability of exploit in next 30d">EPSS</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider" title="grype-composed risk score (CVSS × EPSS)">RISK</th>
              <th className="text-left px-3 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VEX</th>
              <th className="px-3 py-2.5" />
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-800">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-8 text-gray-600 font-mono text-sm">
                  No vulnerabilities found
                </td>
              </tr>
            ) : (
              filtered.map((cve) => <CveRow key={cve.cve_id} cve={cve} />)
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
