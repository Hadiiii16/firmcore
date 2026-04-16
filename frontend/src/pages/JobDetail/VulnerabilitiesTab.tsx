import { useState } from 'react'
import { ShieldAlert, Search, ChevronDown, ChevronUp } from 'lucide-react'
import { SeverityBadge, VexBadge } from '../../components/Badge'
import type { CveResult } from '../../types'

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']

interface VulnerabilitiesTabProps {
  cves: CveResult[]
}

function CveRow({ cve }: { cve: CveResult }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <>
      <tr
        className="hover:bg-surface-800/40 transition-colors cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3">
          <SeverityBadge severity={cve.severity} />
        </td>
        <td className="px-4 py-3 font-mono text-sm text-accent-cyan">{cve.cve_id}</td>
        <td className="px-4 py-3 font-mono text-sm text-gray-300">{cve.package_name}</td>
        <td className="px-4 py-3 font-mono text-xs text-gray-500">{cve.package_version}</td>
        <td className="px-4 py-3">
          <VexBadge status={cve.vex_status} />
        </td>
        <td className="px-4 py-3 text-gray-600">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-surface-900/60">
          <td colSpan={6} className="px-6 pb-4 pt-2">
            <div className="space-y-2 text-sm text-gray-400">
              {cve.description && (
                <p>{cve.description}</p>
              )}
              {cve.fix_version && (
                <p className="font-mono text-xs">
                  Fixed in: <span className="text-accent-green">{cve.fix_version}</span>
                </p>
              )}
              {cve.vex_justification && (
                <p className="font-mono text-xs">
                  Justification: <span className="text-gray-300">{cve.vex_justification}</span>
                </p>
              )}
              {cve.vex_detail && (
                <p className="text-xs text-gray-500 italic">{cve.vex_detail}</p>
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

  const counts: Record<string, number> = {}
  for (const c of cves) counts[c.severity] = (counts[c.severity] ?? 0) + 1

  const filtered = cves
    .filter((c) => {
      if (sevFilter && c.severity !== sevFilter) return false
      if (filter) {
        const q = filter.toLowerCase()
        return (
          c.cve_id.toLowerCase().includes(q) ||
          c.package_name.toLowerCase().includes(q)
        )
      }
      return true
    })
    .sort(
      (a, b) =>
        SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
    )

  return (
    <div className="space-y-4">
      {/* Severity filter pills */}
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

        <div className="ml-auto relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search CVE / package..."
            className="bg-surface-800 border border-surface-600 rounded-lg pl-8 pr-3 py-1.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-accent-cyan w-52"
          />
        </div>
      </div>

      {/* Table */}
      <div className="border border-surface-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-700 bg-surface-800/50">
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">SEV</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">CVE</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">PACKAGE</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VERSION</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VEX</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-800">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-8 text-gray-600 font-mono text-sm">
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
