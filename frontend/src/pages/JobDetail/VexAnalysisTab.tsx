import { Bot } from 'lucide-react'
import { SeverityBadge, VexBadge } from '../../components/Badge'
import type { CveResult } from '../../types'

interface VexAnalysisTabProps {
  cves: CveResult[]
}

const VEX_ORDER = ['affected', 'under_investigation', 'not_affected', 'fixed']

function vexOrder(status: string | null) {
  const idx = VEX_ORDER.indexOf(status ?? '')
  return idx === -1 ? VEX_ORDER.length : idx
}

export function VexAnalysisTab({ cves }: VexAnalysisTabProps) {
  const withVex = cves
    .filter((c) => c.vex_status)
    .sort((a, b) => vexOrder(a.vex_status) - vexOrder(b.vex_status))

  const noVex = cves.filter((c) => !c.vex_status)

  if (cves.length === 0) {
    return (
      <div className="text-center py-16 text-gray-600 font-mono text-sm">
        No vulnerability data available.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex items-center gap-2 text-sm text-gray-400">
        <Bot size={15} className="text-accent-amber" />
        <span className="font-mono">
          {withVex.length} VEX statements generated · {noVex.length} without analysis
        </span>
      </div>

      {/* VEX cards */}
      {withVex.map((cve) => (
        <div
          key={cve.cve_id}
          className="border border-surface-700 rounded-xl overflow-hidden"
        >
          {/* Card header */}
          <div className="flex items-center gap-3 px-5 py-3 bg-surface-800/60 border-b border-surface-700">
            <SeverityBadge severity={cve.severity} />
            <span className="font-mono text-sm text-accent-cyan font-semibold">{cve.cve_id}</span>
            <span className="text-gray-500 text-sm font-mono">{cve.package_name} {cve.package_version}</span>
            <div className="ml-auto">
              <VexBadge status={cve.vex_status} />
            </div>
          </div>

          {/* Card body */}
          <div className="px-5 py-4 space-y-3">
            {cve.description && (
              <p className="text-sm text-gray-400">{cve.description}</p>
            )}

            {cve.vex_justification && (
              <div className="bg-surface-900 rounded-lg px-4 py-3 border border-surface-600">
                <p className="text-xs font-mono text-gray-500 mb-1 tracking-wider">JUSTIFICATION</p>
                <p className="text-sm text-gray-300 font-mono">{cve.vex_justification}</p>
              </div>
            )}

            {cve.vex_detail && (
              <div className="bg-surface-950 rounded-lg px-4 py-3 border border-surface-700">
                <p className="text-xs font-mono text-gray-500 mb-1 tracking-wider">ANALYSIS DETAIL</p>
                <p className="text-sm text-gray-400 leading-relaxed whitespace-pre-wrap">{cve.vex_detail}</p>
              </div>
            )}

            {cve.fixed_version && (
              <p className="text-xs font-mono text-gray-500">
                Fixed in: <span className="text-accent-green">{cve.fixed_version}</span>
              </p>
            )}
          </div>
        </div>
      ))}

      {/* No VEX section */}
      {noVex.length > 0 && (
        <div className="border border-surface-700 rounded-xl overflow-hidden">
          <div className="px-5 py-3 bg-surface-800/40 border-b border-surface-700">
            <p className="text-xs font-mono text-gray-500 tracking-wider">
              NOT ANALYZED BY VEX AI ({noVex.length})
            </p>
          </div>
          <ul className="divide-y divide-surface-800">
            {noVex.map((cve) => (
              <li key={cve.cve_id} className="flex items-center gap-3 px-5 py-2.5">
                <SeverityBadge severity={cve.severity} />
                <span className="font-mono text-sm text-gray-400">{cve.cve_id}</span>
                <span className="text-xs text-gray-600 font-mono">{cve.package_name}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
