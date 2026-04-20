import { useMemo, useState } from 'react'
import { Search, Package, ShieldAlert } from 'lucide-react'
import type { SbomComponent } from '../../types'

interface SbomTabProps {
  components: SbomComponent[]
}

type SortKey = 'severity' | 'cve' | 'name'

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-950/60 text-red-300 border-red-900',
  HIGH: 'bg-orange-950/60 text-orange-300 border-orange-900',
  MEDIUM: 'bg-amber-950/60 text-amber-300 border-amber-900',
  LOW: 'bg-blue-950/60 text-blue-300 border-blue-900',
  UNKNOWN: 'bg-surface-700 text-gray-400 border-surface-600',
}
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0,
}

function shortName(name: string): string {
  // File-type entries store the absolute rootfs path as name.  Show
  // only the tail so the cell stays readable at table widths.
  if (name.startsWith('/')) return name.split('/').slice(-3).join('/')
  return name
}

export function SbomTab({ components }: SbomTabProps) {
  const [filter, setFilter] = useState('')
  const [onlyVulnerable, setOnlyVulnerable] = useState(false)
  const [showFiles, setShowFiles] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('severity')

  const libraryCount = useMemo(
    () => components.filter((c) => c.type !== 'file').length,
    [components],
  )
  const fileCount = components.length - libraryCount
  const vulnerableCount = useMemo(
    () => components.filter((c) => c.cve_count > 0).length,
    [components],
  )

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase()
    const filtered = components.filter((c) => {
      if (!showFiles && c.type === 'file') return false
      if (onlyVulnerable && c.cve_count === 0) return false
      if (!q) return true
      return (
        c.name.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        c.type.toLowerCase().includes(q) ||
        (c.licenses ?? []).some((l) => l.toLowerCase().includes(q))
      )
    })
    return [...filtered].sort((a, b) => {
      // Files always go last regardless of sort mode — they're noise
      // relative to a security review and don't carry CVE info.
      if ((a.type === 'file') !== (b.type === 'file')) {
        return a.type === 'file' ? 1 : -1
      }
      if (sortKey === 'cve') {
        return b.cve_count - a.cve_count || a.name.localeCompare(b.name)
      }
      if (sortKey === 'severity') {
        const ar = SEVERITY_RANK[a.max_severity ?? 'UNKNOWN'] ?? 0
        const br = SEVERITY_RANK[b.max_severity ?? 'UNKNOWN'] ?? 0
        return br - ar || b.cve_count - a.cve_count || a.name.localeCompare(b.name)
      }
      return a.name.localeCompare(b.name)
    })
  }, [components, filter, onlyVulnerable, showFiles, sortKey])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex items-center gap-4 text-sm text-gray-400">
          <div className="flex items-center gap-2">
            <Package size={15} className="text-accent-cyan" />
            <span className="font-mono">{libraryCount} libraries</span>
          </div>
          {fileCount > 0 && (
            <span className="font-mono text-xs text-gray-600">
              + {fileCount} files{showFiles ? '' : ' (hidden)'}
            </span>
          )}
          {vulnerableCount > 0 && (
            <div className="flex items-center gap-1.5 font-mono text-xs text-orange-400">
              <ShieldAlert size={13} />
              {vulnerableCount} with CVEs
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs font-mono text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlyVulnerable}
              onChange={(e) => setOnlyVulnerable(e.target.checked)}
              className="accent-accent-cyan"
            />
            Vulnerable only
          </label>
          <label className="flex items-center gap-1.5 text-xs font-mono text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showFiles}
              onChange={(e) => setShowFiles(e.target.checked)}
              className="accent-accent-cyan"
            />
            Show files
          </label>
          <select
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            className="bg-surface-800 border border-surface-600 rounded-lg px-2 py-1.5 text-xs font-mono text-gray-300 focus:outline-none focus:border-accent-cyan"
          >
            <option value="severity">Sort: Severity</option>
            <option value="cve">Sort: CVE count</option>
            <option value="name">Sort: Name</option>
          </select>
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter name/version/license..."
              className="bg-surface-800 border border-surface-600 rounded-lg pl-8 pr-3 py-1.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-accent-cyan w-60"
            />
          </div>
        </div>
      </div>

      {/* Table — CVE columns come first, they're the whole point of this view. */}
      <div className="border border-surface-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-700 bg-surface-800/50">
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider w-20">CVES</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider w-24">WORST</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">NAME</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VERSION</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">TYPE</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">LICENSES</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-800">
            {visible.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-8 text-gray-600 font-mono text-sm">
                  {filter || onlyVulnerable ? 'No matches' : 'No components'}
                </td>
              </tr>
            ) : (
              visible.map((c) => {
                const isFile = c.type === 'file'
                return (
                  <tr
                    key={`${c.type}:${c.name}@${c.version}`}
                    className={`transition-colors ${
                      isFile ? 'opacity-50 hover:opacity-80' : 'hover:bg-surface-800/40'
                    }`}
                  >
                    <td className="px-4 py-2.5 font-mono">
                      {c.cve_count > 0 ? (
                        <span className="px-2 py-0.5 rounded text-xs bg-orange-950/60 text-orange-300 border border-orange-900 inline-block min-w-[1.5rem] text-center">
                          {c.cve_count}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-700 pl-2">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {c.max_severity ? (
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-mono border ${
                            SEVERITY_STYLE[c.max_severity] ?? SEVERITY_STYLE.UNKNOWN
                          }`}
                        >
                          {c.max_severity}
                        </span>
                      ) : (
                        <span className="font-mono text-xs text-gray-700">—</span>
                      )}
                    </td>
                    <td
                      className="px-4 py-2.5 font-mono text-gray-200 font-medium truncate max-w-[24rem]"
                      title={c.name}
                    >
                      {shortName(c.name)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-accent-cyan text-xs">
                      {c.version || (isFile ? <span className="text-gray-700">(file)</span> : <span className="text-gray-600">unknown</span>)}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-surface-700 text-gray-400">
                        {c.type || '—'}
                      </span>
                    </td>
                    <td
                      className="px-4 py-2.5 font-mono text-xs text-gray-500 truncate max-w-[14rem]"
                      title={(c.licenses ?? []).join(', ') || ''}
                    >
                      {(c.licenses ?? []).length ? c.licenses.join(', ') : '—'}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
