import { useState } from 'react'
import { Search, Package } from 'lucide-react'
import type { SbomComponent } from '../../types'

interface SbomTabProps {
  components: SbomComponent[]
}

export function SbomTab({ components }: SbomTabProps) {
  const [filter, setFilter] = useState('')

  const filtered = components.filter((c) => {
    if (!filter) return true
    const q = filter.toLowerCase()
    return (
      c.name.toLowerCase().includes(q) ||
      c.version.toLowerCase().includes(q) ||
      c.type.toLowerCase().includes(q)
    )
  })

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Package size={15} className="text-accent-cyan" />
          <span className="font-mono">{components.length} components</span>
        </div>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-600" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter..."
            className="bg-surface-800 border border-surface-600 rounded-lg pl-8 pr-3 py-1.5 text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-accent-cyan w-48"
          />
        </div>
      </div>

      {/* Table */}
      <div className="border border-surface-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-700 bg-surface-800/50">
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">NAME</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">VERSION</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">TYPE</th>
              <th className="text-left px-4 py-2.5 text-xs font-mono text-gray-500 tracking-wider">PURL</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-800">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={4} className="text-center py-8 text-gray-600 font-mono text-sm">
                  {filter ? 'No matches' : 'No components'}
                </td>
              </tr>
            ) : (
              filtered.map((c) => (
                <tr key={c.bom_ref} className="hover:bg-surface-800/40 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-gray-200 font-medium">{c.name}</td>
                  <td className="px-4 py-2.5 font-mono text-accent-cyan text-xs">{c.version || '—'}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-surface-700 text-gray-400">
                      {c.type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-600 truncate max-w-xs" title={c.purl ?? ''}>
                    {c.purl ?? '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
