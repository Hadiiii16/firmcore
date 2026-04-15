import { useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'

interface LogLine {
  id: number
  stage: string
  text: string
  ts?: string
}

const STAGE_COLOR: Record<string, string> = {
  extracting:      'text-blue-400',
  sbom_generating: 'text-cyan-400',
  scanning:        'text-accent-purple',
  vex_analyzing:   'text-accent-amber',
  system:          'text-gray-500',
  error:           'text-red-400',
  info:            'text-gray-400',
}

function stageColor(stage: string) {
  return STAGE_COLOR[stage] ?? 'text-gray-400'
}

function formatTs(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
  } catch {
    return ''
  }
}

interface LogViewerProps {
  logs: LogLine[]
  autoScroll?: boolean
  maxHeight?: string
}

export function LogViewer({ logs, autoScroll = true, maxHeight = '400px' }: LogViewerProps) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  return (
    <div
      className="bg-surface-950 border border-surface-600 rounded-lg overflow-hidden"
      style={{ maxHeight }}
    >
      {/* header */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-surface-600 bg-surface-900">
        <Terminal size={13} className="text-accent-green" />
        <span className="text-xs font-mono text-gray-500 tracking-wider">PIPELINE LOG</span>
        <span className="ml-auto text-xs font-mono text-gray-600">{logs.length} lines</span>
      </div>

      {/* log area */}
      <div className="overflow-y-auto font-mono text-xs leading-relaxed p-3 space-y-0.5" style={{ maxHeight: `calc(${maxHeight} - 40px)` }}>
        {logs.length === 0 ? (
          <div className="text-gray-600 text-center py-8">Waiting for pipeline output...</div>
        ) : (
          logs.map((line) => (
            <div key={line.id} className="log-line flex gap-2 group">
              <span className="text-gray-700 shrink-0 w-20 text-right group-hover:text-gray-500 transition-colors">
                {line.ts ? formatTs(line.ts) : ''}
              </span>
              <span className={`shrink-0 w-16 ${stageColor(line.stage)}`}>
                [{line.stage.toUpperCase().slice(0, 4)}]
              </span>
              <span className="text-gray-300 break-all whitespace-pre-wrap">{line.text}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
