import type { ReactNode } from 'react'
import { HardDrive, Package, ShieldAlert, Bot, CheckCircle, XCircle, Loader } from 'lucide-react'
import type { JobStatus } from '../types'

interface Stage {
  key: string
  label: string
  icon: ReactNode
}

const STAGES: Stage[] = [
  { key: 'extracting',      label: 'Extract',  icon: <HardDrive size={16} /> },
  { key: 'sbom_generating', label: 'SBOM',     icon: <Package size={16} /> },
  { key: 'scanning',        label: 'Scan',     icon: <ShieldAlert size={16} /> },
  { key: 'vex_analyzing',   label: 'VEX AI',   icon: <Bot size={16} /> },
]

const STAGE_ORDER: string[] = STAGES.map((s) => s.key)

function stageIndex(stage: string | null): number {
  if (!stage) return -1
  return STAGE_ORDER.indexOf(stage)
}

interface PipelineStepperProps {
  status: JobStatus | null
  currentStage: string | null
  stageProgress: number
}

export function PipelineStepper({ status, currentStage, stageProgress }: PipelineStepperProps) {
  const currentIdx = stageIndex(currentStage)
  const isFailed = status === 'failed'
  const isComplete = status === 'completed'

  return (
    <div className="flex items-start gap-0">
      {STAGES.map((stage, idx) => {
        const done = isComplete || idx < currentIdx
        const active = !isFailed && idx === currentIdx
        const failed = isFailed && idx === currentIdx
        const waiting = !done && !active && !failed

        return (
          <div key={stage.key} className="flex items-center flex-1 min-w-0">
            {/* Step node */}
            <div className="flex flex-col items-center flex-1 min-w-0">
              {/* Icon circle */}
              <div
                className={`
                  relative flex items-center justify-center w-10 h-10 rounded-full border-2 transition-all duration-300
                  ${done    ? 'border-accent-green bg-green-900/30 text-accent-green' : ''}
                  ${active  ? 'border-cyan-400 bg-cyan-900/30 text-cyan-400 border-glow-cyan' : ''}
                  ${failed  ? 'border-red-500 bg-red-900/30 text-red-400' : ''}
                  ${waiting ? 'border-surface-600 bg-surface-800 text-gray-600' : ''}
                `}
              >
                {done   && <CheckCircle size={18} />}
                {failed && <XCircle size={18} />}
                {active && <Loader size={16} className="animate-spin" />}
                {waiting && stage.icon}
              </div>

              {/* Label */}
              <span
                className={`
                  mt-1.5 text-xs font-mono tracking-wide text-center truncate w-full
                  ${done    ? 'text-accent-green' : ''}
                  ${active  ? 'text-cyan-400' : ''}
                  ${failed  ? 'text-red-400'  : ''}
                  ${waiting ? 'text-gray-600'  : ''}
                `}
              >
                {stage.label}
              </span>

              {/* Progress bar (active only) */}
              {active && (
                <div className="mt-1 w-full h-0.5 bg-surface-600 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyan-400 transition-all duration-500 rounded-full"
                    style={{ width: `${stageProgress}%` }}
                  />
                </div>
              )}
            </div>

            {/* Connector line (not after last) */}
            {idx < STAGES.length - 1 && (
              <div
                className={`h-0.5 w-full mx-1 transition-colors duration-300 ${
                  done ? 'bg-accent-green' : 'bg-surface-600'
                }`}
                style={{ marginTop: '-18px' }}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
