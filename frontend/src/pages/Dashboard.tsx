import { useState, useCallback, type MouseEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, RefreshCw, Package, ShieldAlert, Activity, ChevronRight, Trash2,
  AlertTriangle, CheckCircle2, HelpCircle, Upload as UploadIcon,
  ChevronDown, ChevronUp, ExternalLink,
} from 'lucide-react'
import { FileDropzone } from '../components/FileDropzone'
import { StatusBadge } from '../components/Badge'
import { uploadFirmware } from '../api/client'
import { useJobs } from '../hooks/useJobs'
import { useDashboardSummary } from '../hooks/useDashboardSummary'
import type { FirmwareRef, JobSummary, TopCve, TopPackage } from '../types'

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatAge(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-300 bg-red-950/60 border-red-900',
  HIGH: 'text-orange-300 bg-orange-950/60 border-orange-900',
  MEDIUM: 'text-amber-300 bg-amber-950/60 border-amber-900',
  LOW: 'text-blue-300 bg-blue-950/60 border-blue-900',
  UNKNOWN: 'text-gray-400 bg-surface-700 border-surface-600',
}

function SevBadge({ sev }: { sev: string | null | undefined }) {
  const key = (sev ?? 'UNKNOWN').toUpperCase()
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${SEV_COLOR[key] ?? SEV_COLOR.UNKNOWN}`}>
      {key}
    </span>
  )
}

const VEX_COLOR: Record<string, string> = {
  affected: 'text-red-300',
  not_affected: 'text-emerald-300',
  under_investigation: 'text-amber-300',
  unanalyzed: 'text-gray-500',
}

// Shared drill-down panel used for both package & CVE rows — lists every
// firmware the row covers with a link to its detail page.
function FirmwareDrillDown({
  firmwares, mode, onNavigate,
}: {
  firmwares: FirmwareRef[]
  mode: 'package' | 'cve'
  onNavigate: (jobId: string) => void
}) {
  if (!firmwares.length) {
    return (
      <p className="px-6 py-3 text-xs font-mono text-gray-600">
        No firmware data available.
      </p>
    )
  }
  return (
    <ul className="divide-y divide-surface-800">
      {firmwares.map((f) => (
        <li
          key={f.job_id}
          onClick={() => onNavigate(f.job_id)}
          className="flex items-center gap-3 px-6 py-2 hover:bg-surface-800/60 cursor-pointer group"
        >
          <div className="flex-1 min-w-0">
            <p className="text-xs font-mono text-gray-200 truncate">{f.filename}</p>
            <p className="text-[10px] font-mono text-gray-600 truncate">
              {[f.product_name, f.product_version].filter(Boolean).join(' ') || 'No metadata'}
            </p>
          </div>
          {mode === 'package' ? (
            <span className="text-[10px] font-mono text-gray-400">
              {f.cve_count} CVE{f.cve_count === 1 ? '' : 's'}
            </span>
          ) : (
            <span
              className={`text-[10px] font-mono uppercase tracking-wider ${
                VEX_COLOR[f.vex_status ?? 'unanalyzed'] ?? 'text-gray-500'
              }`}
            >
              {(f.vex_status ?? 'unanalyzed').replace(/_/g, ' ')}
            </span>
          )}
          <ExternalLink size={11} className="text-gray-600 group-hover:text-gray-300" />
        </li>
      ))}
    </ul>
  )
}

function TopPackageRow({
  pkg, expanded, onToggle, onNavigate,
}: {
  pkg: TopPackage
  expanded: boolean
  onToggle: () => void
  onNavigate: (jobId: string) => void
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="hover:bg-surface-800/40 cursor-pointer"
      >
        <td className="px-4 py-2 font-mono text-xs text-gray-200 truncate max-w-[14rem]">
          <div className="flex items-center gap-1.5">
            {expanded ? <ChevronUp size={11} className="text-gray-600" /> : <ChevronDown size={11} className="text-gray-600" />}
            <span>{pkg.package_name}</span>
            <span className="text-gray-600">{pkg.package_version}</span>
          </div>
        </td>
        <td className="px-4 py-2 font-mono text-xs text-accent-cyan">{pkg.firmware_count}</td>
        <td className="px-4 py-2 font-mono text-xs text-gray-300">{pkg.cve_count}</td>
        <td className="px-4 py-2 font-mono text-xs">
          {pkg.affected_count > 0 ? (
            <span className="text-red-300">{pkg.affected_count}</span>
          ) : (
            <span className="text-gray-600">—</span>
          )}
        </td>
        <td className="px-4 py-2"><SevBadge sev={pkg.max_severity} /></td>
      </tr>
      {expanded && (
        <tr className="bg-surface-950/60">
          <td colSpan={5} className="py-1">
            <FirmwareDrillDown
              firmwares={pkg.firmwares}
              mode="package"
              onNavigate={onNavigate}
            />
          </td>
        </tr>
      )}
    </>
  )
}

function TopCveRow({
  cve, expanded, onToggle, onNavigate,
}: {
  cve: TopCve
  expanded: boolean
  onToggle: () => void
  onNavigate: (jobId: string) => void
}) {
  return (
    <>
      <tr onClick={onToggle} className="hover:bg-surface-800/40 cursor-pointer">
        <td className="px-4 py-2"><SevBadge sev={cve.severity} /></td>
        <td className="px-4 py-2 font-mono text-xs text-accent-cyan">
          <div className="flex items-center gap-1.5">
            {expanded ? <ChevronUp size={11} className="text-gray-600" /> : <ChevronDown size={11} className="text-gray-600" />}
            <span>{cve.cve_id}</span>
          </div>
        </td>
        <td className="px-4 py-2 font-mono text-xs text-gray-300 truncate max-w-[10rem]">
          {cve.package_name}
        </td>
        <td className="px-4 py-2 font-mono text-xs text-gray-400">{cve.firmware_count}</td>
        <td className="px-4 py-2 font-mono text-xs">
          {cve.affected_firmware_count > 0 ? (
            <span className="text-red-300">{cve.affected_firmware_count}</span>
          ) : (
            <span className="text-gray-600">—</span>
          )}
        </td>
        <td className="px-4 py-2 font-mono text-xs text-gray-400">
          {cve.max_cvss != null ? cve.max_cvss.toFixed(1) : '—'}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-surface-950/60">
          <td colSpan={6} className="py-1">
            <FirmwareDrillDown
              firmwares={cve.firmwares}
              mode="cve"
              onNavigate={onNavigate}
            />
          </td>
        </tr>
      )}
    </>
  )
}

// ── KPI card ─────────────────────────────────────────────────────────────────

function KpiCard({
  label, value, sub, color = 'text-gray-200', icon,
}: {
  label: string
  value: number | string
  sub?: string
  color?: string
  icon?: React.ReactNode
}) {
  return (
    <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
      <div className="flex items-center gap-2 text-xs font-mono tracking-wider text-gray-500 mb-1.5">
        {icon}
        <span>{label}</span>
      </div>
      <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
      {sub && <p className="text-[11px] font-mono text-gray-600 mt-1">{sub}</p>}
    </div>
  )
}

// ── Severity bar chart ──────────────────────────────────────────────────────

function SeverityChart({
  critical, high, medium, low,
}: {
  critical: number; high: number; medium: number; low: number
}) {
  const total = critical + high + medium + low
  const rows = [
    { label: 'CRITICAL', value: critical, color: 'bg-red-500', text: 'text-red-300' },
    { label: 'HIGH',     value: high,     color: 'bg-orange-500', text: 'text-orange-300' },
    { label: 'MEDIUM',   value: medium,   color: 'bg-amber-500', text: 'text-amber-300' },
    { label: 'LOW',      value: low,      color: 'bg-blue-500', text: 'text-blue-300' },
  ]
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <div className="space-y-2">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3 text-xs font-mono">
          <span className={`w-20 ${r.text}`}>{r.label}</span>
          <div className="flex-1 bg-surface-800 rounded h-2 overflow-hidden">
            <div
              className={`h-full ${r.color} transition-all`}
              style={{ width: `${(r.value / max) * 100}%` }}
            />
          </div>
          <span className="w-10 text-right text-gray-400">{r.value}</span>
        </div>
      ))}
      {total === 0 && (
        <p className="text-xs font-mono text-gray-600 text-center pt-2">
          No CVEs across fleet.
        </p>
      )}
    </div>
  )
}

// ── VEX coverage ────────────────────────────────────────────────────────────

function VexCoverage({
  affected, notAffected, underInvestigation, unanalyzed,
}: {
  affected: number; notAffected: number; underInvestigation: number; unanalyzed: number
}) {
  const total = affected + notAffected + underInvestigation + unanalyzed
  const analyzed = affected + notAffected + underInvestigation
  const pct = total > 0 ? Math.round((analyzed / total) * 100) : 0
  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center justify-between text-xs font-mono mb-1.5">
          <span className="text-gray-500">VEX Coverage</span>
          <span className="text-accent-cyan">{pct}%</span>
        </div>
        <div className="bg-surface-800 rounded-full h-2 overflow-hidden flex">
          <div className="h-full bg-red-500/80" style={{ width: total ? `${(affected / total) * 100}%` : 0 }} />
          <div className="h-full bg-emerald-500/80" style={{ width: total ? `${(notAffected / total) * 100}%` : 0 }} />
          <div className="h-full bg-amber-500/80" style={{ width: total ? `${(underInvestigation / total) * 100}%` : 0 }} />
          <div className="h-full bg-surface-600" style={{ width: total ? `${(unanalyzed / total) * 100}%` : 0 }} />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
        <div className="flex items-center gap-2">
          <ShieldAlert size={12} className="text-red-400" />
          <span className="text-gray-500">Affected</span>
          <span className="ml-auto text-red-300">{affected}</span>
        </div>
        <div className="flex items-center gap-2">
          <CheckCircle2 size={12} className="text-emerald-400" />
          <span className="text-gray-500">Not affected</span>
          <span className="ml-auto text-emerald-300">{notAffected}</span>
        </div>
        <div className="flex items-center gap-2">
          <HelpCircle size={12} className="text-amber-400" />
          <span className="text-gray-500">Investigating</span>
          <span className="ml-auto text-amber-300">{underInvestigation}</span>
        </div>
        <div className="flex items-center gap-2">
          <AlertTriangle size={12} className="text-gray-500" />
          <span className="text-gray-500">Unanalyzed</span>
          <span className="ml-auto text-gray-300">{unanalyzed}</span>
        </div>
      </div>
    </div>
  )
}

// ── Severity dots for job list ──────────────────────────────────────────────

function SeverityDots({ job }: { job: JobSummary }) {
  return (
    <div className="flex items-center gap-1 text-[10px] font-mono">
      {job.critical_cves > 0 && (
        <span className="px-1.5 py-0.5 rounded bg-red-900/60 text-red-300">{job.critical_cves}C</span>
      )}
      {job.high_cves > 0 && (
        <span className="px-1.5 py-0.5 rounded bg-orange-900/60 text-orange-300">{job.high_cves}H</span>
      )}
      {job.affected_count > 0 && (
        <span className="px-1.5 py-0.5 rounded bg-red-900/40 text-red-400">{job.affected_count}A</span>
      )}
      {job.total_cves === 0 && job.status === 'completed' && (
        <span className="text-gray-600">—</span>
      )}
    </div>
  )
}

// ── Dashboard ───────────────────────────────────────────────────────────────

export function Dashboard() {
  const navigate = useNavigate()
  const { summary, refresh: refreshSummary } = useDashboardSummary(10000)
  const { jobs = [], total, loading, error, refresh: refreshJobs, remove } = useJobs(10)

  const [uploadOpen, setUploadOpen] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [expandedPkg, setExpandedPkg] = useState<string | null>(null)
  const [expandedCve, setExpandedCve] = useState<string | null>(null)

  const handleUpload = useCallback(
    async (file: File, productName: string, productVersion: string) => {
      setUploading(true)
      setUploadError(null)
      setUploadProgress(0)
      try {
        const res = await uploadFirmware(file, productName, productVersion, setUploadProgress)
        navigate(`/jobs/${res.job_id}`)
      } catch (e) {
        setUploadError((e as Error).message)
        setUploading(false)
      }
    },
    [navigate],
  )

  const handleDelete = useCallback(
    async (e: MouseEvent, jobId: string) => {
      e.stopPropagation()
      if (!confirm('Delete this job?')) return
      try {
        await remove(jobId)
        refreshSummary()
      } catch (err) {
        const msg = (err as Error).message
        // 서버 재시작 등으로 DB 상태만 진행 중으로 남은 고아 Job 이면
        // 409 → force retry 를 사용자에게 한 번 더 확인.
        if (/진행 중인 Job/.test(msg) || msg.includes('status:')) {
          if (confirm(
            `${msg}\n\n이 Job 은 이미 멈춰 있을 수 있습니다. 강제 삭제할까요?`,
          )) {
            try {
              await remove(jobId, true)
              refreshSummary()
              return
            } catch (err2) {
              alert((err2 as Error).message)
              return
            }
          }
          return
        }
        alert(msg)
      }
    },
    [remove, refreshSummary],
  )

  const s = summary

  return (
    <div className="min-h-screen bg-surface-950">
      {/* Nav */}
      <nav className="border-b border-surface-700 bg-surface-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center gap-3">
          <Shield size={20} className="text-accent-green glow-green" />
          <span className="font-mono font-bold text-accent-green tracking-wider glow-green">
            FIRMCORE
          </span>
          <span className="text-gray-600 font-mono text-xs">v1.0</span>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => setUploadOpen((v) => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-green/20 border border-accent-green/50 text-accent-green hover:bg-accent-green/30 text-xs font-mono tracking-wider transition-colors"
            >
              <UploadIcon size={13} />
              NEW ANALYSIS
            </button>
            <button
              onClick={() => { refreshSummary(); refreshJobs() }}
              className="p-1.5 rounded hover:bg-surface-700 text-gray-500 hover:text-gray-300 transition-colors"
              title="Refresh"
            >
              <RefreshCw size={15} />
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Upload modal strip */}
        {uploadOpen && (
          <div className="bg-surface-900 border border-surface-700 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-mono font-semibold text-gray-300 tracking-wider">
                NEW FIRMWARE ANALYSIS
              </h2>
              <button
                onClick={() => setUploadOpen(false)}
                className="text-xs text-gray-500 hover:text-gray-300 font-mono"
              >
                close
              </button>
            </div>
            <FileDropzone
              onSubmit={handleUpload}
              uploading={uploading}
              uploadProgress={uploadProgress}
            />
            {uploadError && (
              <div className="mt-3 text-xs text-red-400 bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2">
                {uploadError}
              </div>
            )}
          </div>
        )}

        {/* Fleet KPI cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <KpiCard
            label="FIRMWARES"
            value={s?.total_firmwares ?? '—'}
            sub={s ? `${s.unique_components} unique packages` : undefined}
            color="text-gray-200"
            icon={<Package size={13} />}
          />
          <KpiCard
            label="UNIQUE CVES"
            value={s?.unique_cves ?? '—'}
            sub={s ? `${s.critical_cves + s.high_cves} critical+high` : undefined}
            color="text-accent-cyan"
            icon={<ShieldAlert size={13} />}
          />
          <KpiCard
            label="AFFECTED"
            value={s?.affected_count ?? '—'}
            sub={s && s.affected_with_fix ? `${s.affected_with_fix} with fix available` : undefined}
            color="text-red-300"
            icon={<AlertTriangle size={13} />}
          />
          <KpiCard
            label="PENDING VEX"
            value={s?.pending_vex ?? '—'}
            sub={s ? `${s.under_investigation_count} investigating` : undefined}
            color={s && s.pending_vex > 0 ? 'text-amber-300' : 'text-gray-400'}
            icon={<HelpCircle size={13} />}
          />
          <KpiCard
            label="NOT AFFECTED"
            value={s?.not_affected_count ?? '—'}
            sub={s ? `${Math.round(((s.not_affected_count) / Math.max(1, s.affected_count + s.not_affected_count + s.under_investigation_count + s.unanalyzed_count)) * 100)}% of findings` : undefined}
            color="text-emerald-300"
            icon={<CheckCircle2 size={13} />}
          />
          <KpiCard
            label="PIPELINE"
            value={s ? `${s.active_jobs}/${s.total_jobs}` : '—'}
            sub={s ? `${s.failed_jobs} failed` : undefined}
            color={s && s.active_jobs > 0 ? 'text-accent-cyan' : 'text-gray-400'}
            icon={<Activity size={13} />}
          />
        </div>

        {/* Severity + VEX panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-surface-900 border border-surface-700 rounded-xl p-5">
            <h3 className="text-xs font-mono font-semibold text-gray-500 tracking-wider mb-4">
              SEVERITY DISTRIBUTION
            </h3>
            {s ? (
              <SeverityChart
                critical={s.critical_cves}
                high={s.high_cves}
                medium={s.medium_cves}
                low={s.low_cves}
              />
            ) : (
              <p className="text-sm font-mono text-gray-600">Loading...</p>
            )}
          </div>
          <div className="bg-surface-900 border border-surface-700 rounded-xl p-5">
            <h3 className="text-xs font-mono font-semibold text-gray-500 tracking-wider mb-4">
              VEX COVERAGE
            </h3>
            {s ? (
              <VexCoverage
                affected={s.affected_count}
                notAffected={s.not_affected_count}
                underInvestigation={s.under_investigation_count}
                unanalyzed={s.unanalyzed_count}
              />
            ) : (
              <p className="text-sm font-mono text-gray-600">Loading...</p>
            )}
          </div>
        </div>

        {/* Top exposures */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold text-gray-500 tracking-wider">
                TOP RISKY PACKAGES
              </h3>
              <span className="text-[10px] font-mono text-gray-600">fleet-wide</span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] font-mono text-gray-600 bg-surface-800/30">
                  <th className="text-left px-4 py-2 tracking-wider">PACKAGE</th>
                  <th className="text-left px-4 py-2 tracking-wider">FWs</th>
                  <th className="text-left px-4 py-2 tracking-wider">CVES</th>
                  <th className="text-left px-4 py-2 tracking-wider">AFFECTED</th>
                  <th className="text-left px-4 py-2 tracking-wider">WORST</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-800">
                {s?.top_packages.length ? s.top_packages.map((p) => {
                  const key = `${p.package_name}@${p.package_version}`
                  return (
                    <TopPackageRow
                      key={key}
                      pkg={p}
                      expanded={expandedPkg === key}
                      onToggle={() =>
                        setExpandedPkg((cur) => (cur === key ? null : key))
                      }
                      onNavigate={(jobId) => navigate(`/jobs/${jobId}`)}
                    />
                  )
                }) : (
                  <tr>
                    <td colSpan={5} className="text-center py-6 text-gray-600 font-mono text-xs">
                      {s ? 'No exposures detected' : 'Loading...'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
              <h3 className="text-xs font-mono font-semibold text-gray-500 tracking-wider">
                TOP CVES
              </h3>
              <span className="text-[10px] font-mono text-gray-600">by severity × fleet impact</span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[10px] font-mono text-gray-600 bg-surface-800/30">
                  <th className="text-left px-4 py-2 tracking-wider">SEV</th>
                  <th className="text-left px-4 py-2 tracking-wider">CVE</th>
                  <th className="text-left px-4 py-2 tracking-wider">PACKAGE</th>
                  <th className="text-left px-4 py-2 tracking-wider">FWs</th>
                  <th className="text-left px-4 py-2 tracking-wider" title="Firmwares with VEX affected verdict">AFF</th>
                  <th className="text-left px-4 py-2 tracking-wider">CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-800">
                {s?.top_cves.length ? s.top_cves.map((c) => (
                  <TopCveRow
                    key={c.cve_id}
                    cve={c}
                    expanded={expandedCve === c.cve_id}
                    onToggle={() =>
                      setExpandedCve((cur) => (cur === c.cve_id ? null : c.cve_id))
                    }
                    onNavigate={(jobId) => navigate(`/jobs/${jobId}`)}
                  />
                )) : (
                  <tr>
                    <td colSpan={6} className="text-center py-6 text-gray-600 font-mono text-xs">
                      {s ? 'No CVEs detected' : 'Loading...'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent analyses — secondary, compact */}
        <div className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
            <h3 className="text-xs font-mono font-semibold text-gray-500 tracking-wider">
              RECENT ANALYSES
            </h3>
            <span className="text-[10px] font-mono text-gray-600">{total} total</span>
          </div>
          {loading && jobs.length === 0 ? (
            <div className="py-10 text-center text-gray-600 font-mono text-sm">Loading...</div>
          ) : error ? (
            <div className="py-10 text-center text-red-500 font-mono text-sm">{error}</div>
          ) : jobs.length === 0 ? (
            <div className="py-10 text-center text-gray-600 font-mono text-sm">
              No analyses yet. Click "NEW ANALYSIS" to begin.
            </div>
          ) : (
            <ul className="divide-y divide-surface-800">
              {jobs.map((job) => (
                <li
                  key={job.id}
                  onClick={() => navigate(`/jobs/${job.id}`)}
                  className="flex items-center gap-3 px-5 py-2.5 hover:bg-surface-800/60 cursor-pointer transition-colors group"
                >
                  <StatusBadge status={job.status} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-gray-200 font-mono truncate">
                      {job.filename}
                    </p>
                    <p className="text-[11px] text-gray-600 mt-0.5 truncate">
                      {[job.product_name, job.product_version].filter(Boolean).join(' ') || 'No metadata'}
                      {' · '}{formatAge(job.created_at)}
                    </p>
                  </div>
                  <SeverityDots job={job} />
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={(e) => handleDelete(e, job.id)}
                      className="p-1.5 rounded hover:bg-red-900/40 text-gray-600 hover:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <Trash2 size={13} />
                    </button>
                    <ChevronRight size={14} className="text-gray-600" />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
