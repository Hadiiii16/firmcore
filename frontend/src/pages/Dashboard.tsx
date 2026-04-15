import { useState, useCallback, type MouseEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Clock, CheckCircle, XCircle, ChevronRight, Trash2, RefreshCw } from 'lucide-react'
import { FileDropzone } from '../components/FileDropzone'
import { StatusBadge } from '../components/Badge'
import { uploadFirmware } from '../api/client'
import { useJobs } from '../hooks/useJobs'
import type { JobSummary } from '../types'

function SeverityDots({ job }: { job: JobSummary }) {
  return (
    <div className="flex items-center gap-1 text-xs font-mono">
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

function formatAge(ts: string) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function Dashboard() {
  const navigate = useNavigate()
  const { jobs = [], total, loading, error, refresh, remove } = useJobs(20)

  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadError, setUploadError] = useState<string | null>(null)

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
      } catch (err) {
        alert((err as Error).message)
      }
    },
    [remove],
  )

  // Stats
  const completed = jobs.filter((j) => j.status === 'completed').length
  const failed = jobs.filter((j) => j.status === 'failed').length
  const active = jobs.filter(
    (j) => !['completed', 'failed', 'pending'].includes(j.status),
  ).length

  return (
    <div className="min-h-screen bg-surface-950">
      {/* Nav */}
      <nav className="border-b border-surface-700 bg-surface-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center gap-3">
          <Shield size={20} className="text-accent-green glow-green" />
          <span className="font-mono font-bold text-accent-green tracking-wider glow-green">
            FIRMCORE
          </span>
          <span className="text-gray-600 font-mono text-xs">v1.0</span>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => refresh()}
              className="p-1.5 rounded hover:bg-surface-700 text-gray-500 hover:text-gray-300 transition-colors"
              title="Refresh"
            >
              <RefreshCw size={15} />
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-6xl mx-auto px-4 py-8 space-y-8">
        {/* Stats bar */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'TOTAL JOBS', value: total, icon: <Clock size={16} />, color: 'text-gray-400' },
            { label: 'ACTIVE',     value: active,    icon: <RefreshCw size={16} className="animate-spin-slow" />, color: 'text-accent-cyan' },
            { label: 'COMPLETED',  value: completed, icon: <CheckCircle size={16} />, color: 'text-accent-green' },
            { label: 'FAILED',     value: failed,    icon: <XCircle size={16} />,     color: 'text-red-400' },
          ].map(({ label, value, icon, color }) => (
            <div key={label} className="bg-surface-900 border border-surface-700 rounded-xl p-4">
              <div className={`flex items-center gap-2 ${color} mb-1`}>
                {icon}
                <span className="text-xs font-mono tracking-wider">{label}</span>
              </div>
              <p className={`text-2xl font-mono font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-5 gap-6">
          {/* Upload panel */}
          <div className="col-span-2">
            <div className="bg-surface-900 border border-surface-700 rounded-xl p-5">
              <h2 className="text-sm font-mono font-semibold text-gray-300 tracking-wider mb-4">
                NEW ANALYSIS
              </h2>
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
          </div>

          {/* Job list */}
          <div className="col-span-3">
            <div className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-surface-700 flex items-center justify-between">
                <h2 className="text-sm font-mono font-semibold text-gray-300 tracking-wider">
                  RECENT ANALYSES
                </h2>
                <span className="text-xs font-mono text-gray-600">{total} total</span>
              </div>

              {loading && jobs.length === 0 ? (
                <div className="py-16 text-center text-gray-600 font-mono text-sm">
                  Loading...
                </div>
              ) : error ? (
                <div className="py-16 text-center text-red-500 font-mono text-sm">
                  {error}
                </div>
              ) : jobs.length === 0 ? (
                <div className="py-16 text-center text-gray-600 font-mono text-sm">
                  No analyses yet. Upload a firmware image to begin.
                </div>
              ) : (
                <ul className="divide-y divide-surface-800">
                  {jobs.map((job) => (
                    <li
                      key={job.id}
                      onClick={() => navigate(`/jobs/${job.id}`)}
                      className="flex items-center gap-3 px-5 py-3.5 hover:bg-surface-800/60 cursor-pointer transition-colors group"
                    >
                      {/* Status */}
                      <StatusBadge status={job.status} />

                      {/* File info */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-200 font-mono truncate">
                          {job.filename}
                        </p>
                        <p className="text-xs text-gray-600 mt-0.5 truncate">
                          {[job.product_name, job.product_version].filter(Boolean).join(' ') || 'No metadata'}
                          {' · '}{formatAge(job.created_at)}
                        </p>
                      </div>

                      {/* CVE dots */}
                      <SeverityDots job={job} />

                      {/* Actions */}
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
      </div>
    </div>
  )
}
