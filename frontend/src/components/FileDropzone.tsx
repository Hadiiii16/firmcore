import { useState, useCallback, useRef } from 'react'
import { Upload, HardDrive, AlertCircle } from 'lucide-react'

const MAX_SIZE_MB = 500
const MAX_BYTES = MAX_SIZE_MB * 1024 * 1024

interface FileDropzoneProps {
  onSubmit: (file: File, productName: string, productVersion: string) => void
  uploading: boolean
  uploadProgress: number
}

export function FileDropzone({ onSubmit, uploading, uploadProgress }: FileDropzoneProps) {
  const [dragOver, setDragOver] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [productName, setProductName] = useState('')
  const [productVersion, setProductVersion] = useState('')
  const [fileError, setFileError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const validateAndSet = useCallback((file: File) => {
    setFileError(null)
    if (file.size > MAX_BYTES) {
      setFileError(`File exceeds ${MAX_SIZE_MB} MB limit (${(file.size / 1024 / 1024).toFixed(1)} MB)`)
      return
    }
    setSelectedFile(file)
  }, [])

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      const file = e.dataTransfer.files[0]
      if (file) validateAndSet(file)
    },
    [validateAndSet],
  )

  const onFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) validateAndSet(file)
    },
    [validateAndSet],
  )

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFile || uploading) return
    onSubmit(selectedFile, productName, productVersion)
  }

  const fmtSize = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
    return `${(bytes / 1024).toFixed(0)} KB`
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Drop zone */}
      <div
        onClick={() => !uploading && inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={`
          relative flex flex-col items-center justify-center gap-3
          border-2 border-dashed rounded-xl p-10 cursor-pointer
          transition-all duration-200 select-none
          ${dragOver
            ? 'border-accent-cyan bg-cyan-900/10 border-glow-cyan'
            : selectedFile
              ? 'border-accent-green bg-green-900/10'
              : 'border-surface-600 hover:border-surface-500 bg-surface-900/50 hover:bg-surface-900'
          }
          ${uploading ? 'cursor-not-allowed opacity-60' : ''}
        `}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={onFileChange}
          disabled={uploading}
          accept=".bin,.img,.fw,.zip,.gz,.tar,.elf,.hex"
        />

        {selectedFile ? (
          <>
            <HardDrive size={36} className="text-accent-green" />
            <div className="text-center">
              <p className="font-mono text-accent-green font-semibold truncate max-w-xs">
                {selectedFile.name}
              </p>
              <p className="text-sm text-gray-500 mt-0.5">{fmtSize(selectedFile.size)}</p>
            </div>
            {!uploading && (
              <p className="text-xs text-gray-600">Click to change file</p>
            )}
          </>
        ) : (
          <>
            <Upload
              size={36}
              className={`transition-colors ${dragOver ? 'text-accent-cyan' : 'text-gray-600'}`}
            />
            <div className="text-center">
              <p className="text-gray-400 font-medium">
                Drop firmware image here or{' '}
                <span className="text-accent-cyan">browse</span>
              </p>
              <p className="text-xs text-gray-600 mt-1">
                .bin .img .fw .zip .gz .tar .elf · Max {MAX_SIZE_MB} MB
              </p>
            </div>
          </>
        )}
      </div>

      {/* File error */}
      {fileError && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2">
          <AlertCircle size={14} />
          {fileError}
        </div>
      )}

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1 tracking-wider">
            PRODUCT NAME
          </label>
          <input
            type="text"
            value={productName}
            onChange={(e) => setProductName(e.target.value)}
            placeholder="e.g. TP-Link Archer C6"
            disabled={uploading}
            className="w-full bg-surface-800 border border-surface-600 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-accent-cyan transition-colors disabled:opacity-50"
          />
        </div>
        <div>
          <label className="block text-xs font-mono text-gray-500 mb-1 tracking-wider">
            VERSION
          </label>
          <input
            type="text"
            value={productVersion}
            onChange={(e) => setProductVersion(e.target.value)}
            placeholder="e.g. 3.1.2"
            disabled={uploading}
            className="w-full bg-surface-800 border border-surface-600 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-accent-cyan transition-colors disabled:opacity-50"
          />
        </div>
      </div>

      {/* Upload progress */}
      {uploading && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs font-mono text-gray-500">
            <span>Uploading...</span>
            <span>{uploadProgress}%</span>
          </div>
          <div className="h-1.5 bg-surface-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-cyan rounded-full transition-all duration-300"
              style={{ width: `${uploadProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Submit */}
      <button
        type="submit"
        disabled={!selectedFile || uploading || !!fileError}
        className="
          w-full py-3 rounded-lg font-mono font-semibold text-sm tracking-wider
          transition-all duration-200
          bg-accent-green text-surface-950
          hover:brightness-110 active:scale-[0.99]
          disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:brightness-100
        "
      >
        {uploading ? 'UPLOADING...' : 'START ANALYSIS'}
      </button>
    </form>
  )
}
