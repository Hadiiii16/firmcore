import { useState, useEffect, useCallback } from 'react'
import { getJobs, deleteJob } from '../api/client'
import type { JobSummary } from '../types'

interface UseJobsState {
  jobs: JobSummary[]
  total: number
  loading: boolean
  error: string | null
}

export function useJobs(limit = 20, refreshInterval = 5000) {
  const [offset, setOffset] = useState(0)
  const [state, setState] = useState<UseJobsState>({
    jobs: [],
    total: 0,
    loading: true,
    error: null,
  })

  const fetch = useCallback(async () => {
    try {
      const data = await getJobs(limit, offset)
      setState({ jobs: data.items ?? [], total: data.total ?? 0, loading: false, error: null })
    } catch (e) {
      setState((s) => ({ ...s, loading: false, error: (e as Error).message }))
    }
  }, [limit, offset])

  useEffect(() => {
    setState((s) => ({ ...s, loading: true }))
    fetch()
    const id = setInterval(fetch, refreshInterval)
    return () => clearInterval(id)
  }, [fetch, refreshInterval])

  const remove = useCallback(
    async (jobId: string, force = false) => {
      await deleteJob(jobId, force)
      await fetch()
    },
    [fetch],
  )

  return { ...state, offset, setOffset, refresh: fetch, remove }
}
