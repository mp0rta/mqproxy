import { ref, onMounted, computed, type Ref } from 'vue'

// ── Format helpers ──

export function fmtDate(ts: string) {
  return new Date(ts).toISOString().slice(0, 10)
}

export function fmtCommit(c: string) {
  return c ? c.slice(0, 7) : '?'
}

export function fmtNum(v: number | null | undefined, digits = 1) {
  if (v == null) return '-'
  return Number(v).toFixed(digits)
}

// ── Data types ──

export interface IndexEntry {
  commit: string
  timestamp: string
  type: string
  files: string[]
}

export interface BenchmarkItem {
  commit: string
  timestamp: string
  data: any
}

// ── Fetch helpers ──

async function fetchJson(url: string) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${url}: ${res.status}`)
  return res.json()
}

// PERF_DATA_BASE includes the bucket prefix so subPath '' reaches the
// per-commit index. The R2 custom domain is bound to bucket root; the
// duplicated "perf-data" segment = subdomain + S3 prefix.
// mqproxy data is colocated in the mqvpn-bench bucket under the mqproxy/ prefix.
const PERF_DATA_BASE = (import.meta as any).env?.VITE_PERF_DATA_BASE
  ?? 'https://perf-data.mqvpn.org/mqproxy/perf-data'

/**
 * Fetch mqproxy benchmark data from R2.
 * @param subPath - '' for per-commit, '/weekly' for weekly
 * @param maxEntries - how many index entries to load (default 10)
 */
export function usePerfData(subPath: string, maxEntries = 10) {
  const basePath = `${PERF_DATA_BASE}${subPath}`
  const loading = ref(true)
  const error = ref('')
  const items: Ref<BenchmarkItem[]> = ref([])

  onMounted(async () => {
    try {
      const index: IndexEntry[] = await fetchJson(`${basePath}/index.json`)
      const entries = index.slice(0, maxEntries)

      const tasks = entries.flatMap(entry =>
        (entry.files || []).map(async file => ({
          commit: entry.commit,
          timestamp: entry.timestamp,
          data: await fetchJson(`${basePath}/${file}`),
        }))
      )
      items.value = await Promise.all(tasks)
    } catch (e: any) {
      error.value = e.message || 'Failed to load benchmark data.'
    } finally {
      loading.value = false
    }
  })

  // ── Computed row extractors ──

  /**
   * TCP proxy rows: direct baseline + single_path + multipath columns.
   * Source JSON: { test: 'tcp_proxy', results: { DL: { direct_mbps, single_path_mbps, multipath_mbps } },
   *               aggregation_ratio, overhead_pct: { single_path } }
   */
  const tcpProxyRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'tcp_proxy') continue
      const dl = item.data.results?.DL
      if (!dl) continue
      rows.push({
        commit: fmtCommit(item.commit),
        date: fmtDate(item.timestamp),
        direct: fmtNum(dl.direct_mbps),
        single_path: fmtNum(dl.single_path_mbps),
        multipath: fmtNum(dl.multipath_mbps),
        aggregation_ratio: fmtNum(item.data.aggregation_ratio, 2),
        overhead_single: fmtNum(item.data.overhead_pct?.single_path, 1),
      })
    }
    return rows
  })

  /**
   * MITM rows: single_path and multipath H2 throughput.
   * Source JSON: { test: 'mitm', results: { DL: { single_path_mbps, multipath_mbps } },
   *               aggregation_ratio }
   */
  const mitmRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'mitm') continue
      const dl = item.data.results?.DL
      if (!dl) continue
      rows.push({
        commit: fmtCommit(item.commit),
        date: fmtDate(item.timestamp),
        single_path: fmtNum(dl.single_path_mbps),
        multipath: fmtNum(dl.multipath_mbps),
        aggregation_ratio: fmtNum(item.data.aggregation_ratio, 2),
      })
    }
    return rows
  })

  /**
   * Multi-stream sweep rows: flat array across profiles and stream counts.
   * Source JSON: { test: 'multi_stream', results: [{ profile, streams, single_path_mbps, multipath_mbps, gain_pct }] }
   */
  const multiStreamRows = computed(() => {
    const rows: any[] = []
    for (const item of items.value) {
      if (item.data.test !== 'multi_stream') continue
      for (const r of item.data.results || []) {
        rows.push({
          commit: fmtCommit(item.commit),
          date: fmtDate(item.timestamp),
          profile: r.profile,
          streams: r.streams,
          single_path: fmtNum(r.single_path_mbps),
          multipath: fmtNum(r.multipath_mbps),
          gain_pct: r.gain_pct != null ? fmtNum(r.gain_pct, 1) + '%' : '-',
        })
      }
    }
    return rows
  })

  return {
    loading,
    error,
    items,
    tcpProxyRows,
    mitmRows,
    multiStreamRows,
  }
}
