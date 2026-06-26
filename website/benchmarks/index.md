---
title: Benchmarks
---

# Benchmarks

Automated benchmarks run on every push to `main` (TCP proxy + MITM) and weekly (multi-stream sweep).
All measurements run in a GitHub-hosted `ubuntu-latest` container with `CAP_NET_ADMIN`, using
two shaped network paths (100 Mbit/25 ms each) via `tc-netem`.

<script setup>
import { ref, computed } from 'vue'
import { usePerfData, fmtNum } from '../.vitepress/theme/composables/usePerfData'

const push    = usePerfData('', 1)
const pushAll = usePerfData('')
const weekly  = usePerfData('/weekly')

const selectedProfile = ref('symmetric')
const filteredMultiStream = computed(() =>
  weekly.multiStreamRows.value.filter(r => r.profile === selectedProfile.value)
)
</script>

<ClientOnly>

<div v-if="push.loading.value" class="loading-msg">Loading benchmark data…</div>
<div v-else-if="push.error.value" class="error-msg">{{ push.error.value }}</div>
<template v-else>

## Summary

<div class="summary-cards">
  <div class="summary-card">
    <div class="card-label">TCP Proxy Throughput</div>
    <div class="card-value">{{ push.tcpProxyRows.value[0]?.multipath ?? '—' }} <span class="unit">Mbps</span></div>
    <div class="card-sub">multipath, latest commit</div>
  </div>
  <div class="summary-card">
    <div class="card-label">Aggregation Ratio</div>
    <div class="card-value">{{ push.tcpProxyRows.value[0]?.aggregation_ratio ?? '—' }}<span class="unit">×</span></div>
    <div class="card-sub">multipath / direct, latest commit</div>
  </div>
  <div class="summary-card">
    <div class="card-label">MITM Throughput</div>
    <div class="card-value">{{ push.mitmRows.value[0]?.multipath ?? '—' }} <span class="unit">Mbps</span></div>
    <div class="card-sub">multipath H2, latest commit</div>
  </div>
</div>

> **Note:** GitHub-hosted runner throughput varies between runs due to shared infrastructure.
> Aggregation ratios are more stable than absolute Mbps values.

</template>

---

## Per-commit Results

<div v-if="pushAll.loading.value" class="loading-msg">Loading…</div>
<div v-else-if="pushAll.error.value" class="error-msg">{{ pushAll.error.value }}</div>
<template v-else>

### TCP Proxy

<table v-if="pushAll.tcpProxyRows.value.length > 0">
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Direct (Mbps)</th>
      <th>Single Path (Mbps)</th>
      <th>Multipath (Mbps)</th>
      <th>Aggregation</th>
      <th>Overhead%</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="r in pushAll.tcpProxyRows.value" :key="r.commit + r.date">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.direct }}</td>
      <td>{{ r.single_path }}</td>
      <td>{{ r.multipath }}</td>
      <td>{{ r.aggregation_ratio }}×</td>
      <td>{{ r.overhead_single }}%</td>
    </tr>
  </tbody>
</table>
<p v-else class="no-data">No per-commit TCP proxy data yet. Data will appear after the first successful <code>perf.yml</code> run.</p>

### MITM H2

<table v-if="pushAll.mitmRows.value.length > 0">
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Single Path (Mbps)</th>
      <th>Multipath (Mbps)</th>
      <th>Aggregation</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="r in pushAll.mitmRows.value" :key="r.commit + r.date">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.single_path }}</td>
      <td>{{ r.multipath }}</td>
      <td>{{ r.aggregation_ratio }}×</td>
    </tr>
  </tbody>
</table>
<p v-else class="no-data">No per-commit MITM data yet.</p>

</template>

---

## Weekly Results

<div v-if="weekly.loading.value" class="loading-msg">Loading…</div>
<div v-else-if="weekly.error.value" class="error-msg">{{ weekly.error.value }}</div>
<template v-else>

### TCP Proxy (weekly)

<table v-if="weekly.tcpProxyRows.value.length > 0">
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Direct (Mbps)</th>
      <th>Single Path (Mbps)</th>
      <th>Multipath (Mbps)</th>
      <th>Aggregation</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="r in weekly.tcpProxyRows.value" :key="r.commit + r.date">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.direct }}</td>
      <td>{{ r.single_path }}</td>
      <td>{{ r.multipath }}</td>
      <td>{{ r.aggregation_ratio }}×</td>
    </tr>
  </tbody>
</table>
<p v-else class="no-data">No weekly TCP proxy data yet.</p>

### MITM H2 (weekly)

<table v-if="weekly.mitmRows.value.length > 0">
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Single Path (Mbps)</th>
      <th>Multipath (Mbps)</th>
      <th>Aggregation</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="r in weekly.mitmRows.value" :key="r.commit + r.date">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.single_path }}</td>
      <td>{{ r.multipath }}</td>
      <td>{{ r.aggregation_ratio }}×</td>
    </tr>
  </tbody>
</table>
<p v-else class="no-data">No weekly MITM data yet.</p>

### Multi-Stream Sweep (weekly)

<div class="filter-bar">
  Profile:
  <select v-model="selectedProfile">
    <option v-for="p in profiles" :key="p" :value="p">{{ p }}</option>
  </select>
</div>

<table v-if="filteredMultiStream.length > 0">
  <thead>
    <tr>
      <th>Commit</th>
      <th>Date</th>
      <th>Streams</th>
      <th>Single Path (Mbps)</th>
      <th>Multipath (Mbps)</th>
      <th>Gain</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="r in filteredMultiStream" :key="r.commit + r.date + r.streams">
      <td><code>{{ r.commit }}</code></td>
      <td>{{ r.date }}</td>
      <td>{{ r.streams }}</td>
      <td>{{ r.single_path }}</td>
      <td>{{ r.multipath }}</td>
      <td>{{ r.gain_pct }}</td>
    </tr>
  </tbody>
</table>
<p v-else class="no-data">No weekly multi-stream data yet (runs Sunday 03:00 UTC).</p>

</template>

</ClientOnly>

<style scoped>
.loading-msg {
  color: var(--vp-c-text-2);
  font-style: italic;
  margin: 1rem 0;
}
.error-msg {
  color: var(--vp-c-danger-1);
  margin: 1rem 0;
}
.no-data {
  color: var(--vp-c-text-2);
  font-style: italic;
}

.summary-cards {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin: 1.5rem 0;
}
.summary-card {
  flex: 1 1 180px;
  border: 1px solid var(--vp-c-border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  background: var(--vp-c-bg-soft);
}
.card-label {
  font-size: 0.8rem;
  color: var(--vp-c-text-2);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 0.5rem;
}
.card-value {
  font-size: 1.8rem;
  font-weight: 700;
  color: var(--vp-c-brand-1);
}
.card-value .unit {
  font-size: 0.9rem;
  font-weight: 400;
  color: var(--vp-c-text-2);
}
.card-sub {
  font-size: 0.75rem;
  color: var(--vp-c-text-2);
  margin-top: 0.25rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
  margin: 1rem 0;
}
th, td {
  text-align: left;
  padding: 0.4rem 0.75rem;
  border-bottom: 1px solid var(--vp-c-border);
}
th {
  background: var(--vp-c-bg-soft);
  font-weight: 600;
}

.filter-bar {
  margin: 1rem 0 0.5rem;
  font-size: 0.9rem;
}
.filter-bar select {
  margin-left: 0.5rem;
  padding: 0.2rem 0.5rem;
  border: 1px solid var(--vp-c-border);
  border-radius: 4px;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-1);
}
</style>
