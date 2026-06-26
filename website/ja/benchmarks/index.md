---
title: ベンチマーク
---

# ベンチマーク

`main` への push ごと（TCP プロキシ + MITM）および週次（マルチストリームスイープ）でベンチマークが自動実行されます。
すべての計測は GitHub ホスト型 `ubuntu-latest` コンテナ（`CAP_NET_ADMIN`）上で、
`tc-netem` で帯域制限した 2 パス構成（各 100 Mbit/25 ms）を用いて行われます。

<script setup>
import { ref, computed } from 'vue'
import { usePerfData, fmtNum } from '../../.vitepress/theme/composables/usePerfData'

const push    = usePerfData('', 1)
const pushAll = usePerfData('')
const weekly  = usePerfData('/weekly')

const selectedProfile = ref('symmetric')
const filteredMultiStream = computed(() =>
  weekly.multiStreamRows.value.filter(r => r.profile === selectedProfile.value)
)
</script>

<ClientOnly>

<div v-if="push.loading.value" class="loading-msg">ベンチマークデータを読み込み中…</div>
<div v-else-if="push.error.value" class="error-msg">{{ push.error.value }}</div>
<template v-else>

## サマリー

<div class="summary-cards">
  <div class="summary-card">
    <div class="card-label">TCP プロキシ スループット</div>
    <div class="card-value">{{ push.tcpProxyRows.value[0]?.multipath ?? '—' }} <span class="unit">Mbps</span></div>
    <div class="card-sub">マルチパス、最新コミット</div>
  </div>
  <div class="summary-card">
    <div class="card-label">集約率</div>
    <div class="card-value">{{ push.tcpProxyRows.value[0]?.aggregation_ratio ?? '—' }}<span class="unit">×</span></div>
    <div class="card-sub">マルチパス / ダイレクト、最新コミット</div>
  </div>
  <div class="summary-card">
    <div class="card-label">MITM スループット</div>
    <div class="card-value">{{ push.mitmRows.value[0]?.multipath ?? '—' }} <span class="unit">Mbps</span></div>
    <div class="card-sub">マルチパス H2、最新コミット</div>
  </div>
</div>

> **注意:** GitHub ホスト型ランナーのスループットは共有インフラの影響で実行ごとにばらつきがあります。
> 集約率は絶対値より安定しています。

</template>

---

## コミットごとの結果

<div v-if="pushAll.loading.value" class="loading-msg">読み込み中…</div>
<div v-else-if="pushAll.error.value" class="error-msg">{{ pushAll.error.value }}</div>
<template v-else>

### TCP プロキシ

<table v-if="pushAll.tcpProxyRows.value.length > 0">
  <thead>
    <tr>
      <th>コミット</th>
      <th>日時</th>
      <th>ダイレクト (Mbps)</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス (Mbps)</th>
      <th>集約率</th>
      <th>オーバーヘッド%</th>
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
<p v-else class="no-data"><code>perf.yml</code> が初回成功した後にデータが表示されます。</p>

### MITM H2

<table v-if="pushAll.mitmRows.value.length > 0">
  <thead>
    <tr>
      <th>コミット</th>
      <th>日時</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス (Mbps)</th>
      <th>集約率</th>
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
<p v-else class="no-data">MITM データはまだありません。</p>

</template>

---

## 週次結果

<div v-if="weekly.loading.value" class="loading-msg">読み込み中…</div>
<div v-else-if="weekly.error.value" class="error-msg">{{ weekly.error.value }}</div>
<template v-else>

### TCP プロキシ（週次）

<table v-if="weekly.tcpProxyRows.value.length > 0">
  <thead>
    <tr>
      <th>コミット</th>
      <th>日時</th>
      <th>ダイレクト (Mbps)</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス (Mbps)</th>
      <th>集約率</th>
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
<p v-else class="no-data">週次 TCP プロキシデータはまだありません。</p>

### MITM H2（週次）

<table v-if="weekly.mitmRows.value.length > 0">
  <thead>
    <tr>
      <th>コミット</th>
      <th>日時</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス (Mbps)</th>
      <th>集約率</th>
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
<p v-else class="no-data">週次 MITM データはまだありません。</p>

### マルチストリームスイープ（週次）

<div class="filter-bar">
  プロファイル:
  <select v-model="selectedProfile">
    <option value="symmetric">symmetric（対称）</option>
    <option value="asymmetric">asymmetric（非対称）</option>
  </select>
</div>

<table v-if="filteredMultiStream.length > 0">
  <thead>
    <tr>
      <th>コミット</th>
      <th>日時</th>
      <th>ストリーム数</th>
      <th>シングルパス (Mbps)</th>
      <th>マルチパス (Mbps)</th>
      <th>ゲイン</th>
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
<p v-else class="no-data">週次マルチストリームデータはまだありません（毎週日曜 03:00 UTC に実行）。</p>

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
