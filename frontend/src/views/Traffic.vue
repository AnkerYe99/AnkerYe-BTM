<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2>流量统计</h2>
      <div style="display:flex;align-items:center;gap:12px">
        <el-radio-group v-model="period" @change="load" size="small">
          <el-radio-button value="today">今天</el-radio-button>
          <el-radio-button value="7d">近7天</el-radio-button>
          <el-radio-button value="30d">近30天</el-radio-button>
          <el-radio-button value="all">全部</el-radio-button>
        </el-radio-group>
        <el-button size="small" icon="Refresh" @click="load">刷新</el-button>
      </div>
    </div>

    <!-- 汇总卡片 -->
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-label">总请求数</div>
          <div class="stat-value">{{ fmtNum(total.requests) }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-label">出站流量</div>
          <div class="stat-value">{{ fmtBytes(total.bytes_out) }}</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-label">成功率（2xx）</div>
          <div class="stat-value" :style="{color: successRate < 90 ? '#f56c6c' : '#67c23a'}">
            {{ successRate }}%
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card">
          <div class="stat-label">错误请求（4xx+5xx）</div>
          <div class="stat-value" :style="{color: total.s4xx+total.s5xx > 0 ? '#e6a23c' : '#909399'}">
            {{ fmtNum(total.s4xx + total.s5xx) }}
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 明细表格 -->
    <el-card>
      <el-table :data="pagedList" size="small" v-loading="loading">
        <el-table-column label="站点" min-width="160">
          <template #default="{row}">
            <el-tag size="small" :type="protoTagType(row.protocol)" style="margin-right:6px">{{ row.protocol.toUpperCase() }}</el-tag>
            {{ row.name }}
          </template>
        </el-table-column>
        <el-table-column label="总请求" width="110" align="right">
          <template #default="{row}">{{ fmtNum(row.requests) }}</template>
        </el-table-column>
        <el-table-column label="出站流量" width="130" align="right">
          <template #default="{row}">{{ fmtBytes(row.bytes_out) }}</template>
        </el-table-column>
        <el-table-column label="1xx" width="75" align="right">
          <template #default="{row}">
            <span :style="{color: row.s1xx ? '#909399' : '#ccc'}">{{ fmtNum(row.s1xx) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="2xx" width="90" align="right">
          <template #default="{row}">
            <span :style="{color: row.s2xx ? '#67c23a' : '#ccc'}">{{ fmtNum(row.s2xx) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="3xx" width="90" align="right">
          <template #default="{row}">
            <span :style="{color: row.s3xx ? '#409eff' : '#ccc'}">{{ fmtNum(row.s3xx) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="4xx" width="90" align="right">
          <template #default="{row}">
            <span :style="{color: row.s4xx ? '#e6a23c' : '#ccc'}">{{ fmtNum(row.s4xx) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="5xx" width="90" align="right">
          <template #default="{row}">
            <span :style="{color: row.s5xx ? '#f56c6c' : '#ccc'}">{{ fmtNum(row.s5xx) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="成功率" width="100" align="right">
          <template #default="{row}">
            <span v-if="row.requests" :style="{color: rowSuccessRate(row) < 90 ? '#f56c6c' : '#67c23a'}">
              {{ rowSuccessRate(row) }}%
            </span>
            <span v-else style="color:#ccc">—</span>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="!loading && list.every(r=>r.requests===0)" style="text-align:center;color:#909399;padding:32px 0;font-size:13px">
        暂无数据，统计每分钟自动采集一次
      </div>
      <Pagination :total="list.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30
const period = ref('today')
const list = ref([])
const loading = ref(false)
const page = ref(1)

watch(period, () => { page.value = 1 })

const pagedList = computed(() => list.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))

async function load() {
  loading.value = true
  try {
    list.value = (await api.get('/stats/traffic', { params: { period: period.value } })).data || []
  } catch {}
  loading.value = false
}

const total = computed(() => list.value.reduce((acc, r) => {
  acc.requests += r.requests
  acc.bytes_out += r.bytes_out
  acc.s1xx += r.s1xx
  acc.s2xx += r.s2xx
  acc.s3xx += r.s3xx
  acc.s4xx += r.s4xx
  acc.s5xx += r.s5xx
  return acc
}, { requests: 0, bytes_out: 0, s1xx: 0, s2xx: 0, s3xx: 0, s4xx: 0, s5xx: 0 }))

const successRate = computed(() => {
  if (!total.value.requests) return 0
  return Math.round(total.value.s2xx / total.value.requests * 1000) / 10
})

function rowSuccessRate(row) {
  if (!row.requests) return 0
  return Math.round(row.s2xx / row.requests * 1000) / 10
}

function fmtNum(n) {
  if (!n) return '0'
  if (n >= 1e8) return (n / 1e8).toFixed(1) + ' 亿'
  if (n >= 1e4) return (n / 1e4).toFixed(1) + ' 万'
  return n.toLocaleString()
}

function fmtBytes(b) {
  if (!b) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = b
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return v.toFixed(2) + ' ' + units[i]
}

function protoTagType(p) {
  return { http: '', tcp: 'success', udp: 'warning', tcpudp: 'danger' }[p] || 'info'
}

onMounted(load)
</script>

<style scoped>
.stat-card { text-align: center; }
.stat-label { font-size: 13px; color: #909399; margin-bottom: 8px; }
.stat-value { font-size: 26px; font-weight: 600; color: #303133; }
</style>
