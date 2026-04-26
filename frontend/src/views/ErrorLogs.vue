<template>
  <div class="errorlog-page">
    <div class="page-header">
      <h2 style="margin:0">出错日志</h2>
      <span class="header-sub">nginx access log 中状态码 ≥ 400 的请求，按日期范围查询</span>
    </div>

    <!-- 筛选栏 -->
    <el-card shadow="never" class="filter-card">
      <div class="filter-row">
        <el-date-picker
          v-model="filter.dateRange"
          type="daterange"
          range-separator="至"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
          format="YYYY-MM-DD"
          value-format="YYYY-MM-DD"
          :clearable="false"
          style="width:240px"
          @change="load"
        />

        <el-select v-model="filter.ruleId" placeholder="全部规则" clearable style="width:180px" @change="load">
          <el-option v-for="r in rules" :key="r.id" :label="r.name" :value="r.id" />
        </el-select>

        <el-radio-group v-model="filter.code" @change="load">
          <el-radio-button value="all">全部错误</el-radio-button>
          <el-radio-button value="4xx">4xx 客户端</el-radio-button>
          <el-radio-button value="5xx">5xx 服务端</el-radio-button>
        </el-radio-group>

        <el-button :icon="Refresh" @click="load" :loading="loading">刷新</el-button>
        <el-switch v-model="autoRefresh" active-text="自动刷新" @change="toggleAuto" />
      </div>

      <div v-if="list.length > 0" class="result-hint">
        共 <b>{{ list.length }}</b> 条错误记录
        <span v-if="stat4xx || stat5xx" style="margin-left:16px">
          <el-tag type="danger" size="small" style="margin-right:6px" v-if="stat444">拦截 {{ stat444 }}</el-tag>
          <el-tag type="warning" size="small" style="margin-right:6px" v-if="stat4xx">4xx {{ stat4xx }}</el-tag>
          <el-tag type="danger" size="small" v-if="stat5xx">5xx {{ stat5xx }}</el-tag>
        </span>
      </div>
    </el-card>

    <!-- 表格 -->
    <el-card shadow="never" class="table-card" v-loading="loading">
      <el-table :data="pagedList" stripe size="small" style="width:100%" :row-class-name="rowClass">
        <el-table-column label="时间" prop="time" width="165" fixed />
        <el-table-column label="规则" prop="rule_name" width="130" show-overflow-tooltip />
        <el-table-column label="客户端 IP" prop="ip" width="145" />
        <el-table-column label="方法" prop="method" width="70">
          <template #default="{row}">
            <el-tag size="small" :type="methodType(row.method)" effect="plain">{{ row.method }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="请求路径" prop="path" min-width="220" show-overflow-tooltip />
        <el-table-column label="状态码" prop="status" width="90">
          <template #default="{row}">
            <el-tag v-if="row.status===444" type="danger" size="small" effect="dark" style="font-weight:700;letter-spacing:1px">
              拦截
            </el-tag>
            <el-tag v-else :type="row.status>=500?'danger':'warning'" size="small" effect="dark">
              {{ row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="80">
          <template #default="{row}">{{ fmtBytes(row.bytes) }}</template>
        </el-table-column>
        <el-table-column label="上游节点" prop="upstream" width="165" show-overflow-tooltip />
        <el-table-column label="User-Agent" prop="ua" min-width="180" show-overflow-tooltip />
      </el-table>

      <div v-if="!loading && list.length === 0" class="empty-hint">
        <el-empty description="所选日期范围内暂无出错记录" />
      </div>
      <Pagination :total="list.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30

function fmtLocalDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}
function today() {
  return fmtLocalDate(new Date())
}
function daysAgo(n) {
  const d = new Date()
  d.setDate(d.getDate() - n)
  return fmtLocalDate(d)
}

const filter = ref({
  ruleId: null,
  code: 'all',
  dateRange: [daysAgo(6), today()]
})
const rules = ref([])
const list = ref([])
const loading = ref(false)
const autoRefresh = ref(false)
const page = ref(1)
let timer = null

const stat444 = computed(() => list.value.filter(r => r.status === 444).length)
const stat4xx = computed(() => list.value.filter(r => r.status >= 400 && r.status < 500 && r.status !== 444).length)
const stat5xx = computed(() => list.value.filter(r => r.status >= 500).length)
const pagedList = computed(() => list.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))

async function load() {
  loading.value = true
  page.value = 1
  try {
    const [start, end] = filter.value.dateRange || [daysAgo(6), today()]
    const params = { code: filter.value.code, start, end }
    if (filter.value.ruleId) params.rule_id = filter.value.ruleId
    const res = await api.get('/stats/errors', { params })
    list.value = res.data.list || []
  } catch {}
  loading.value = false
}

async function loadRules() {
  const res = await api.get('/rules/simple')
  rules.value = res.data || []
}

function toggleAuto(val) {
  clearInterval(timer)
  if (val) timer = setInterval(load, 30000)
}

function rowClass({ row }) {
  if (row.status === 444) return 'row-444'
  return row.status >= 500 ? 'row-5xx' : 'row-4xx'
}

function methodType(m) {
  if (m === 'GET') return 'info'
  if (m === 'POST') return 'success'
  if (m === 'DELETE') return 'danger'
  return 'warning'
}

function fmtBytes(b) {
  if (!b) return '0'
  if (b < 1024) return b + 'B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + 'K'
  return (b / 1024 / 1024).toFixed(1) + 'M'
}

onMounted(async () => {
  await loadRules()
  await load()
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.errorlog-page { padding-bottom: 40px; }
.page-header {
  display: flex;
  align-items: baseline;
  gap: 16px;
  margin-bottom: 16px;
}
.header-sub {
  font-size: 12px;
  color: #909399;
}
.filter-card { margin-bottom: 12px; }
.filter-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.result-hint {
  margin-top: 10px;
  font-size: 13px;
  color: #606266;
}
.table-card { }
.empty-hint { padding: 40px 0; }
:deep(.row-444) { background: #fff0f0 !important; }
:deep(.row-444 td) { color: #cf1322 !important; font-weight: 500; }
:deep(.row-444:hover > td) { background: #ffd6d6 !important; }
:deep(.row-5xx) { background: #fff2f0 !important; }
:deep(.row-5xx:hover > td) { background: #ffe4e0 !important; }
:deep(.row-4xx) { }
</style>
