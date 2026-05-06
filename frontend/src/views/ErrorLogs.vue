<template>
  <div class="errorlog-page">
    <div class="page-header">
      <h2 style="margin:0">出错日志</h2>
      <span class="header-sub">nginx access log 中状态码 ≥ 400 的请求，按日期范围查询</span>
    </div>

    <!-- 筛选栏 -->
    <el-card shadow="never" class="filter-card">
      <!-- 第一行：日期/规则/状态码组/操作 -->
      <div class="filter-row">
        <el-date-picker v-model="filter.startDate" type="date" placeholder="开始日期"
          format="YYYY-MM-DD" value-format="YYYY-MM-DD" size="small" style="width:118px" @change="load" />
        <span style="color:#909399;font-size:12px;padding:0 2px">~</span>
        <el-date-picker v-model="filter.endDate" type="date" placeholder="结束日期"
          format="YYYY-MM-DD" value-format="YYYY-MM-DD" size="small" style="width:118px" @change="load" />

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

      <!-- 第二行：细粒度搜索 -->
      <div class="filter-row" style="margin-top:10px">
        <el-input v-model="search.ip" placeholder="客户端 IP" clearable size="small" style="width:150px" />
        <el-select v-model="search.method" placeholder="方法" clearable size="small" style="width:110px">
          <el-option v-for="m in methodOptions" :key="m" :label="m" :value="m" />
        </el-select>
        <el-input v-model="search.status" placeholder="状态码" clearable size="small" style="width:100px" />
        <el-input v-model="search.upstream" placeholder="上游节点" clearable size="small" style="width:160px" />
        <el-button size="small" @click="resetSearch">重置搜索</el-button>
      </div>

      <div class="result-hint">
        <template v-if="filteredList.length !== list.length">
          筛选 <b>{{ filteredList.length }}</b> 条 / 共 <b>{{ list.length }}</b> 条错误记录
        </template>
        <template v-else-if="list.length > 0">
          共 <b>{{ list.length }}</b> 条错误记录
        </template>
        <span v-if="stat444 || stat4xx || stat5xx" style="margin-left:16px">
          <el-tag type="danger" size="small" style="margin-right:6px" v-if="stat444">拦截 {{ stat444 }}</el-tag>
          <el-tag type="warning" size="small" style="margin-right:6px" v-if="stat4xx">4xx {{ stat4xx }}</el-tag>
          <el-tag type="danger" size="small" v-if="stat5xx">5xx {{ stat5xx }}</el-tag>
        </span>
      </div>
    </el-card>

    <!-- 表格 -->
    <el-card shadow="never" class="table-card" v-loading="loading">
      <el-table :data="pagedList" stripe size="small" style="width:100%" :row-class-name="rowClass" table-layout="fixed">
        <el-table-column label="规则" prop="rule_name" min-width="100" show-overflow-tooltip fixed />
        <el-table-column label="客户端 IP / 归属地" min-width="190">
          <template #default="{row}">
            <span>{{ row.ip }}</span>
            <span v-if="row.location" style="color:#909399;font-size:11px;margin-left:3px">/{{ row.location }}</span>
          </template>
        </el-table-column>
        <el-table-column label="方法" width="72">
          <template #default="{row}">
            <el-tag size="small" :type="methodType(row.method)" effect="plain">{{ row.method }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="请求路径" prop="path" min-width="200" show-overflow-tooltip />
        <el-table-column label="状态" width="76">
          <template #default="{row}">
            <el-tag v-if="row.status===444" type="danger" size="small" effect="dark" style="font-weight:700;letter-spacing:1px">拦截</el-tag>
            <el-tag v-else :type="row.status>=500?'danger':'warning'" size="small" effect="dark">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="72">
          <template #default="{row}">{{ fmtBytes(row.bytes) }}</template>
        </el-table-column>
        <el-table-column label="上游节点" prop="upstream" min-width="148" show-overflow-tooltip />
        <el-table-column label="时间" prop="time" width="152" />
        <el-table-column label="User-Agent" prop="ua" min-width="200" show-overflow-tooltip />
      </el-table>

      <div v-if="!loading && filteredList.length === 0" class="empty-hint">
        <el-empty :description="list.length === 0 ? '所选日期范围内暂无出错记录' : '无匹配记录'" />
      </div>
      <Pagination :total="filteredList.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30

function fmtLocalDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}
function today() { return fmtLocalDate(new Date()) }
function daysAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return fmtLocalDate(d) }

const filter = ref({ ruleId: null, code: 'all', startDate: daysAgo(6), endDate: today() })
const search = ref({ ip: '', method: '', status: '', upstream: '' })
const rules = ref([])
const list = ref([])
const loading = ref(false)
const autoRefresh = ref(false)
const page = ref(1)
let timer = null

const methodOptions = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'PRI', 'PROPFIND', 'MGLNDD']

const stat444 = computed(() => list.value.filter(r => r.status === 444).length)
const stat4xx = computed(() => list.value.filter(r => r.status >= 400 && r.status < 500 && r.status !== 444).length)
const stat5xx = computed(() => list.value.filter(r => r.status >= 500).length)

const filteredList = computed(() => {
  let r = list.value
  const { ip, method, status, upstream } = search.value
  if (ip) r = r.filter(x => (x.ip || '').includes(ip.trim()))
  if (method) r = r.filter(x => x.method === method)
  if (status) {
    const s = parseInt(status)
    if (!isNaN(s)) r = r.filter(x => x.status === s)
  }
  if (upstream) r = r.filter(x => (x.upstream || '').includes(upstream.trim()))
  return r
})

const pagedList = computed(() => filteredList.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))

watch(search, () => { page.value = 1 }, { deep: true })

function resetSearch() {
  search.value = { ip: '', method: '', status: '', upstream: '' }
}

async function load() {
  loading.value = true
  page.value = 1
  try {
    const start = filter.value.startDate || daysAgo(6)
    const end = filter.value.endDate || today()
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

onMounted(async () => { await loadRules(); await load() })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.errorlog-page { padding-bottom: 40px; }
.page-header { display: flex; align-items: baseline; gap: 16px; margin-bottom: 16px; }
.header-sub { font-size: 12px; color: #909399; }
.filter-card { margin-bottom: 12px; }
.filter-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.result-hint { margin-top: 10px; font-size: 13px; color: #606266; }
.table-card { }
.empty-hint { padding: 40px 0; }
:deep(.row-444) { background: #fff0f0 !important; }
:deep(.row-444 td) { color: #cf1322 !important; font-weight: 500; }
:deep(.row-444:hover > td) { background: #ffd6d6 !important; }
:deep(.row-5xx) { background: #fff2f0 !important; }
:deep(.row-5xx:hover > td) { background: #ffe4e0 !important; }
:deep(.row-4xx) { }
</style>
