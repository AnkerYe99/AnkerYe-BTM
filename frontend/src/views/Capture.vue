<template>
  <div class="capture-page">
    <div class="page-header">
      <h2 style="margin:0">请求捕获</h2>
      <span class="header-sub">查看启用了「记录请求体」的规则捕获到的请求（含 POST body），可作回放/测试数据</span>
    </div>

    <el-card shadow="never" class="filter-card">
      <div class="filter-row">
        <el-select v-model="ruleId" placeholder="选择规则" style="width:240px" @change="load" filterable>
          <el-option v-for="r in rules" :key="r.id" :label="r.name" :value="r.id" />
        </el-select>
        <el-select v-model="search.method" placeholder="方法" clearable size="small" style="width:110px">
          <el-option v-for="m in methodOptions" :key="m" :label="m" :value="m" />
        </el-select>
        <el-input v-model="search.status" placeholder="状态码" clearable size="small" style="width:110px" />
        <el-input v-model="search.kw" placeholder="搜索 URI 或 Body 关键字" clearable size="small" style="width:240px" />
        <el-input-number v-model="limit" :min="50" :max="2000" :step="50" size="small" style="width:120px" @change="load" />
        <span style="color:#909399;font-size:12px">条</span>
        <el-button :icon="Refresh" @click="load" :loading="loading">刷新</el-button>
      </div>
      <div class="result-hint">
        <template v-if="!ruleId">请选择一个规则</template>
        <template v-else-if="data.capture_enabled === false">
          <el-tag type="warning" size="small">规则未启用 capture</el-tag>
          <span style="margin-left:8px">请到「转发规则 → 编辑 → 高级 → 记录请求体」开启</span>
        </template>
        <template v-else>
          共 <b>{{ filteredList.length }}</b> 条，最新在前
          <el-tag v-if="data.hint" type="info" size="small" style="margin-left:8px">{{ data.hint }}</el-tag>
        </template>
      </div>
    </el-card>

    <el-card shadow="never" class="table-card" v-loading="loading">
      <div style="overflow-x:auto">
        <el-table :data="filteredList" stripe size="small" style="width:100%" table-layout="auto" @row-click="openDetail">
          <el-table-column label="时间" min-width="170">
            <template #default="{row}">
              <span style="font-size:12px;color:#606266">{{ fmtTime(row.time) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="客户端 IP / 归属地" min-width="190">
            <template #default="{row}">
              <span>{{ row.ip }}</span>
              <span v-if="row.location" style="color:#909399;font-size:11px;margin-left:3px">/{{ row.location }}</span>
            </template>
          </el-table-column>
          <el-table-column label="方法" width="76">
            <template #default="{row}">
              <el-tag size="small" :type="methodType(row.method)" effect="plain">{{ row.method }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="URI" min-width="220" show-overflow-tooltip>
            <template #default="{row}"><code style="font-size:12px">{{ row.uri }}</code></template>
          </el-table-column>
          <el-table-column label="状态" min-width="76" align="center">
            <template #default="{row}">
              <el-tag :type="statusType(row.status)" size="small" effect="dark">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="耗时" min-width="100">
            <template #default="{row}">
              <span :style="{color: row.req_time>3?'#f56c6c':row.req_time>1?'#e6a23c':'#67c23a'}">
                {{ fmtDur(row.req_time) }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="上游节点" prop="upstream" min-width="148" show-overflow-tooltip />
          <el-table-column label="Content-Type" min-width="160" show-overflow-tooltip>
            <template #default="{row}">
              <span style="font-size:12px;color:#606266">{{ row.content_type || '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="Body 预览" min-width="220">
            <template #default="{row}">
              <span v-if="!row.body" style="color:#ccc">空</span>
              <span v-else style="font-family:monospace;font-size:12px;color:#606266">
                {{ row.body.length > 80 ? row.body.slice(0,80) + '...' : row.body }}
              </span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <!-- 详情弹窗 -->
    <el-dialog v-model="detailShow" title="请求详情" width="800px">
      <div v-if="current" class="detail">
        <div class="detail-row"><b>时间</b><span>{{ fmtTime(current.time) }}</span></div>
        <div class="detail-row"><b>客户端</b><span>{{ current.ip }} <span v-if="current.location" style="color:#909399">({{ current.location }})</span></span></div>
        <div class="detail-row"><b>方法</b><span>{{ current.method }}</span></div>
        <div class="detail-row"><b>URI</b><span><code>{{ current.uri }}</code></span></div>
        <div class="detail-row"><b>状态</b><span>{{ current.status }}</span></div>
        <div class="detail-row"><b>耗时</b><span>{{ fmtDur(current.req_time) }}（upstream: {{ current.up_time }}s）</span></div>
        <div class="detail-row"><b>upstream</b><span>{{ current.upstream }}</span></div>
        <div class="detail-row"><b>Content-Type</b><span>{{ current.content_type || '—' }}</span></div>
        <div class="detail-row"><b>User-Agent</b><span style="font-size:12px;color:#606266">{{ current.ua }}</span></div>
        <div class="detail-row" style="display:block">
          <b>Body</b>
          <div style="margin-top:6px">
            <el-input v-model="prettyBody" type="textarea" :rows="14" readonly
              style="font-family:'JetBrains Mono','Consolas',monospace;font-size:12px" />
          </div>
          <div style="margin-top:8px;display:flex;gap:8px">
            <el-button size="small" @click="copyBody">复制 Body</el-button>
            <el-button size="small" @click="copyAsCurl" type="primary">复制为 curl 命令</el-button>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import api from '../api'

const ruleId = ref(null)
const rules = ref([])
const loading = ref(false)
const limit = ref(200)
const search = ref({ method: '', status: '', kw: '' })
const data = ref({ capture_enabled: null, list: [], hint: '' })
const detailShow = ref(false)
const current = ref(null)

const methodOptions = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

const filteredList = computed(() => {
  let list = data.value.list || []
  if (search.value.method) list = list.filter(r => r.method === search.value.method)
  if (search.value.status) {
    const s = parseInt(search.value.status)
    if (!isNaN(s)) list = list.filter(r => r.status === s)
  }
  if (search.value.kw) {
    const kw = search.value.kw.toLowerCase()
    list = list.filter(r => (r.uri || '').toLowerCase().includes(kw) || (r.body || '').toLowerCase().includes(kw))
  }
  return list
})

const prettyBody = computed(() => {
  if (!current.value || !current.value.body) return '(空)'
  const body = current.value.body
  // 如果是 JSON 尝试格式化
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {}
  return body
})

async function loadRules() {
  rules.value = (await api.get('/rules/simple')).data || []
  if (rules.value.length && !ruleId.value) {
    ruleId.value = rules.value[0].id
    load()
  }
}

async function load() {
  if (!ruleId.value) return
  loading.value = true
  try {
    const params = { limit: limit.value }
    const res = await api.get(`/rules/${ruleId.value}/capture`, { params })
    data.value = res.data || { list: [] }
  } catch {
    data.value = { list: [], hint: '加载失败' }
  }
  loading.value = false
}

function openDetail(row) {
  current.value = row
  detailShow.value = true
}

function fmtTime(t) {
  if (!t) return '—'
  return t.replace('T', ' ').replace(/\+\d{2}:\d{2}$/, '').slice(0, 19)
}

function fmtDur(v) {
  if (v === null || v === undefined || v === '') return '—'
  const n = parseFloat(v)
  if (isNaN(n)) return v
  if (n < 0.001) return (n * 1000000).toFixed(0) + 'µs'
  if (n < 1) return (n * 1000).toFixed(0) + 'ms'
  return n.toFixed(2) + 's'
}

function methodType(m) {
  if (m === 'GET') return 'info'
  if (m === 'POST') return 'success'
  if (m === 'DELETE') return 'danger'
  return 'warning'
}

function statusType(s) {
  if (s >= 500) return 'danger'
  if (s >= 400) return 'warning'
  if (s >= 300) return 'info'
  return 'success'
}

async function copyBody() {
  if (!current.value) return
  await navigator.clipboard.writeText(current.value.body || '')
  ElMessage.success('Body 已复制')
}

async function copyAsCurl() {
  if (!current.value) return
  const r = current.value
  const proto = r.uri.startsWith('http') ? '' : 'http://example.com'
  let cmd = `curl -X ${r.method} '${proto}${r.uri}'`
  if (r.content_type) cmd += ` \\\n  -H 'Content-Type: ${r.content_type}'`
  if (r.ua) cmd += ` \\\n  -H 'User-Agent: ${r.ua}'`
  if (r.body) {
    const escaped = r.body.replace(/'/g, "'\\''")
    cmd += ` \\\n  -d '${escaped}'`
  }
  await navigator.clipboard.writeText(cmd)
  ElMessage.success('curl 命令已复制')
}

onMounted(loadRules)
</script>

<style scoped>
.capture-page { padding-bottom: 40px; }
.page-header { display: flex; align-items: baseline; gap: 16px; margin-bottom: 16px; }
.header-sub { font-size: 12px; color: #909399; }
.filter-card { margin-bottom: 12px; }
.filter-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.result-hint { margin-top: 10px; font-size: 13px; color: #606266; }
.detail-row { display: flex; padding: 4px 0; gap: 12px; }
.detail-row b { width: 110px; color: #606266; flex-shrink: 0; }
.detail-row span { color: #303133; }
</style>
