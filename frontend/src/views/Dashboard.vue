<template>
  <div class="dashboard">

    <!-- 系统资源（最顶部）-->
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :xs="24" :sm="8">
        <el-card shadow="never" class="res-card">
          <div class="res-title"><el-icon><Cpu /></el-icon> 系统负载 <span class="uptime-inline">运行时长 {{ uptime(sys.uptime_sec) }}</span></div>
          <div class="load-row">
            <div v-for="(v,label) in {' 1分钟':sys.load1,' 5分钟':sys.load5,'15分钟':sys.load15}" :key="label" class="load-item">
              <div class="load-val" :style="{color: loadColor(v)}">{{ v?.toFixed(2) ?? '—' }}</div>
              <div class="load-label">{{ label }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card shadow="never" class="res-card">
          <div class="res-title"><el-icon><Memo /></el-icon> 内存使用</div>
          <div class="mem-bar-wrap">
            <el-progress :percentage="memPct" :color="memPct>85?'#f56c6c':memPct>70?'#e6a23c':'#67c23a'"
              :stroke-width="10" style="margin:10px 0 6px" />
          </div>
          <div class="res-sub">进程已用 {{ fmtBytes(sys.mem_used) }} · 可用 {{ fmtBytes(sys.mem_available) }}</div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card shadow="never" class="res-card">
          <div class="res-title"><el-icon><Monitor /></el-icon> 服务状态</div>
          <div class="service-row">
            <div class="svc-item">
              <div class="svc-val blue">{{ sys.go_goroutines ?? '—' }}</div>
              <div class="svc-lbl">Go 协程</div>
            </div>
            <div class="svc-item">
              <div class="svc-val">{{ fmtBytes(sys.go_heap_alloc) }}</div>
              <div class="svc-lbl">堆内存</div>
            </div>
            <div class="svc-item">
              <el-tag type="success" effect="dark" size="small">运行中</el-tag>
              <div class="svc-lbl" style="margin-top:6px">AnkerYe - 流量管理</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 两张宽卡 -->
    <el-row :gutter="16" style="margin-bottom:16px">
      <!-- 左卡：系统概况 -->
      <el-col :xs="24" :md="12">
        <el-card shadow="never" class="wide-card">
          <div class="wide-card-items">
            <div class="wc-item">
              <div class="wc-label">活跃规则</div>
              <div class="wc-val">{{ stats.rule_count || 0 }}</div>
              <div class="wc-sub">条转发规则</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">后端节点</div>
              <div class="wc-val" :class="(stats.up_count||0)<(stats.server_count||0)?'warn':''">
                {{ stats.up_count||0 }} / {{ stats.server_count||0 }}
              </div>
              <div class="wc-sub">在线 / 总数</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">节点健康率</div>
              <div class="wc-val" :class="(stats.health_rate||100)<80?'danger':''">
                {{ Math.round(stats.health_rate||0) }}%
              </div>
              <div class="wc-sub">健康检测</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">SSL 证书</div>
              <div class="wc-val" :class="(stats.cert_expiring||0)>0?'warn':''">
                {{ stats.cert_count||0 }}
              </div>
              <div class="wc-sub" :class="(stats.cert_expiring||0)>0?'warn-text':''">
                {{ (stats.cert_expiring||0)>0 ? (stats.cert_expiring+' 个即将到期') : '全部正常' }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <!-- 右卡：流量统计 -->
      <el-col :xs="24" :md="12">
        <el-card shadow="never" class="wide-card">
          <div class="wide-card-items">
            <div class="wc-item">
              <div class="wc-label">近24小时请求</div>
              <div class="wc-val">{{ fmtNum(h24Traffic.requests) }}</div>
              <div class="wc-sub">含昨今两天</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">近24小时流量</div>
              <div class="wc-val">{{ fmtBytes(h24Traffic.bytes_out) }}</div>
              <div class="wc-sub">出站</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">今日请求</div>
              <div class="wc-val">{{ fmtNum(todayTraffic.requests) }}</div>
              <div class="wc-sub" :class="todaySuccessRate<90?'danger-text':'ok-text'">成功率 {{ todaySuccessRate }}%</div>
            </div>
            <div class="wc-divider" />
            <div class="wc-item">
              <div class="wc-label">今日流量</div>
              <div class="wc-val">{{ fmtBytes(todayTraffic.bytes_out) }}</div>
              <div class="wc-sub" :class="(todayTraffic.s4xx+todayTraffic.s5xx)>0?'warn-text':''">
                4xx+5xx {{ fmtNum(todayTraffic.s4xx+todayTraffic.s5xx) }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 节点健康状态（全宽表格）-->
    <el-card shadow="never" style="margin-bottom:16px">
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span><el-icon style="vertical-align:-2px"><Connection /></el-icon> 节点健康状态</span>
          <div style="display:flex;gap:8px;align-items:center">
            <el-button size="small" :type="sortByReq?'primary':'default'" @click="sortByReq=!sortByReq">
              {{ sortByReq ? '▼ 浏览量排序' : '默认排序' }}
            </el-button>
            <el-button size="small" icon="Refresh" @click="load" :loading="loading">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="serverRows" size="small" :span-method="spanMethod"
        :row-class-name="rowClassName" border style="width:100%">
        <el-table-column label="规则名" prop="rule_name" min-width="120">
          <template #default="{row}">
            <div class="rule-cell">
              <span class="rule-cell-name">{{ row.rule_name }}</span>
              <el-tag v-if="ruleDownMap[row.rule_id]>0" type="danger" size="small" effect="plain" style="margin-left:6px">
                {{ ruleDownMap[row.rule_id] }} 下线
              </el-tag>
              <el-tag v-else type="success" size="small" effect="plain" style="margin-left:6px">健康</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="节点地址" min-width="170">
          <template #default="{row}">
            <span class="mono">{{ row.address }}:{{ row.port }}</span>
            <span class="weight-badge">w{{ row.weight }}</span>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="78" align="center">
          <template #default="{row}">
            <el-tag v-if="row.state==='up'" type="success" size="small" effect="dark">正常</el-tag>
            <el-tag v-else-if="row.state==='down'" type="danger" size="small" effect="dark">异常</el-tag>
            <el-tag v-else type="info" size="small">禁用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="今天访问" width="90" align="right">
          <template #default="{row}">
            <span :class="row.today_req?'num-active':'num-zero'">{{ fmtNum(row.today_req) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="今天流量" width="100" align="right">
          <template #default="{row}">
            <span :class="row.today_bytes?'num-active':'num-zero'">{{ fmtBytes(row.today_bytes) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="7天访问" width="90" align="right">
          <template #default="{row}">
            <span :class="row.d7_req?'num-active':'num-zero'">{{ fmtNum(row.d7_req) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="7天流量" width="100" align="right">
          <template #default="{row}">
            <span :class="row.d7_bytes?'num-active':'num-zero'">{{ fmtBytes(row.d7_bytes) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="30天访问" width="90" align="right">
          <template #default="{row}">
            <span :class="row.d30_req?'num-active':'num-zero'">{{ fmtNum(row.d30_req) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="30天流量" width="100" align="right">
          <template #default="{row}">
            <span :class="row.d30_bytes?'num-active':'num-zero'">{{ fmtBytes(row.d30_bytes) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="最后检测" width="150" align="center">
          <template #default="{row}">
            <span style="color:#909399;font-size:12px">{{ row.last_check_at || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="错误信息" min-width="120">
          <template #default="{row}">
            <span v-if="row.last_err" class="err-text" :title="row.last_err">⚠ {{ row.last_err.slice(0,50) }}</span>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="!loading && serverRows.length===0" class="empty-tip">暂无节点数据</div>
    </el-card>

    <!-- SSL 证书 -->
    <el-card shadow="never">
      <template #header>
        <span><el-icon style="vertical-align:-2px"><Lock /></el-icon> SSL 证书到期</span>
      </template>
      <div v-if="certList.length===0" class="empty-tip">无证书记录</div>
      <el-row :gutter="16">
        <el-col v-for="cert in certList" :key="cert.id" :xs="12" :sm="8" :md="6" :lg="4">
          <div class="cert-item">
            <div class="cert-domain">{{ cert.domain }}</div>
            <el-tag :type="cert.days<=10?'danger':cert.days<=30?'warning':'success'" size="small">
              {{ cert.days <= 0 ? '已过期' : cert.days + ' 天' }}
            </el-tag>
          </div>
        </el-col>
      </el-row>
    </el-card>

  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import api from '../api'

const stats        = ref({})
const serverHealth = ref([])
const sys          = ref({})
const certs        = ref([])
const traffic      = ref([])
const traffic24h   = ref([])
const loading      = ref(false)
let timer = null

async function load() {
  loading.value = true
  const [ov, sh, sy, ce, tr, tr24] = await Promise.allSettled([
    api.get('/stats/overview'),
    api.get('/stats/server_health'),
    api.get('/stats/system'),
    api.get('/certs'),
    api.get('/stats/traffic', { params: { period: 'today' } }),
    api.get('/stats/traffic', { params: { period: '24h' } }),
  ])
  const val = r => r.status === 'fulfilled' ? r.value : null
  if (val(ov))   stats.value        = val(ov).data  || {}
  if (val(sh))   serverHealth.value = val(sh).data  || []
  if (val(sy))   sys.value          = val(sy).data  || {}
  if (val(ce))   certs.value        = val(ce).data  || []
  if (val(tr))   traffic.value      = val(tr).data  || []
  if (val(tr24)) traffic24h.value   = val(tr24).data || []
  loading.value = false
}

// 内存
const memPct = computed(() => {
  if (!sys.value.mem_total) return 0
  // mem_used = mem_total - mem_available（内核计算的真实进程占用，排除 cache）
  return Math.round(sys.value.mem_used / sys.value.mem_total * 100)
})
function loadColor(v) {
  if (!v && v !== 0) return '#909399'
  return v > 4 ? '#f56c6c' : v > 2 ? '#e6a23c' : '#67c23a'
}

// 核心指标卡片
const h24Traffic = computed(() => traffic24h.value.reduce((acc, r) => {
  acc.requests  += r.requests  || 0
  acc.bytes_out += r.bytes_out || 0
  return acc
}, { requests: 0, bytes_out: 0 }))

const sortByReq = ref(true)

// 按规则今日请求总量排序后展开的扁平列表，保持同规则节点连续
const sortedServerHealth = computed(() => {
  const raw = serverHealth.value
  if (!sortByReq.value) return raw
  // 按 rule_id 分组
  const groups = []
  const seen = {}
  for (const r of raw) {
    if (!seen[r.rule_id]) { seen[r.rule_id] = []; groups.push(seen[r.rule_id]) }
    seen[r.rule_id].push(r)
  }
  // 每组按 today_req 总和排序
  groups.sort((a, b) =>
    b.reduce((s, r) => s + r.today_req, 0) - a.reduce((s, r) => s + r.today_req, 0)
  )
  return groups.flat()
})

// 节点表格数据
const serverRows = computed(() => sortedServerHealth.value.slice(0, 10))

// 每条规则的下线节点数
const ruleDownMap = computed(() => {
  const m = {}
  for (const r of serverHealth.value) {
    if (!m[r.rule_id]) m[r.rule_id] = 0
    if (r.state === 'down') m[r.rule_id]++
  }
  return m
})

// el-table span-method：规则名列按规则分组合并行
const spanMap = computed(() => {
  const map = {}
  const rows = sortedServerHealth.value
  let i = 0
  while (i < rows.length) {
    const ruleId = rows[i].rule_id
    let count = 0
    let j = i
    while (j < rows.length && rows[j].rule_id === ruleId) { count++; j++ }
    map[i] = { rowspan: count, colspan: 1 }
    for (let k = i + 1; k < j; k++) map[k] = { rowspan: 0, colspan: 0 }
    i = j
  }
  return map
})

function spanMethod({ rowIndex, columnIndex }) {
  if (columnIndex === 0) return spanMap.value[rowIndex] || { rowspan: 0, colspan: 0 }
  return { rowspan: 1, colspan: 1 }
}

function rowClassName({ row }) {
  return row.state === 'down' ? 'row-down' : ''
}

// 证书（按到期天数排序）
const certList = computed(() =>
  certs.value.map(c => ({
    ...c,
    days: Math.ceil((new Date(c.expire_at) - new Date()) / 86400000)
  })).sort((a, b) => a.days - b.days)
)

// 今日流量汇总
const todayTraffic = computed(() => traffic.value.reduce((acc, r) => {
  acc.requests  += r.requests  || 0
  acc.bytes_out += r.bytes_out || 0
  acc.s2xx += r.s2xx || 0
  acc.s4xx += r.s4xx || 0
  acc.s5xx += r.s5xx || 0
  return acc
}, { requests: 0, bytes_out: 0, s2xx: 0, s4xx: 0, s5xx: 0 }))

const todaySuccessRate = computed(() => {
  const t = todayTraffic.value
  if (!t.requests) return 100
  return Math.round(t.s2xx / t.requests * 1000) / 10
})

function fmtBytes(b) {
  if (!b) return '0 B'
  const units = ['B','KB','MB','GB','TB']
  let i = 0; let v = b
  while (v >= 1024 && i < 4) { v /= 1024; i++ }
  return v.toFixed(1) + ' ' + units[i]
}
function fmtNum(n) {
  if (!n) return '0'
  if (n >= 1e8) return (n/1e8).toFixed(1)+'亿'
  if (n >= 1e4) return (n/1e4).toFixed(1)+'万'
  return n.toLocaleString()
}
function uptime(s) {
  if (!s) return '—'
  const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60)
  return d ? `${d}天${h}时${m}分` : `${h}时${m}分`
}

onMounted(() => {
  // 延迟 200ms：让浏览器先完成 JS/CSS 资源加载，释放 HTTP/1.1 连接后再发 API 请求
  setTimeout(() => { load(); timer = setInterval(load, 15000) }, 200)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.dashboard { padding-bottom: 24px; }

/* 系统资源卡片 */
.res-card { height: 130px; }
.res-title { font-size: 13px; color: #606266; display: flex; align-items: center; gap: 4px; margin-bottom: 10px; flex-wrap: wrap; }
.uptime-inline { margin-left: auto; font-size: 12px; color: #909399; font-weight: 400; }
.load-row { display: flex; justify-content: space-around; margin: 4px 0; }
.load-item { text-align: center; }
.load-val { font-size: 22px; font-weight: 700; }
.load-label { font-size: 11px; color: #909399; margin-top: 2px; }
.mem-bar-wrap { padding: 0 4px; }
.res-sub { font-size: 12px; color: #909399; margin-top: 4px; text-align: center; }
.service-row { display: flex; justify-content: space-around; align-items: center; margin-top: 6px; }
.svc-item { text-align: center; }
.svc-val { font-size: 20px; font-weight: 700; color: #303133; }
.svc-val.blue { color: #409eff; }
.svc-lbl { font-size: 11px; color: #909399; margin-top: 4px; }

/* 宽卡 */
.wide-card :deep(.el-card__body) { padding: 0; }
.wide-card-items { display: flex; align-items: stretch; }
.wc-item { flex: 1; padding: 16px 12px; text-align: center; }
.wc-divider { width: 1px; background: #f0f0f0; flex-shrink: 0; margin: 12px 0; }
.wc-label { font-size: 12px; color: #909399; margin-bottom: 8px; white-space: nowrap; }
.wc-val { font-size: 24px; font-weight: 700; color: #303133; line-height: 1.2; }
.wc-val.warn { color: #e6a23c; }
.wc-val.danger { color: #f56c6c; }
.wc-sub { font-size: 11px; color: #c0c4cc; margin-top: 6px; white-space: nowrap; }
.warn-text { color: #e6a23c !important; }
.danger-text { color: #f56c6c !important; }
.ok-text { color: #67c23a !important; }

/* 节点表格 */
.rule-cell { display: flex; align-items: center; }
.rule-cell-name { font-weight: 600; color: #303133; font-size: 13px; }
.mono { font-family: monospace; color: #303133; }
.weight-badge { font-size: 10px; color: #c0c4cc; background: #f5f5f5;
  border-radius: 3px; padding: 0 4px; margin-left: 6px; line-height: 18px; }
.num-active { color: #303133; font-weight: 500; }
.num-zero { color: #c0c4cc; }
.err-text { color: #f56c6c; font-size: 12px; }
:deep(.row-down td) { background: #fff5f5 !important; }

/* 证书 */
.cert-item { padding: 8px 4px; display: flex; flex-direction: column; gap: 6px; }
.cert-domain { font-size: 12px; color: #303133; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.empty-tip { text-align: center; color: #c0c4cc; padding: 20px 0; font-size: 13px; }
</style>
