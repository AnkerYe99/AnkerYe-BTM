<template>
  <div>
    <h2>系统总览</h2>
    <el-row :gutter="16">
      <el-col :span="6"><el-card><div class="stat"><div class="label">规则总数</div><div class="num">{{ stats.rule_count || 0 }}</div></div></el-card></el-col>
      <el-col :span="6"><el-card><div class="stat"><div class="label">后端节点</div><div class="num">{{ stats.server_count || 0 }}</div></div></el-card></el-col>
      <el-col :span="6"><el-card><div class="stat"><div class="label">健康率</div><div class="num" :class="{red: stats.health_rate < 80}">{{ Math.round(stats.health_rate || 0) }}%</div></div></el-card></el-col>
      <el-col :span="6"><el-card><div class="stat"><div class="label">证书10天内到期</div><div class="num" :class="{red: stats.cert_expiring > 0}">{{ stats.cert_expiring || 0 }}</div></div></el-card></el-col>
    </el-row>

    <el-card style="margin-top:16px">
      <template #header>
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span>节点健康状态</span>
          <el-button size="small" @click="load">刷新</el-button>
        </div>
      </template>
      <el-table :data="health" size="small">
        <el-table-column prop="rule_name" label="规则" />
        <el-table-column label="节点">
          <template #default="{row}">{{ row.address }}:{{ row.port }}</template>
        </el-table-column>
        <el-table-column prop="weight" label="权重" width="80" />
        <el-table-column label="状态" width="120">
          <template #default="{row}">
            <el-tag v-if="row.state==='up'" type="success">UP</el-tag>
            <el-tag v-else-if="row.state==='down'" type="danger">DOWN</el-tag>
            <el-tag v-else type="info">DISABLED</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_check_at" label="最后检查" width="180" />
        <el-table-column prop="last_err" label="错误" show-overflow-tooltip />
      </el-table>
    </el-card>

    <el-card style="margin-top:16px">
      <template #header>系统资源</template>
      <el-descriptions :column="3" border>
        <el-descriptions-item label="内存使用">{{ fmt(sys.mem_used) }} / {{ fmt(sys.mem_total) }}</el-descriptions-item>
        <el-descriptions-item label="负载(1/5/15min)">{{ sys.load1?.toFixed(2) }} / {{ sys.load5?.toFixed(2) }} / {{ sys.load15?.toFixed(2) }}</el-descriptions-item>
        <el-descriptions-item label="运行时间">{{ uptime(sys.uptime_sec) }}</el-descriptions-item>
        <el-descriptions-item label="Go 协程">{{ sys.go_goroutines }}</el-descriptions-item>
        <el-descriptions-item label="Go 堆内存">{{ fmt(sys.go_heap_alloc) }}</el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import api from '../api'

const stats = ref({})
const health = ref([])
const sys = ref({})
let timer = null

async function load() {
  try {
    stats.value = (await api.get('/stats/overview')).data
    health.value = (await api.get('/stats/health')).data
    sys.value = (await api.get('/stats/system')).data
  } catch {}
}
function fmt(b) {
  if (!b) return '0'
  const u = ['B','KB','MB','GB']
  let i = 0; while (b >= 1024 && i < 3) { b /= 1024; i++ }
  return b.toFixed(1) + u[i]
}
function uptime(s) {
  if (!s) return '-'
  const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60)
  return `${d}天${h}时${m}分`
}
onMounted(() => { load(); timer = setInterval(load, 10000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.stat { text-align: center; padding: 10px 0; }
.stat .label { color: #909399; font-size: 13px; margin-bottom: 8px; }
.stat .num { font-size: 32px; font-weight: bold; color: #1890ff; }
.stat .num.red { color: #f56c6c; }
</style>
