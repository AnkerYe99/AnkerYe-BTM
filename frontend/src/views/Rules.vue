<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
      <h2 style="margin:0">转发规则</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <el-input v-model="search" placeholder="搜索名称/域名/地址" clearable style="width:220px" prefix-icon="Search" />
        <el-button type="primary" icon="Plus" @click="$router.push('/rules/new')">新建规则</el-button>
      </div>
    </div>
    <el-card>
      <div style="overflow-x:auto">
        <el-table :data="filteredList" size="small" v-loading="loading">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="name" label="名称" min-width="120" />
          <el-table-column label="类型" width="70">
            <template #default="{row}">
              <el-tag :type="protoTagType(row.protocol)" size="small">{{ row.protocol.toUpperCase() }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="端口" width="180">
            <template #default="{row}">
              <span v-if="row.protocol==='http'">
                <el-tag size="small" type="info">HTTP:{{ row.listen_port }}</el-tag>
                <el-tag v-if="row.https_enabled===1" size="small" type="success" style="margin-left:4px">
                  HTTPS:{{ row.https_port }}
                </el-tag>
              </span>
              <span v-else>
                {{ row.listen_port }}
                <el-tag size="small" :type="stackType(row.listen_stack)" style="margin-left:4px">
                  {{ stackLabel(row.listen_stack) }}
                </el-tag>
              </span>
            </template>
          </el-table-column>
          <el-table-column prop="server_name" label="域名" min-width="140" />
          <el-table-column prop="addresses" label="后端地址" min-width="160" show-overflow-tooltip />
          <el-table-column label="均衡算法" width="100">
            <template #default="{row}">
              {{ lbLabel(row.lb_method) }}
            </template>
          </el-table-column>
          <el-table-column label="节点" width="90">
            <template #default="{row}">
              <el-tooltip :content="`${row.up_count} 个在线 / 共 ${row.server_count} 个`" placement="top">
                <el-tag :type="row.up_count===0?'danger': row.up_count<row.server_count?'warning':'success'" size="small">
                  {{ row.up_count }}/{{ row.server_count }} 在线
                </el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="80">
            <template #default="{row}">
              <el-tag v-if="row.status===1" type="success" size="small">启用</el-tag>
              <el-tag v-else type="info" size="small">禁用</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="210">
            <template #default="{row}">
              <el-button size="small" @click="$router.push(`/rules/${row.id}/edit`)">编辑</el-button>
              <el-button v-if="row.status===1" size="small" @click="toggle(row,0)">禁用</el-button>
              <el-button v-else size="small" type="success" @click="toggle(row,1)">启用</el-button>
              <el-dropdown size="small" @command="handleCmd($event, row)" style="margin-left:6px">
                <el-button size="small">更多<el-icon class="el-icon--right"><ArrowDown/></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="preview">预览配置</el-dropdown-item>
                    <el-dropdown-item command="log">实时日志</el-dropdown-item>
                    <el-dropdown-item command="del" divided style="color:#f56c6c">删除</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-card>

    <el-dialog v-model="previewShow" title="nginx 配置预览" width="700px">
      <pre class="preview">{{ previewText }}</pre>
    </el-dialog>

    <el-drawer v-model="logShow" :title="`实时日志 — ${logRule?.name}`"
      size="70%" direction="btt" @close="closeLog">
      <div class="log-toolbar">
        <el-tag type="info" size="small">{{ logLines.length }} 行</el-tag>
        <el-switch v-model="logPaused" active-text="暂停" inactive-text="实时"
          style="margin-left:12px" />
        <el-button size="small" style="margin-left:12px" @click="logLines=[]">清空</el-button>
        <el-button size="small" style="margin-left:8px" @click="scrollBottom">↓ 最新</el-button>
      </div>
      <div ref="logBox" class="log-box">
        <div v-for="(l,i) in logLines" :key="i" class="log-line">{{ l }}</div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const list = ref([])
const loading = ref(false)
const search = ref('')
const previewShow = ref(false)
const previewText = ref('')

// 日志
const logShow = ref(false)
const logRule = ref(null)
const logLines = ref([])
const logPaused = ref(false)
const logBox = ref(null)
let logEs = null

const filteredList = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return list.value
  return list.value.filter(r =>
    (r.name || '').toLowerCase().includes(q) ||
    (r.server_name || '').toLowerCase().includes(q) ||
    (r.addresses || '').toLowerCase().includes(q)
  )
})

function handleCmd(cmd, row) {
  if (cmd === 'preview') preview(row.id)
  else if (cmd === 'log') openLog(row)
  else if (cmd === 'del') del(row)
}

function openLog(row) {
  logRule.value = row
  logLines.value = []
  logPaused.value = false
  logShow.value = true
  const token = localStorage.getItem('token')
  const logType = row.protocol === 'http' ? 'access' : 'stream'
  logEs = new EventSource(`/api/v1/rules/${row.id}/logs/stream?token=${token}&type=${logType}`)
  logEs.onmessage = (e) => {
    if (logPaused.value) return
    logLines.value.push(e.data)
    if (logLines.value.length > 2000) logLines.value.shift()
    nextTick(() => scrollBottom())
  }
  logEs.onerror = () => {}
}
function closeLog() {
  if (logEs) { logEs.close(); logEs = null }
}
function scrollBottom() {
  if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
}

async function load() {
  loading.value = true
  try { list.value = (await api.get('/rules')).data } catch {}
  loading.value = false
}
function protoTagType(p) { return {http:'primary', tcp:'warning', udp:'danger'}[p] || 'info' }
function lbLabel(m) { return {round_robin:'轮询', ip_hash:'IP哈希', least_conn:'最少连接'}[m] || m }
function stackLabel(s) { return {v4:'v4', v6:'v6', both:'v4+v6'}[s||'both'] }
function stackType(s)  { return {v4:'info', v6:'warning', both:'success'}[s||'both'] }
async function preview(id) {
  const res = await api.get(`/rules/${id}/preview`)
  previewText.value = res.data.config
  previewShow.value = true
}
async function toggle(row, status) {
  const action = status === 1 ? 'enable' : 'disable'
  await api.post(`/rules/${row.id}/${action}`)
  ElMessage.success('已' + (status === 1 ? '启用' : '禁用'))
  load()
}
async function del(row) {
  try {
    await ElMessageBox.confirm(`删除规则 "${row.name}" ?`, '确认', { type: 'warning' })
    await api.delete(`/rules/${row.id}`)
    ElMessage.success('已删除')
    load()
  } catch {}
}
onMounted(load)
</script>

<style scoped>
.warn { color: #e6a23c; font-weight: bold; }
.preview { background: #282c34; color: #abb2bf; padding: 16px; border-radius: 4px;
  max-height: 500px; overflow: auto; font-size: 12px; margin: 0; white-space: pre-wrap; }
.log-toolbar { display:flex; align-items:center; padding: 0 0 12px 0; flex-wrap: wrap; gap: 4px; }
.log-box { background: #1a1b1e; border-radius: 8px; padding: 12px 16px;
  height: calc(70vh - 100px); overflow-y: auto; font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
  font-size: 12.5px; line-height: 1.7; }
.log-line { color: #c9d1d9; white-space: pre-wrap; word-break: break-all; border-bottom: 1px solid #2a2b2f; padding: 1px 0; }
.log-line:last-child { border-bottom: none; }
</style>
