<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
      <h2 style="margin:0">SSL 证书</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <el-button type="success" icon="MagicStick" @click="openApply">申请证书</el-button>
        <el-button type="primary" icon="Plus" @click="openUpload">上传证书</el-button>
      </div>
    </div>
    <el-card>
      <div style="overflow-x:auto">
        <el-table :data="pagedList" size="small" table-layout="auto">
          <el-table-column prop="domain" label="域名" min-width="160" show-overflow-tooltip />
          <el-table-column v-if="!isMobile" prop="expire_at" label="到期时间" min-width="156" />
          <el-table-column label="剩余天数" min-width="92" align="center">
            <template #default="{row}">
              <el-tag :type="daysLeft(row.expire_at) < 10 ? 'danger' : 'success'" size="small">
                {{ daysLeft(row.expire_at) }} 天
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column v-if="!isMobile" label="自动续签" min-width="84" align="center">
            <template #default="{row}">
              <el-switch :model-value="row.auto_renew===1" @change="toggleRenew(row,$event)" />
            </template>
          </el-table-column>
          <el-table-column label="续签状态" min-width="96" align="center">
            <template #default="{row}">
              <el-tag :type="statusTagType(row.renew_status)" size="small">
                {{ statusLabel(row.renew_status) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column v-if="!isMobile" prop="last_renew_at" label="最后续签" min-width="156" />
          <el-table-column label="操作" :min-width="isMobile ? 100 : 240" fixed="right">
            <template #default="{row}">
              <template v-if="isMobile">
                <el-dropdown size="small" @command="handleCertCmd($event, row)">
                  <el-button size="small">操作<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="edit">编辑</el-dropdown-item>
                      <el-dropdown-item command="renew">续签</el-dropdown-item>
                      <el-dropdown-item command="log">日志</el-dropdown-item>
                      <el-dropdown-item command="auto_renew">
                        {{ row.auto_renew===1 ? '关闭自动续签' : '开启自动续签' }}
                      </el-dropdown-item>
                      <el-dropdown-item command="del" divided style="color:#f56c6c">删除</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </template>
              <template v-else>
                <el-button size="small" @click="openEdit(row)">编辑</el-button>
                <el-button size="small" type="primary" @click="renew(row)">续签</el-button>
                <el-button size="small" type="info" @click="openLog(row)">日志</el-button>
                <el-button size="small" type="danger" @click="del(row)">删除</el-button>
              </template>
            </template>
          </el-table-column>
        </el-table>
      </div>
      <Pagination :total="list.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>

    <!-- 申请证书对话框 -->
    <el-dialog v-model="applyShow" title="申请 SSL 证书（Let's Encrypt）" :width="dialogWidthSm" :close-on-click-modal="false">
      <el-alert type="info" :closable="false" style="margin-bottom:16px">
        通过 DNS-01 自动申请免费证书，需在<b>系统设置</b>中配置 DNSPod 或腾讯云 DNS API 及 ACME 邮箱。
      </el-alert>
      <el-form :model="applyForm" label-width="90px">
        <el-form-item label="域名" required>
          <el-input v-model="applyForm.domain" placeholder="例如：example.com 或 sub.example.com"
            clearable @keyup.enter="applySubmit" />
        </el-form-item>
        <el-form-item label="自动续签">
          <el-switch v-model="applyForm.auto_renew" :active-value="1" :inactive-value="0" />
          <span style="margin-left:8px;font-size:12px;color:#999">到期前 10 天自动触发</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="applyShow=false">取消</el-button>
        <el-button type="success" :loading="applying" @click="applySubmit">开始申请</el-button>
      </template>
    </el-dialog>

    <!-- 上传证书对话框 -->
    <el-dialog v-model="uploadShow" title="上传 SSL 证书" :width="dialogWidthLg" :close-on-click-modal="false">
      <el-alert type="info" :closable="false" style="margin-bottom:16px">
        系统将自动从证书中提取域名（SAN/CN）。证书与私钥不匹配时上传会失败。
      </el-alert>
      <el-form :model="form" label-width="120px">
        <el-form-item label="证书 (PEM)" required>
          <div style="width:100%">
            <div style="display:flex;gap:8px;margin-bottom:8px">
              <el-button size="small" icon="Upload" @click="pickFile('cert')">选择文件</el-button>
              <span style="font-size:12px;color:#999;line-height:28px">{{ certFileName || '支持 .pem / .crt / .cer 文件' }}</span>
            </div>
            <el-input v-model="form.cert_pem" type="textarea" :rows="6"
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" />
          </div>
        </el-form-item>
        <el-form-item label="私钥 (PEM)" required>
          <div style="width:100%">
            <div style="display:flex;gap:8px;margin-bottom:8px">
              <el-button size="small" icon="Upload" @click="pickFile('key')">选择文件</el-button>
              <span style="font-size:12px;color:#999;line-height:28px">{{ keyFileName || '支持 .pem / .key 文件' }}</span>
            </div>
            <el-input v-model="form.key_pem" type="textarea" :rows="6"
              placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" />
          </div>
        </el-form-item>
        <el-form-item label="自动续签">
          <el-switch v-model="form.auto_renew" :active-value="1" :inactive-value="0" />
        </el-form-item>
      </el-form>
      <input ref="fileInputCert" type="file" accept=".pem,.crt,.cer,.txt" style="display:none" @change="onFileChange('cert', $event)" />
      <input ref="fileInputKey" type="file" accept=".pem,.key,.txt" style="display:none" @change="onFileChange('key', $event)" />
      <template #footer>
        <el-button @click="uploadShow=false">取消</el-button>
        <el-button type="primary" :loading="uploading" @click="upload">上传并验证</el-button>
      </template>
    </el-dialog>

    <!-- 编辑证书对话框 -->
    <el-dialog v-model="editShow" :title="`编辑证书 — ${editForm.domain || ''}`" :width="dialogWidthLg" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" style="margin-bottom:16px">
        直接编辑证书与私钥内容，保存后将重新解析域名 / 到期时间，并写入 nginx 证书目录。
      </el-alert>
      <el-form :model="editForm" label-width="120px" v-loading="editLoading">
        <el-form-item label="证书 (PEM)" required>
          <el-input v-model="editForm.cert_pem" type="textarea" :rows="9"
            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            style="font-family:'JetBrains Mono','Consolas',monospace;font-size:12px" />
        </el-form-item>
        <el-form-item label="私钥 (PEM)" required>
          <el-input v-model="editForm.key_pem" type="textarea" :rows="9"
            placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
            style="font-family:'JetBrains Mono','Consolas',monospace;font-size:12px" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editShow=false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- 续签日志对话框 -->
    <el-dialog v-model="logShow" :title="`续签日志 — ${logCert?.domain}`" :width="dialogWidthMd" @close="closeLogDialog">
      <div style="margin-bottom:12px;display:flex;align-items:center;flex-wrap:wrap;gap:8px">
        <el-tag :type="statusTagType(logStatus)" size="small">{{ statusLabel(logStatus) }}</el-tag>
        <el-tag v-if="logStatus==='pending'" type="info" size="small" effect="plain">
          每 15 秒自动刷新
        </el-tag>
        <el-button size="small" @click="refreshLog">刷新</el-button>
      </div>
      <div ref="logBox" class="renew-log-box">
        <div v-if="!logText" style="color:#666;text-align:center;padding:20px">暂无日志</div>
        <div v-for="(line, i) in logLines" :key="i" class="renew-log-line"
          :class="{'log-ok': line.includes('成功') || line.includes('完成'), 'log-err': line.includes('失败') || line.includes('错误') || line.includes('超时')}">
          {{ line }}
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30
const list = ref([])
const page = ref(1)
const pagedList = computed(() => list.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))

const isMobile = ref(window.innerWidth < 768)
const dialogWidthSm = computed(() => isMobile.value ? '95vw' : '480px')
const dialogWidthMd = computed(() => isMobile.value ? '95vw' : '700px')
const dialogWidthLg = computed(() => isMobile.value ? '95vw' : '760px')
function _onResize() { isMobile.value = window.innerWidth < 768 }

// 申请证书
const applyShow = ref(false)
const applying = ref(false)
const applyForm = ref({ domain: '', auto_renew: 1 })

function openApply() {
  applyForm.value = { domain: '', auto_renew: 1 }
  applyShow.value = true
}

async function applySubmit() {
  const domain = applyForm.value.domain.trim()
  if (!domain) return ElMessage.warning('请输入域名')
  applying.value = true
  try {
    const res = await api.post('/certs/apply', applyForm.value)
    ElMessage.success(res.data.msg || '已提交申请')
    applyShow.value = false
    await load()
    const newRow = list.value.find(r => r.id === res.data.id)
    if (newRow) openLog(newRow)
  } catch {}
  applying.value = false
}

const uploadShow = ref(false)
const uploading = ref(false)
const form = ref({ cert_pem: '', key_pem: '', auto_renew: 1 })
const certFileName = ref('')
const keyFileName = ref('')
const fileInputCert = ref(null)
const fileInputKey = ref(null)

// 日志对话框
const logShow = ref(false)
const logCert = ref(null)
const logText = ref('')
const logStatus = ref('')
const logBox = ref(null)
let logPollTimer = null

const logLines = computed(() => logText.value ? logText.value.split('\n').filter(l => l) : [])

function statusLabel(s) {
  return { pending: '续签中', success: '已续签', failed: '续签失败', idle: '未续签', '': '未续签' }[s] ?? s ?? '未续签'
}
function statusTagType(s) {
  return { pending: 'warning', success: 'success', failed: 'danger' }[s] || 'info'
}

function openUpload() {
  form.value = { cert_pem: '', key_pem: '', auto_renew: 1 }
  certFileName.value = ''
  keyFileName.value = ''
  uploadShow.value = true
}

function pickFile(type) {
  if (type === 'cert') fileInputCert.value.click()
  else fileInputKey.value.click()
}

function onFileChange(type, e) {
  const file = e.target.files[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = (ev) => {
    if (type === 'cert') { form.value.cert_pem = ev.target.result; certFileName.value = file.name }
    else { form.value.key_pem = ev.target.result; keyFileName.value = file.name }
  }
  reader.readAsText(file)
  e.target.value = ''
}

async function load() { list.value = (await api.get('/certs')).data }

// 编辑证书
const editShow = ref(false)
const editLoading = ref(false)
const editSaving = ref(false)
const editForm = ref({ id: 0, domain: '', cert_pem: '', key_pem: '' })

async function openEdit(row) {
  editForm.value = { id: row.id, domain: row.domain, cert_pem: '', key_pem: '' }
  editShow.value = true
  editLoading.value = true
  try {
    const res = await api.get(`/certs/${row.id}`)
    editForm.value.cert_pem = res.data.cert_pem || ''
    editForm.value.key_pem = res.data.key_pem || ''
  } catch {}
  editLoading.value = false
}

async function saveEdit() {
  if (!editForm.value.cert_pem || !editForm.value.key_pem) return ElMessage.warning('证书和私钥不能为空')
  editSaving.value = true
  try {
    const res = await api.put(`/certs/${editForm.value.id}`, {
      cert_pem: editForm.value.cert_pem,
      key_pem: editForm.value.key_pem,
    })
    ElMessage.success(`保存成功，到期：${res.data.expire_at}`)
    editShow.value = false
    load()
  } catch {}
  editSaving.value = false
}

function daysLeft(expire) {
  return Math.ceil((new Date(expire) - new Date()) / 86400000)
}

async function upload() {
  if (!form.value.cert_pem || !form.value.key_pem) return ElMessage.warning('请填写或选择证书和私钥')
  uploading.value = true
  try {
    const res = await api.post('/certs', form.value)
    ElMessage.success(`上传成功，域名：${res.data.domain}，到期：${res.data.expire_at}`)
    uploadShow.value = false
    load()
  } catch {}
  uploading.value = false
}

async function del(row) {
  try {
    await ElMessageBox.confirm(`删除证书 ${row.domain} ?`, '确认', { type: 'warning' })
    await api.delete(`/certs/${row.id}`)
    ElMessage.success('已删除')
    load()
  } catch {}
}

async function toggleRenew(row, v) {
  await api.put(`/certs/${row.id}/auto_renew`, { auto_renew: v ? 1 : 0 })
  ElMessage.success('已更新')
  load()
}

async function renew(row) {
  try {
    const res = await api.post(`/certs/${row.id}/renew`)
    ElMessage.success(res.data.msg || '已提交续签申请')
    load()
    openLog(row)
  } catch {}
}

function handleCertCmd(cmd, row) {
  if (cmd === 'edit') openEdit(row)
  else if (cmd === 'renew') renew(row)
  else if (cmd === 'log') openLog(row)
  else if (cmd === 'auto_renew') toggleRenew(row, row.auto_renew !== 1)
  else if (cmd === 'del') del(row)
}

async function openLog(row) {
  logCert.value = row
  logText.value = ''
  logStatus.value = row.renew_status || ''
  logShow.value = true
  await refreshLog()
  if (logStatus.value === 'pending') startLogPoll(row.id)
}

async function refreshLog() {
  if (!logCert.value) return
  try {
    const res = await api.get(`/certs/${logCert.value.id}/renew_log`)
    logText.value = res.data.log || ''
    logStatus.value = res.data.status || ''
    await nextTick()
    if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
    if (logStatus.value !== 'pending') stopLogPoll()
  } catch {}
}

function startLogPoll(id) {
  stopLogPoll()
  logPollTimer = setInterval(async () => {
    await refreshLog()
    if (logStatus.value !== 'pending') {
      stopLogPoll()
      load()
    }
  }, 15000)
}

function stopLogPoll() {
  if (logPollTimer) { clearInterval(logPollTimer); logPollTimer = null }
}

function closeLogDialog() {
  stopLogPoll()
}

onMounted(() => { load(); window.addEventListener('resize', _onResize) })
onUnmounted(() => window.removeEventListener('resize', _onResize))
</script>

<style scoped>
.renew-log-box {
  background: #1a1b1e;
  border-radius: 8px;
  padding: 12px 16px;
  min-height: 200px;
  max-height: 420px;
  overflow-y: auto;
  font-family: 'JetBrains Mono','Fira Code','Consolas',monospace;
  font-size: 12.5px;
  line-height: 1.7;
}
.renew-log-line {
  color: #c9d1d9;
  white-space: pre-wrap;
  word-break: break-all;
  padding: 1px 0;
  border-bottom: 1px solid #2a2b2f;
}
.renew-log-line:last-child { border-bottom: none; }
.renew-log-line.log-ok { color: #3fb950; }
.renew-log-line.log-err { color: #f85149; }
</style>
