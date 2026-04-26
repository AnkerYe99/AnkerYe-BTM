<template>
  <div>
    <el-row :gutter="16" style="margin-bottom:16px">
      <el-col :span="24">
        <el-card shadow="never">
          <template #header>
            <div style="display:flex;align-items:center;justify-content:space-between">
              <span style="font-weight:600;font-size:15px">黑名单</span>
              <div style="display:flex;gap:8px">
                <el-select v-model="blFilter" style="width:120px" size="small">
                  <el-option label="全部类型" value="" />
                  <el-option label="IP" value="ip" />
                  <el-option label="CIDR" value="cidr" />
                  <el-option label="路径" value="path" />
                  <el-option label="UA" value="ua" />
                  <el-option label="自动封锁" value="auto" />
                </el-select>
                <el-button type="primary" size="small" @click="blDialog=true" :icon="Plus">添加</el-button>
                <el-button size="small" @click="applyFilter" :loading="applying" type="warning">立即应用</el-button>
              </div>
            </div>
          </template>
          <el-table :data="filteredBl" stripe size="small" v-loading="blLoading">
            <el-table-column label="类型" prop="type" width="70">
              <template #default="{row}">
                <el-tag :type="typeColor(row.type)" size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="值" prop="value" min-width="160" />
            <el-table-column label="备注" prop="note" min-width="120" />
            <el-table-column label="命中" prop="hits" width="60" />
            <el-table-column label="来源" width="80">
              <template #default="{row}">
                <el-tag v-if="row.auto_added" type="warning" size="small">自动</el-tag>
                <el-tag v-else type="info" size="small">手动</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="70">
              <template #default="{row}">
                <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
                  {{ row.enabled ? '启用' : '停用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="160" fixed="right">
              <template #default="{row}">
                <el-button v-if="!row.enabled" size="small" type="success" text @click="blEnable(row)">启用</el-button>
                <el-button v-else size="small" type="warning" text @click="blDisable(row)">停用</el-button>
                <el-button size="small" type="danger" text @click="blDelete(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div style="margin-top:8px;color:#999;font-size:12px">共 {{ filteredBl.length }} 条 / 总 {{ blacklist.length }} 条</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>
        <div style="display:flex;align-items:center;justify-content:space-between">
          <span style="font-weight:600;font-size:15px">白名单（白名单内 IP 永久放行，优先级高于黑名单）</span>
          <el-button type="primary" size="small" @click="wlDialog=true" :icon="Plus">添加</el-button>
        </div>
      </template>
      <el-table :data="whitelist" stripe size="small" v-loading="wlLoading">
        <el-table-column label="类型" prop="type" width="70">
          <template #default="{row}">
            <el-tag type="success" size="small">{{ row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="值" prop="value" min-width="160" />
        <el-table-column label="备注" prop="note" min-width="120" />
        <el-table-column label="状态" width="70">
          <template #default="{row}">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{row}">
            <el-button v-if="!row.enabled" size="small" type="success" text @click="wlEnable(row)">启用</el-button>
            <el-button v-else size="small" type="warning" text @click="wlDisable(row)">停用</el-button>
            <el-button size="small" type="danger" text @click="wlDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加黑名单 -->
    <el-dialog v-model="blDialog" title="添加黑名单" width="460px">
      <el-form :model="blForm" label-width="80px">
        <el-form-item label="类型" required>
          <el-select v-model="blForm.type" style="width:100%">
            <el-option label="IP 地址" value="ip" />
            <el-option label="CIDR 段" value="cidr" />
            <el-option label="路径 (正则)" value="path" />
            <el-option label="User-Agent (正则)" value="ua" />
          </el-select>
        </el-form-item>
        <el-form-item label="值" required>
          <el-input v-model="blForm.value" :placeholder="blPlaceholder" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="blForm.note" placeholder="可选说明" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="blDialog=false">取消</el-button>
        <el-button type="primary" :loading="blSaving" @click="blSave">保存</el-button>
      </template>
    </el-dialog>

    <!-- 添加白名单 -->
    <el-dialog v-model="wlDialog" title="添加白名单" width="460px">
      <el-form :model="wlForm" label-width="80px">
        <el-form-item label="类型" required>
          <el-select v-model="wlForm.type" style="width:100%">
            <el-option label="IP 地址" value="ip" />
            <el-option label="CIDR 段" value="cidr" />
          </el-select>
        </el-form-item>
        <el-form-item label="值" required>
          <el-input v-model="wlForm.value" :placeholder="wlForm.type === 'ip' ? '如 1.2.3.4' : '如 192.168.1.0/24'" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="wlForm.note" placeholder="可选说明" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="wlDialog=false">取消</el-button>
        <el-button type="primary" :loading="wlSaving" @click="wlSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import api from '../api'

const blacklist = ref([])
const whitelist = ref([])
const blLoading = ref(false)
const wlLoading = ref(false)
const blFilter = ref('')
const applying = ref(false)

const blDialog = ref(false)
const blSaving = ref(false)
const blForm = ref({ type: 'ip', value: '', note: '' })

const wlDialog = ref(false)
const wlSaving = ref(false)
const wlForm = ref({ type: 'ip', value: '', note: '' })

const filteredBl = computed(() => {
  if (!blFilter.value) return blacklist.value
  if (blFilter.value === 'auto') return blacklist.value.filter(r => r.auto_added)
  return blacklist.value.filter(r => r.type === blFilter.value)
})

const blPlaceholder = computed(() => {
  const m = { ip: '如 1.2.3.4', cidr: '如 10.0.0.0/8', path: '如 ~*/wp-login.php', ua: '如 ~*sqlmap' }
  return m[blForm.value.type] || ''
})

function typeColor(t) {
  return { ip: 'danger', cidr: 'warning', path: 'primary', ua: '' }[t] || 'info'
}

async function loadBl() {
  blLoading.value = true
  try { blacklist.value = (await api.get('/filter/blacklist')).data.data || [] } catch {}
  blLoading.value = false
}
async function loadWl() {
  wlLoading.value = true
  try { whitelist.value = (await api.get('/filter/whitelist')).data.data || [] } catch {}
  wlLoading.value = false
}

async function blSave() {
  if (!blForm.value.value) return ElMessage.warning('请填写值')
  blSaving.value = true
  try {
    await api.post('/filter/blacklist', blForm.value)
    ElMessage.success('添加成功')
    blDialog.value = false
    blForm.value = { type: 'ip', value: '', note: '' }
    loadBl()
  } catch {}
  blSaving.value = false
}
async function blDelete(row) {
  await ElMessageBox.confirm(`删除黑名单：${row.value}？`, '确认', { type: 'warning' })
  await api.delete(`/filter/blacklist/${row.id}`)
  ElMessage.success('已删除')
  loadBl()
}
async function blEnable(row) { await api.post(`/filter/blacklist/${row.id}/enable`); loadBl() }
async function blDisable(row) { await api.post(`/filter/blacklist/${row.id}/disable`); loadBl() }

async function wlSave() {
  if (!wlForm.value.value) return ElMessage.warning('请填写值')
  wlSaving.value = true
  try {
    await api.post('/filter/whitelist', wlForm.value)
    ElMessage.success('添加成功')
    wlDialog.value = false
    wlForm.value = { type: 'ip', value: '', note: '' }
    loadWl()
  } catch {}
  wlSaving.value = false
}
async function wlDelete(row) {
  await ElMessageBox.confirm(`删除白名单：${row.value}？`, '确认', { type: 'warning' })
  await api.delete(`/filter/whitelist/${row.id}`)
  ElMessage.success('已删除')
  loadWl()
}
async function wlEnable(row) { await api.post(`/filter/whitelist/${row.id}/enable`); loadWl() }
async function wlDisable(row) { await api.post(`/filter/whitelist/${row.id}/disable`); loadWl() }

async function applyFilter() {
  applying.value = true
  try {
    await api.post('/filter/apply')
    ElMessage.success('规则已应用到 nginx')
  } catch {}
  applying.value = false
}

onMounted(() => { loadBl(); loadWl() })
</script>
