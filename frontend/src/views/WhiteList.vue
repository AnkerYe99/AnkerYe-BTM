<template>
  <div class="wl-page">
    <div class="page-header">
      <h2 style="margin:0">白名单</h2>
      <div style="display:flex;gap:8px">
        <el-button type="primary" size="small" :icon="Plus" @click="wlDialog=true">添加</el-button>
        <el-button size="small" :icon="Refresh" @click="load" :loading="loading">刷新</el-button>
      </div>
    </div>

    <!-- 搜索栏 -->
    <el-card shadow="never" style="margin-bottom:12px">
      <div class="search-row">
        <el-input v-model="q.value" placeholder="值" clearable size="small" style="width:160px" />
        <el-input v-model="q.note" placeholder="备注" clearable size="small" style="width:140px" />
        <el-select v-model="q.status" placeholder="状态" clearable style="width:85px" size="small">
          <el-option label="启用" value="1" />
          <el-option label="停用" value="0" />
        </el-select>
        <el-button size="small" @click="resetQ">重置</el-button>
        <el-button size="small" type="primary" :icon="Search" @click="doSearch">搜索</el-button>
      </div>
    </el-card>

    <!-- 表格 -->
    <el-card shadow="never" v-loading="loading">
      <el-table :data="pagedList" stripe size="small" style="width:100%">
        <el-table-column label="类型" width="72">
          <template #default="{row}">
            <el-tag type="success" size="small">{{ row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="值" prop="value" min-width="160" show-overflow-tooltip />
        <el-table-column label="备注" prop="note" min-width="120" show-overflow-tooltip />
        <el-table-column label="状态" width="66" align="center">
          <template #default="{row}">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
              {{ row.enabled ? '启用' : '停用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="加入时间" width="152">
          <template #default="{row}">
            <span style="color:#909399;font-size:12px">{{ fmtDate(row.created_at) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{row}">
            <el-button v-if="!row.enabled" size="small" type="success" text @click="doEnable(row)">启用</el-button>
            <el-button v-else size="small" type="warning" text @click="doDisable(row)">停用</el-button>
            <el-button size="small" type="danger" text @click="doDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <Pagination :total="filtered.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>

    <!-- 添加对话框 -->
    <el-dialog v-model="wlDialog" title="添加白名单" width="460px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="类型" required>
          <el-select v-model="form.type" style="width:100%">
            <el-option label="IP 地址" value="ip" />
            <el-option label="CIDR 段" value="cidr" />
          </el-select>
        </el-form-item>
        <el-form-item label="值" required>
          <el-input v-model="form.value" :placeholder="form.type === 'ip' ? '如 1.2.3.4' : '如 192.168.1.0/24'" />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="form.note" placeholder="可选说明" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="wlDialog=false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="doSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, Search } from '@element-plus/icons-vue'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30

const list = ref([])
const loading = ref(false)
const wlDialog = ref(false)
const saving = ref(false)
const form = ref({ type: 'ip', value: '', note: '' })
const page = ref(1)

const emptyQ = () => ({ value: '', note: '', status: '' })
const q = ref(emptyQ())
const activeQ = ref(emptyQ())

const filtered = computed(() => {
  let r = list.value
  const { value, note, status } = activeQ.value
  if (value) r = r.filter(x => (x.value || '').toLowerCase().includes(value.toLowerCase()))
  if (note) r = r.filter(x => (x.note || '').toLowerCase().includes(note.toLowerCase()))
  if (status === '1') r = r.filter(x => x.enabled)
  if (status === '0') r = r.filter(x => !x.enabled)
  return r
})

const pagedList = computed(() => filtered.value.slice((page.value-1)*PAGE_SIZE, page.value*PAGE_SIZE))

function fmtDate(s) {
  if (!s) return '-'
  return s.replace('T', ' ').slice(0, 16)
}

function doSearch() { activeQ.value = { ...q.value }; page.value = 1 }

function resetQ() {
  q.value = emptyQ()
  activeQ.value = emptyQ()
  page.value = 1
}

async function load() {
  loading.value = true
  try { list.value = (await api.get('/filter/whitelist')).data || [] } catch {}
  loading.value = false
}

async function doSave() {
  if (!form.value.value) return ElMessage.warning('请填写值')
  saving.value = true
  try {
    await api.post('/filter/whitelist', form.value)
    ElMessage.success('添加成功')
    wlDialog.value = false
    form.value = { type: 'ip', value: '', note: '' }
    load()
  } catch {}
  saving.value = false
}

async function doDelete(row) {
  await ElMessageBox.confirm(`删除白名单：${row.value}？`, '确认', { type: 'warning' })
  await api.delete(`/filter/whitelist/${row.id}`)
  ElMessage.success('已删除')
  load()
}

async function doEnable(row) { await api.post(`/filter/whitelist/${row.id}/enable`); load() }
async function doDisable(row) { await api.post(`/filter/whitelist/${row.id}/disable`); load() }

onMounted(load)
</script>

<style scoped>
.wl-page { }
.page-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
.page-header h2 { margin:0; }
.search-row { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
</style>
