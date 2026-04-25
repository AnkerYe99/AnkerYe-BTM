<template>
  <div>
    <div style="display:flex;justify-content:space-between;margin-bottom:16px">
      <h2>从节点</h2>
      <el-button type="primary" icon="Plus" @click="addShow=true">注册从节点</el-button>
    </div>
    <el-alert :closable="false" type="info" style="margin-bottom:16px">
      从节点 Agent 会定期拉取主节点 <code>/api/v1/sync/export?token=...</code> 接口，对比版本哈希后自动应用配置。
      <br>sync_token 在「系统设置」中配置。
    </el-alert>
    <el-card>
      <el-table :data="pagedList" size="small">
        <el-table-column prop="name" label="节点名称" />
        <el-table-column prop="address" label="地址" />
        <el-table-column prop="last_sync_at" label="最后同步" width="180" />
        <el-table-column label="版本" width="140">
          <template #default="{row}">
            <el-tag size="small">{{ row.last_version ? row.last_version.slice(0,20)+'...' : '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{row}">
            <el-tag v-if="row.status==='ok'" type="success">正常</el-tag>
            <el-tag v-else type="warning">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{row}">
            <el-button size="small" type="danger" link @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <Pagination :total="list.length" :page-size="PAGE_SIZE" v-model:current="page" />
    </el-card>

    <el-dialog v-model="addShow" title="注册从节点" width="400px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="如 slave-1" />
        </el-form-item>
        <el-form-item label="地址" required>
          <el-input v-model="form.address" placeholder="10.14.x.x" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addShow=false">取消</el-button>
        <el-button type="primary" @click="submit">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import Pagination from '../components/Pagination.vue'

const PAGE_SIZE = 30
const list = ref([])
const page = ref(1)
const pagedList = computed(() => list.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))
const addShow = ref(false)
const form = ref({ name: '', address: '' })

async function load() { list.value = (await api.get('/sync/nodes')).data }
async function submit() {
  await api.post('/sync/nodes', form.value)
  ElMessage.success('已添加')
  addShow.value = false
  form.value = { name: '', address: '' }
  load()
}
async function del(row) {
  await ElMessageBox.confirm(`删除从节点 ${row.name}?`, '确认', { type: 'warning' })
  await api.delete(`/sync/nodes/${row.id}`)
  load()
}
onMounted(load)
</script>
