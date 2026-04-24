<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <h2>节点监控</h2>
      <el-button @click="load">刷新</el-button>
    </div>
    <el-card>
      <el-table :data="list" size="small">
        <el-table-column prop="rule_name" label="规则" />
        <el-table-column label="节点">
          <template #default="{row}">{{ row.address }}:{{ row.port }}</template>
        </el-table-column>
        <el-table-column prop="weight" label="权重" width="80" />
        <el-table-column label="状态" width="100">
          <template #default="{row}">
            <el-tag v-if="row.state==='up'" type="success">UP</el-tag>
            <el-tag v-else-if="row.state==='down'" type="danger">DOWN</el-tag>
            <el-tag v-else type="info">DISABLED</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_check_at" label="最后检查" width="180" />
        <el-table-column prop="last_err" label="错误" show-overflow-tooltip />
        <el-table-column label="操作" width="140">
          <template #default="{row}">
            <el-button v-if="row.state!=='disabled'" size="small" @click="toggle(row,'disable')">禁用</el-button>
            <el-button v-else size="small" type="success" @click="toggle(row,'enable')">启用</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const list = ref([])
let timer = null

async function load() {
  list.value = (await api.get('/stats/health')).data
}
async function toggle(row, action) {
  await api.post(`/rules/${row.rule_id}/servers/${row.id}/${action}`)
  ElMessage.success('已' + (action==='enable'?'启用':'禁用'))
  load()
}
onMounted(() => { load(); timer = setInterval(load, 8000) })
onUnmounted(() => clearInterval(timer))
</script>
