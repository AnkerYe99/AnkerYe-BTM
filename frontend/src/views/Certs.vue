<template>
  <div>
    <div style="display:flex;justify-content:space-between;margin-bottom:16px">
      <h2>SSL 证书</h2>
      <el-button type="primary" icon="Plus" @click="uploadShow=true">上传证书</el-button>
    </div>
    <el-card>
      <el-table :data="list" size="small">
        <el-table-column prop="domain" label="域名" />
        <el-table-column prop="expire_at" label="到期时间" width="180" />
        <el-table-column label="剩余天数" width="100">
          <template #default="{row}">
            <el-tag :type="daysLeft(row.expire_at) < 10 ? 'danger' : 'success'">
              {{ daysLeft(row.expire_at) }} 天
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="自动续签" width="100">
          <template #default="{row}">
            <el-switch :model-value="row.auto_renew===1" @change="toggleRenew(row,$event)" />
          </template>
        </el-table-column>
        <el-table-column prop="renew_status" label="续签状态" width="120" />
        <el-table-column prop="last_renew_at" label="最后续签" width="180" />
        <el-table-column label="操作" width="180">
          <template #default="{row}">
            <el-button size="small" @click="renew(row)">续签</el-button>
            <el-button size="small" type="danger" @click="del(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="uploadShow" title="上传 SSL 证书" width="700px">
      <el-alert type="info" :closable="false" style="margin-bottom:12px">
        系统将自动从证书中提取域名（SAN/CN）。证书与私钥不匹配时上传会失败。
      </el-alert>
      <el-form :model="form" label-width="120px">
        <el-form-item label="证书 (PEM)" required>
          <el-input v-model="form.cert_pem" type="textarea" :rows="7" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" />
        </el-form-item>
        <el-form-item label="私钥 (PEM)" required>
          <el-input v-model="form.key_pem" type="textarea" :rows="7" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" />
        </el-form-item>
        <el-form-item label="自动续签">
          <el-switch v-model="form.auto_renew" :active-value="1" :inactive-value="0" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="uploadShow=false">取消</el-button>
        <el-button type="primary" :loading="uploading" @click="upload">上传并验证</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const list = ref([])
const uploadShow = ref(false)
const uploading = ref(false)
const form = ref({ cert_pem: '', key_pem: '', auto_renew: 1 })

async function load() { list.value = (await api.get('/certs')).data }
function daysLeft(expire) {
  const d = Math.ceil((new Date(expire) - new Date()) / 86400000)
  return d
}
async function upload() {
  if (!form.value.cert_pem || !form.value.key_pem) return ElMessage.warning('请填写证书和私钥')
  uploading.value = true
  try {
    const res = await api.post('/certs', form.value)
    ElMessage.success(`上传成功，域名：${res.data.domain}，到期：${res.data.expire_at}`)
    uploadShow.value = false
    form.value = { cert_pem: '', key_pem: '', auto_renew: 1 }
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
  const res = await api.post(`/certs/${row.id}/renew`)
  ElMessage.info(res.data.msg || '已提交续签')
}
onMounted(load)
</script>
