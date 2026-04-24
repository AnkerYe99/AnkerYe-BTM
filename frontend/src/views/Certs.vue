<template>
  <div>
    <div style="display:flex;justify-content:space-between;margin-bottom:16px">
      <h2>SSL 证书</h2>
      <el-button type="primary" icon="Plus" @click="openUpload">上传证书</el-button>
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

    <el-dialog v-model="uploadShow" title="上传 SSL 证书" width="700px" :close-on-click-modal="false">
      <el-alert type="info" :closable="false" style="margin-bottom:16px">
        系统将自动从证书中提取域名（SAN/CN）。证书与私钥不匹配时上传会失败。
      </el-alert>
      <el-form :model="form" label-width="120px">

        <!-- 证书 -->
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

        <!-- 私钥 -->
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

      <!-- 隐藏文件输入 -->
      <input ref="fileInputCert" type="file" accept=".pem,.crt,.cer,.txt" style="display:none" @change="onFileChange('cert', $event)" />
      <input ref="fileInputKey" type="file" accept=".pem,.key,.txt" style="display:none" @change="onFileChange('key', $event)" />

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
const certFileName = ref('')
const keyFileName = ref('')
const fileInputCert = ref(null)
const fileInputKey = ref(null)

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
    if (type === 'cert') {
      form.value.cert_pem = ev.target.result
      certFileName.value = file.name
    } else {
      form.value.key_pem = ev.target.result
      keyFileName.value = file.name
    }
  }
  reader.readAsText(file)
  e.target.value = ''
}

async function load() { list.value = (await api.get('/certs')).data }

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
  const res = await api.post(`/certs/${row.id}/renew`)
  ElMessage.info(res.data.msg || '已提交续签')
}

onMounted(load)
</script>
