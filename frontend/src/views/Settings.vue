<template>
  <div>
    <h2>系统设置</h2>
    <el-card>
      <el-form :model="form" label-width="180px" style="max-width:800px">
        <el-divider>nginx 全局参数</el-divider>
        <el-form-item label="工作进程数">
          <el-input v-model="form.nginx_worker_processes" placeholder="auto">
            <template #append>worker_processes</template>
          </el-input>
        </el-form-item>
        <el-form-item label="最大并发连接数">
          <el-input v-model="form.nginx_worker_connections">
            <template #append>worker_connections</template>
          </el-input>
        </el-form-item>
        <el-form-item label="长连接超时时间">
          <el-input v-model="form.nginx_keepalive_timeout">
            <template #append>秒 · keepalive_timeout</template>
          </el-input>
        </el-form-item>
        <el-form-item label="最大请求体大小">
          <el-input v-model="form.nginx_client_max_body_size" placeholder="64m">
            <template #append>client_max_body_size</template>
          </el-input>
        </el-form-item>
        <el-form-item label="默认日志轮转大小">
          <el-input v-model="form.default_log_max_size" placeholder="5M">
            <template #append>超过此大小自动压缩</template>
          </el-input>
        </el-form-item>

        <el-divider>腾讯云 SSL 续签</el-divider>
        <el-form-item label="API SecretId">
          <el-input v-model="form.tencent_secret_id" />
        </el-form-item>
        <el-form-item label="API SecretKey">
          <el-input v-model="form.tencent_secret_key" type="password" show-password placeholder="未修改保持为空" />
        </el-form-item>
        <el-form-item label="DNS 解析区域">
          <el-input v-model="form.tencent_dns_region" placeholder="ap-guangzhou" />
        </el-form-item>

        <el-divider>主从同步</el-divider>
        <el-form-item label="同步鉴权 Token">
          <el-input v-model="form.sync_token" type="password" show-password placeholder="从节点鉴权 token" />
        </el-form-item>

        <el-divider>告警通知</el-divider>
        <el-form-item label="Mattermost Webhook">
          <el-input v-model="form.notify_mm_webhook" placeholder="http://..." />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="save">保存</el-button>
          <el-button @click="load">重置</el-button>
          <el-divider direction="vertical" />
          <el-button @click="testNginx">测试 nginx 配置</el-button>
          <el-button @click="reloadNginx">重载 nginx</el-button>
          <el-button type="info" @click="backup">导出备份</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const form = ref({})

async function load() { form.value = (await api.get('/settings')).data }
async function save() {
  // 移除值为 *** 的敏感字段（表示未修改）
  const data = {}
  for (const k in form.value) {
    if (form.value[k] !== '***') data[k] = form.value[k]
  }
  await api.put('/settings', data)
  ElMessage.success('已保存')
  load()
}
async function testNginx() {
  try {
    const res = await api.post('/settings/nginx_test')
    ElMessageBox.alert(res.data.output, 'nginx 语法检查', { type: 'success' })
  } catch (e) {
    ElMessageBox.alert(e.msg || '失败', 'nginx 语法错误', { type: 'error' })
  }
}
async function reloadNginx() {
  await api.post('/settings/nginx_reload')
  ElMessage.success('nginx 已重载')
}
async function backup() {
  try {
    const blob = await api.get('/settings/backup', { responseType: 'blob' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nginxflow-backup-${new Date().toISOString().slice(0,10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success('备份已下载')
  } catch {}
}
onMounted(load)
</script>
