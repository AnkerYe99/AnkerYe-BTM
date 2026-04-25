<template>
  <div class="settings-page">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
      <h2 style="margin:0">系统设置</h2>
    </div>

    <el-tabs v-model="activeTab" class="settings-tabs">
      <!-- ── Nginx 参数 ── -->
      <el-tab-pane label="Nginx 参数" name="nginx">
        <el-card shadow="never" class="section-card">
          <template #header>
            <span class="card-title">全局参数</span>
            <span class="card-subtitle">调整 nginx 进程与连接相关设置，修改后需重载生效</span>
          </template>
          <el-form :model="form" label-width="150px" class="section-form">
            <el-form-item label="工作进程数">
              <el-input v-model="form.nginx_worker_processes" placeholder="auto" style="max-width:280px">
                <template #append>worker_processes</template>
              </el-input>
            </el-form-item>
            <el-form-item label="最大并发连接数">
              <el-input v-model="form.nginx_worker_connections" style="max-width:280px">
                <template #append>worker_connections</template>
              </el-input>
            </el-form-item>
            <el-form-item label="长连接超时">
              <el-input v-model="form.nginx_keepalive_timeout" style="max-width:280px">
                <template #append>秒</template>
              </el-input>
            </el-form-item>
            <el-form-item label="最大请求体大小">
              <el-input v-model="form.nginx_client_max_body_size" placeholder="64m" style="max-width:280px" />
            </el-form-item>
            <el-form-item label="日志轮转大小">
              <el-input v-model="form.default_log_max_size" placeholder="5M" style="max-width:280px">
                <template #append>超过自动压缩</template>
              </el-input>
            </el-form-item>
          </el-form>
          <div class="inline-actions">
            <el-button @click="testNginx">测试 nginx 配置</el-button>
            <el-button type="success" @click="reloadNginx">重载 nginx</el-button>
          </div>
        </el-card>
      </el-tab-pane>

      <!-- ── SSL 续签 ── -->
      <el-tab-pane label="SSL 续签" name="ssl">
        <el-card shadow="never" class="section-card">
          <template #header>
            <span class="card-title">Let's Encrypt 自动续签</span>
            <span class="card-subtitle">通过 DNSPod API 自动完成 DNS-01 验证，填写下方任意一种 API 凭据即可</span>
          </template>
          <el-form :model="form" label-width="150px" class="section-form">
            <el-form-item label="ACME 注册邮箱" required>
              <el-input v-model="form.acme_email" placeholder="your@email.com" style="max-width:360px" />
              <div class="field-hint">用于 Let's Encrypt 账号注册及证书到期提醒</div>
            </el-form-item>

            <div class="sub-section">
              <div class="sub-section-title">方式一：DNSPod Token API（推荐）</div>
              <el-form-item label="Token ID">
                <el-input v-model="form.dnspod_id" placeholder="在 dnspod.cn → API Token 页面生成" style="max-width:280px" />
              </el-form-item>
              <el-form-item label="Token Key">
                <el-input v-model="form.dnspod_key" type="password" show-password placeholder="未修改留空" style="max-width:360px" />
              </el-form-item>
            </div>

            <div class="sub-section">
              <div class="sub-section-title">方式二：腾讯云 CAM API</div>
              <el-form-item label="CAM SecretId">
                <el-input v-model="form.tencent_secret_id" placeholder="腾讯云控制台 → 访问管理 → API 密钥" style="max-width:420px" />
              </el-form-item>
              <el-form-item label="CAM SecretKey">
                <el-input v-model="form.tencent_secret_key" type="password" show-password placeholder="未修改留空" style="max-width:360px" />
              </el-form-item>
            </div>

            <div class="sub-section">
              <div class="sub-section-title">从节点模式</div>
              <el-form-item label="禁止本机自动续签">
                <el-switch v-model="form.cert_renew_disabled" active-value="1" inactive-value="0" />
                <span class="field-hint" style="display:inline;margin-left:12px">
                  开启后本机不执行任何续签（自动+手动均禁用），适合由主节点统一续签后通过证书同步分发的从节点
                </span>
              </el-form-item>
            </div>
          </el-form>
        </el-card>
      </el-tab-pane>

      <!-- ── 邮件通知 ── -->
      <el-tab-pane label="邮件通知" name="email">
        <div class="two-col">
          <el-card shadow="never" class="section-card">
            <template #header>
              <span class="card-title">SMTP 配置</span>
            </template>
            <el-form :model="form" label-width="120px" class="section-form">
              <el-form-item label="邮箱服务商">
                <el-select v-model="smtpProvider" style="width:100%;max-width:240px" @change="onProviderChange">
                  <el-option v-for="p in smtpPresets" :key="p.value" :label="p.name" :value="p.value" />
                  <el-option label="自定义" value="custom" />
                </el-select>
                <span v-if="smtpProvider && smtpProvider !== 'custom'" class="preset-hint">
                  {{ currentPreset?.host }}:{{ currentPreset?.port }}
                </span>
              </el-form-item>
              <el-form-item label="用户名">
                <el-input v-model="form.smtp_user" :placeholder="currentPreset?.userPlaceholder || 'user@example.com'" />
              </el-form-item>
              <el-form-item label="密码">
                <el-input v-model="form.smtp_password" type="password" show-password
                  :placeholder="currentPreset?.needAuthCode ? '授权码（非登录密码）' : '登录密码'" />
                <div v-if="currentPreset?.needAuthCode" class="field-hint warn-hint">
                  须填授权码，非邮箱登录密码。网页邮箱 → 设置 → POP3/SMTP → 开启服务 → 新增授权密码
                </div>
              </el-form-item>
              <el-form-item label="收件人">
                <el-input v-model="form.notify_email_to" placeholder="admin@example.com，多个英文逗号分隔" />
              </el-form-item>

              <el-collapse style="margin:4px 0 12px">
                <el-collapse-item title="高级 SMTP 设置（自定义服务器时展开）" name="adv">
                  <el-form-item label="服务器地址" style="margin-top:12px">
                    <el-input v-model="form.smtp_host" placeholder="smtp.example.com" style="max-width:220px" />
                    <el-input-number v-model.number="form.smtp_port" :min="1" :max="65535"
                      placeholder="端口" style="width:90px;margin-left:8px" />
                    <el-switch v-model="smtpTLS" active-text="SSL/TLS" inactive-text="STARTTLS"
                      style="margin-left:12px" @change="v => form.smtp_tls = v ? '1' : '0'" />
                  </el-form-item>
                  <el-form-item label="发件人名称">
                    <el-input v-model="form.smtp_from" placeholder="AnkerYe <noreply@example.com>" />
                    <div class="field-hint">163/126 信封发件人固定为用户名，此项仅影响显示名称</div>
                  </el-form-item>
                </el-collapse-item>
              </el-collapse>

              <div class="inline-actions">
                <el-button @click="testEmail" :loading="testingEmail">发送测试邮件</el-button>
              </div>
            </el-form>
          </el-card>

          <el-card shadow="never" class="section-card">
            <template #header>
              <span class="card-title">通知事件</span>
              <span class="card-subtitle">选择需要接收邮件提醒的事件</span>
            </template>
            <div class="notify-list">
              <div class="notify-item">
                <div class="notify-info">
                  <div class="notify-title">证书续签失败</div>
                  <div class="notify-desc">证书自动或手动续签失败时发送通知</div>
                </div>
                <el-switch v-model="form.notify_cert_fail" active-value="1" inactive-value="0" />
              </div>
              <div class="notify-item">
                <div class="notify-info">
                  <div class="notify-title">证书续签成功</div>
                  <div class="notify-desc">证书续签完成并生效时发送通知</div>
                </div>
                <el-switch v-model="form.notify_cert_success" active-value="1" inactive-value="0" />
              </div>
              <div class="notify-item">
                <div class="notify-info">
                  <div class="notify-title">节点下线告警</div>
                  <div class="notify-desc">后端节点健康检查失败下线时发送通知</div>
                </div>
                <el-switch v-model="form.notify_server_down" active-value="1" inactive-value="0" />
              </div>
              <div class="notify-item">
                <div class="notify-info">
                  <div class="notify-title">节点恢复通知</div>
                  <div class="notify-desc">下线节点重新上线时发送通知</div>
                </div>
                <el-switch v-model="form.notify_server_up" active-value="1" inactive-value="0" />
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>

      <!-- ── 主从同步 ── -->
      <el-tab-pane label="主从同步" name="sync">
        <div class="two-col">
          <!-- 规则同步 -->
          <el-card shadow="never" class="section-card sync-card">
            <template #header>
              <span class="card-title">规则同步</span>
            </template>
            <div class="sync-card-body">
              <div class="sub-section">
                <div class="sub-section-title">作为主节点</div>
                <el-form-item label="同步 Token" label-width="90px">
                  <el-input v-model="form.sync_rules_token" type="password" show-password
                    placeholder="设置后从节点可拉取本机规则" />
                  <el-button style="margin-top:8px;width:100%" @click="genRulesToken">生成 Token</el-button>
                </el-form-item>
              </div>
              <div class="sub-section">
                <div class="sub-section-title">作为从节点 <span class="sub-hint">（留空不启用）</span></div>
                <el-form-item label="主节点地址" label-width="90px">
                  <el-input v-model="form.slave_rules_url" placeholder="http://10.x.x.x:9000" />
                </el-form-item>
                <el-form-item label="主节点 Token" label-width="90px">
                  <el-input v-model="form.slave_rules_token" type="password" show-password placeholder="未修改留空" />
                </el-form-item>
                <el-form-item label="同步间隔" label-width="90px">
                  <el-input-number v-model.number="form.slave_rules_interval" :min="10" :max="3600" style="width:120px" />
                  <span style="margin-left:8px;color:#909399;font-size:13px">秒/次</span>
                </el-form-item>
              </div>
              <el-button type="primary" plain :loading="triggeringRules" @click="triggerRules" style="width:100%">立即同步规则</el-button>
              <div v-if="form.slave_rules_last_sync_at" class="sync-status" style="margin-top:10px">
                <el-tag :type="form.slave_rules_last_status==='ok'?'success':'danger'" size="small">
                  {{ form.slave_rules_last_status==='ok' ? '正常' : '异常' }}
                </el-tag>
                <span style="margin-left:8px;color:#909399;font-size:12px;word-break:break-all">
                  {{ form.slave_rules_last_sync_at }}<br>{{ form.slave_rules_last_msg }}
                </span>
              </div>
            </div>
          </el-card>

          <!-- 证书同步 -->
          <el-card shadow="never" class="section-card sync-card">
            <template #header>
              <span class="card-title">证书同步</span>
            </template>
            <div class="sync-card-body">
              <div class="sub-section">
                <div class="sub-section-title">作为主节点</div>
                <el-form-item label="同步 Token" label-width="90px">
                  <el-input v-model="form.sync_certs_token" type="password" show-password
                    placeholder="设置后从节点可拉取本机证书" />
                  <el-button style="margin-top:8px;width:100%" @click="genCertsToken">生成 Token</el-button>
                </el-form-item>
              </div>
              <div class="sub-section">
                <div class="sub-section-title">作为从节点 <span class="sub-hint">（留空不启用）</span></div>
                <el-form-item label="主节点地址" label-width="90px">
                  <el-input v-model="form.slave_certs_url" placeholder="http://10.x.x.x:9000" />
                </el-form-item>
                <el-form-item label="主节点 Token" label-width="90px">
                  <el-input v-model="form.slave_certs_token" type="password" show-password placeholder="未修改留空" />
                </el-form-item>
                <el-form-item label="同步间隔" label-width="90px">
                  <el-input-number v-model.number="form.slave_certs_interval" :min="10" :max="3600" style="width:120px" />
                  <span style="margin-left:8px;color:#909399;font-size:13px">秒/次</span>
                </el-form-item>
              </div>
              <el-button type="primary" plain :loading="triggeringCerts" @click="triggerCerts" style="width:100%">立即同步证书</el-button>
              <div v-if="form.slave_certs_last_sync_at" class="sync-status" style="margin-top:10px">
                <el-tag :type="form.slave_certs_last_status==='ok'?'success':'danger'" size="small">
                  {{ form.slave_certs_last_status==='ok' ? '正常' : '异常' }}
                </el-tag>
                <span style="margin-left:8px;color:#909399;font-size:12px;word-break:break-all">
                  {{ form.slave_certs_last_sync_at }}<br>{{ form.slave_certs_last_msg }}
                </span>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>

      <!-- ── 数据管理 ── -->
      <el-tab-pane label="数据管理" name="data">
        <div class="two-col">
          <el-card shadow="never" class="section-card data-card">
            <div class="data-icon export-icon">⬇</div>
            <div class="data-card-title">导出备份</div>
            <div class="data-card-desc">
              将全部规则、证书、节点和系统配置打包为加密备份文件。使用 AES-256-GCM 加密，可在任意 AnkerYe 实例上还原，无需担心明文泄露。
            </div>
            <el-button type="primary" size="large" @click="backup" style="width:100%;max-width:260px">
              导出备份 (.bak)
            </el-button>
          </el-card>

          <el-card shadow="never" class="section-card data-card">
            <div class="data-icon import-icon">⬆</div>
            <div class="data-card-title">导入恢复</div>
            <div class="data-card-desc">
              选择之前导出的 <code>.bak</code> 备份文件，系统将自动解密并还原所有配置。<br>
              <b style="color:#E6A23C">注意：恢复将覆盖当前所有数据，操作不可撤销。</b>
            </div>
            <el-button type="warning" size="large" @click="$refs.restoreInput.click()" style="width:100%;max-width:260px">
              选择备份文件并恢复
            </el-button>
            <input ref="restoreInput" type="file" accept=".bak,.json" style="display:none" @change="restore" />
          </el-card>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 底部固定保存栏 -->
    <div class="bottom-bar">
      <el-button type="primary" @click="save" size="large">保存设置</el-button>
      <el-button @click="load" size="large">重置</el-button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const activeTab = ref('nginx')
const form = ref({})
const testingEmail = ref(false)
const smtpProvider = ref('')
const triggeringRules = ref(false)
const triggeringCerts = ref(false)

const smtpPresets = [
  { value: '163',     name: '163邮箱',    host: 'smtp.163.com',         port: 465, tls: true,  needAuthCode: true,  userPlaceholder: 'yourname@163.com' },
  { value: '126',     name: '126邮箱',    host: 'smtp.126.com',         port: 465, tls: true,  needAuthCode: true,  userPlaceholder: 'yourname@126.com' },
  { value: 'yeah',    name: 'yeah邮箱',   host: 'smtp.yeah.net',        port: 465, tls: true,  needAuthCode: true,  userPlaceholder: 'yourname@yeah.net' },
  { value: 'qq',      name: 'QQ邮箱',     host: 'smtp.qq.com',          port: 465, tls: true,  needAuthCode: true,  userPlaceholder: 'yourQQ@qq.com' },
  { value: 'gmail',   name: 'Gmail',      host: 'smtp.gmail.com',       port: 465, tls: true,  needAuthCode: true,  userPlaceholder: 'you@gmail.com' },
  { value: 'outlook', name: 'Outlook',    host: 'smtp.office365.com',   port: 587, tls: false, needAuthCode: false, userPlaceholder: 'you@outlook.com' },
  { value: 'qq_ent',  name: '腾讯企业邮', host: 'smtp.exmail.qq.com',   port: 465, tls: true,  needAuthCode: false, userPlaceholder: 'you@yourcompany.com' },
  { value: 'ali',     name: '阿里企业邮', host: 'smtp.qiye.aliyun.com', port: 465, tls: true,  needAuthCode: false, userPlaceholder: 'you@yourcompany.com' },
]

const currentPreset = computed(() => smtpPresets.find(p => p.value === smtpProvider.value) || null)
const slaveStatus = computed(() => !!form.value.slave_last_sync_at)

const smtpTLS = computed({
  get: () => form.value.smtp_tls !== '0',
  set: (v) => { form.value.smtp_tls = v ? '1' : '0' }
})

function onProviderChange(val) {
  const p = smtpPresets.find(x => x.value === val)
  if (!p) return
  form.value.smtp_host = p.host
  form.value.smtp_port = p.port
  form.value.smtp_tls  = p.tls ? '1' : '0'
}

function detectProvider(host) {
  if (!host) return ''
  const p = smtpPresets.find(x => x.host === host)
  return p ? p.value : 'custom'
}

async function load() {
  form.value = (await api.get('/settings')).data
  if (form.value.smtp_port) form.value.smtp_port = Number(form.value.smtp_port)
  if (form.value.slave_interval) form.value.slave_interval = Number(form.value.slave_interval)
  if (form.value.slave_rules_interval) form.value.slave_rules_interval = Number(form.value.slave_rules_interval)
  if (form.value.slave_certs_interval) form.value.slave_certs_interval = Number(form.value.slave_certs_interval)
  smtpProvider.value = detectProvider(form.value.smtp_host)
}

async function save() {
  const data = {}
  for (const k in form.value) {
    if (form.value[k] !== '***') data[k] = String(form.value[k] ?? '')
  }
  await api.put('/settings', data)
  ElMessage.success('设置已保存')
  load()
}

async function testEmail() {
  testingEmail.value = true
  try {
    await api.post('/settings/test_email')
    ElMessage.success('测试邮件已发送，请检查收件箱')
  } catch (e) {
    ElMessage.error('发送失败：' + (e?.response?.data?.msg || e.message || '未知错误'))
  }
  testingEmail.value = false
}

async function testNginx() {
  try {
    const res = await api.post('/settings/nginx_test')
    ElMessageBox.alert(res.data.output, 'nginx 语法检查通过', { type: 'success' })
  } catch (e) {
    ElMessageBox.alert(e?.response?.data?.msg || '检查失败', 'nginx 语法错误', { type: 'error' })
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
    a.download = `ankye-backup-${new Date().toISOString().slice(0,10)}.bak`
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success('备份已下载（AES-256 加密）')
  } catch { ElMessage.error('备份失败') }
}

async function restore(e) {
  const file = e.target.files[0]
  if (!file) return
  e.target.value = ''
  try {
    await ElMessageBox.confirm(
      '恢复将覆盖当前所有规则、证书和设置，确认继续？',
      '导入恢复', { type: 'warning', confirmButtonText: '确认恢复', cancelButtonText: '取消' }
    )
  } catch { return }
  const fd = new FormData()
  fd.append('file', file)
  try {
    await api.post('/settings/restore', fd, { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 60000 })
    ElMessage.success('恢复成功，配置已重新加载')
    load()
  } catch (e) { ElMessage.error(e?.response?.data?.msg || '恢复失败，请检查备份文件') }
}

async function triggerRules() {
  if (!form.value.slave_rules_url) { ElMessage.warning('请先设置主节点地址'); return }
  triggeringRules.value = true
  try {
    await api.post('/sync/trigger_rules')
    ElMessage.success('已触发规则同步，约3秒后刷新状态')
    setTimeout(load, 4000)
  } catch (e) { ElMessage.error('触发失败') }
  triggeringRules.value = false
}

async function triggerCerts() {
  if (!form.value.slave_certs_url) { ElMessage.warning('请先设置主节点地址'); return }
  triggeringCerts.value = true
  try {
    await api.post('/sync/trigger_certs')
    ElMessage.success('已触发证书同步，约3秒后刷新状态')
    setTimeout(load, 4000)
  } catch (e) { ElMessage.error('触发失败') }
  triggeringCerts.value = false
}

function randToken() {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('')
}
function genToken() {
  form.value.sync_token = randToken()
  ElMessage.success('Token 已生成，请记得保存')
}
function genRulesToken() {
  form.value.sync_rules_token = randToken()
  ElMessage.success('规则同步 Token 已生成，请记得保存')
}
function genCertsToken() {
  form.value.sync_certs_token = randToken()
  ElMessage.success('证书同步 Token 已生成，请记得保存')
}

onMounted(load)
</script>

<style scoped>
.settings-page {
  padding-bottom: 80px;
}
.settings-tabs :deep(.el-tabs__content) {
  padding: 0;
}
.section-card {
  margin-bottom: 16px;
}
.section-card :deep(.el-card__header) {
  padding: 14px 20px;
  background: #fafafa;
  border-bottom: 1px solid #f0f2f5;
}
.card-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}
.card-subtitle {
  font-size: 12px;
  color: #909399;
  margin-left: 10px;
}
.section-form {
  max-width: 720px;
  padding-top: 4px;
}
.sub-section {
  margin-bottom: 20px;
}
.sub-section-title {
  font-size: 13px;
  font-weight: 600;
  color: #606266;
  background: #f5f7fa;
  border-left: 3px solid #409EFF;
  padding: 6px 12px;
  border-radius: 0 4px 4px 0;
  margin-bottom: 16px;
}
.field-hint {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
  line-height: 1.5;
}
.warn-hint {
  color: #e6a23c;
}
.preset-hint {
  font-size: 12px;
  color: #909399;
  margin-left: 10px;
}
.inline-actions {
  border-top: 1px solid #f0f2f5;
  padding-top: 16px;
  margin-top: 8px;
  display: flex;
  gap: 10px;
}
.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
@media (max-width: 900px) {
  .two-col {
    grid-template-columns: 1fr;
  }
}
.notify-list {
  padding: 0 4px;
}
.notify-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  border-bottom: 1px solid #f5f7fa;
}
.notify-item:last-child {
  border-bottom: none;
}
.notify-title {
  font-size: 14px;
  font-weight: 500;
  color: #303133;
}
.notify-desc {
  font-size: 12px;
  color: #909399;
  margin-top: 3px;
}
.sub-hint {
  font-weight: 400;
  font-size: 12px;
  color: #909399;
}
.sync-card :deep(.el-card__body) {
  padding: 16px 20px;
}
.sync-card-body {
  display: flex;
  flex-direction: column;
}
.sync-actions {
  margin: 8px 0 12px;
}
.sync-status {
  margin-top: 8px;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 6px;
  display: flex;
  align-items: center;
}
.data-card {
  text-align: center;
  padding: 8px;
}
.data-card :deep(.el-card__body) {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 32px 24px;
}
.data-icon {
  font-size: 40px;
  margin-bottom: 16px;
  line-height: 1;
}
.export-icon {
  color: #409EFF;
}
.import-icon {
  color: #E6A23C;
}
.data-card-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 12px 0;
  color: #303133;
}
.data-card-desc {
  font-size: 13px;
  color: #606266;
  line-height: 1.7;
  margin-bottom: 24px;
  max-width: 340px;
}
.bottom-bar {
  position: sticky;
  bottom: 0;
  background: #fff;
  border-top: 1px solid #e4e7ed;
  padding: 14px 20px;
  margin-top: 16px;
  display: flex;
  gap: 12px;
  z-index: 100;
  box-shadow: 0 -2px 12px rgba(0,0,0,0.06);
}
</style>
