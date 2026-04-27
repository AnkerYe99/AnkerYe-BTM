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
            <span class="card-title">基本设置</span>
          </template>
          <el-form :model="form" label-width="150px" class="section-form">
            <el-form-item label="平台名称">
              <el-input v-model="form.site_title" placeholder="AnkerYe - 流量管理平台" style="max-width:360px" clearable />
              <div class="field-hint">显示在浏览器标签页和侧边栏顶部，留空恢复默认名称</div>
            </el-form-item>
          </el-form>
        </el-card>
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
        <!-- 同步 Token 设置（主节点） -->
        <el-card shadow="never" class="section-card">
          <template #header>
            <span class="card-title">同步 Token</span>
            <span class="card-subtitle">作为主节点时，从节点使用此 Token 拉取本机数据</span>
          </template>
          <div style="max-width:520px;padding:4px 0">
            <el-form-item label="同步 Token" label-width="100px">
              <div style="display:flex;gap:8px;width:100%">
                <el-input v-model="form.sync_token"
                  placeholder="设置后从节点凭此 Token 拉取数据" style="flex:1" />
                <el-button @click="genToken">生成</el-button>
              </div>
              <div class="field-hint">所有同步类型共用同一个 Token，从节点填入对应主节点地址和此 Token 即可</div>
            </el-form-item>
          </div>
        </el-card>

        <!-- 从节点设置 -->
        <el-card shadow="never" class="section-card" style="margin-top:16px">
          <template #header>
            <span class="card-title">从节点设置</span>
            <span class="card-subtitle">配置本机从哪些主节点拉取数据，可独立开关每种同步类型</span>
          </template>
          <div class="slave-sync-list">

            <!-- 规则同步 -->
            <div class="slave-sync-item">
              <div class="slave-sync-header">
                <div class="slave-sync-label">
                  <el-icon style="color:#409EFF"><Connection /></el-icon>
                  <span>规则同步</span>
                </div>
                <el-switch v-model="form.slave_rules_enabled" active-value="1" inactive-value="0"
                  active-text="开启" inactive-text="关闭" />
              </div>
              <div class="slave-sync-body" :class="{ 'slave-sync-disabled': form.slave_rules_enabled === '0' }">
                <el-form :model="form" label-width="90px" size="small">
                  <el-form-item label="主节点地址">
                    <el-input v-model="form.slave_rules_url" placeholder="http://主节点IP:端口"
                      :disabled="form.slave_rules_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="主节点 Token">
                    <el-input v-model="form.slave_rules_token"
                      placeholder="主节点同步 Token" :disabled="form.slave_rules_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="同步间隔">
                    <el-input-number v-model.number="form.slave_rules_interval" :min="10" :max="3600"
                      style="width:120px" :disabled="form.slave_rules_enabled === '0'" />
                    <span style="margin-left:8px;color:#909399;font-size:13px">秒/次</span>
                  </el-form-item>
                </el-form>
                <div class="slave-sync-actions">
                  <el-button size="small" type="primary" plain :loading="triggeringRules"
                    :disabled="form.slave_rules_enabled === '0'" @click="triggerRules">立即同步</el-button>
                  <div v-if="form.slave_rules_last_sync_at" class="sync-inline-status">
                    <el-tag :type="form.slave_rules_last_status==='ok'?'success':form.slave_rules_last_status==='syncing'?'warning':'danger'" size="small" effect="plain">
                      {{ form.slave_rules_last_status==='ok'?'正常':form.slave_rules_last_status==='syncing'?'同步中':'异常' }}
                    </el-tag>
                    <span style="color:#909399;font-size:12px">{{ form.slave_rules_last_sync_at }}</span>
                    <span v-if="form.slave_rules_last_msg" style="color:#606266;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ form.slave_rules_last_msg }}</span>
                  </div>
                </div>
              </div>
            </div>

            <el-divider />

            <!-- 证书同步 -->
            <div class="slave-sync-item">
              <div class="slave-sync-header">
                <div class="slave-sync-label">
                  <el-icon style="color:#67C23A"><Lock /></el-icon>
                  <span>证书同步</span>
                </div>
                <el-switch v-model="form.slave_certs_enabled" active-value="1" inactive-value="0"
                  active-text="开启" inactive-text="关闭" />
              </div>
              <div class="slave-sync-body" :class="{ 'slave-sync-disabled': form.slave_certs_enabled === '0' }">
                <el-form :model="form" label-width="90px" size="small">
                  <el-form-item label="主节点地址">
                    <el-input v-model="form.slave_certs_url" placeholder="http://主节点IP:端口"
                      :disabled="form.slave_certs_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="主节点 Token">
                    <el-input v-model="form.slave_certs_token"
                      placeholder="主节点同步 Token" :disabled="form.slave_certs_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="同步间隔">
                    <el-input-number v-model.number="form.slave_certs_interval" :min="10" :max="3600"
                      style="width:120px" :disabled="form.slave_certs_enabled === '0'" />
                    <span style="margin-left:8px;color:#909399;font-size:13px">秒/次</span>
                  </el-form-item>
                </el-form>
                <div class="slave-sync-actions">
                  <el-button size="small" type="primary" plain :loading="triggeringCerts"
                    :disabled="form.slave_certs_enabled === '0'" @click="triggerCerts">立即同步</el-button>
                  <div v-if="form.slave_certs_last_sync_at" class="sync-inline-status">
                    <el-tag :type="form.slave_certs_last_status==='ok'?'success':form.slave_certs_last_status==='syncing'?'warning':'danger'" size="small" effect="plain">
                      {{ form.slave_certs_last_status==='ok'?'正常':form.slave_certs_last_status==='syncing'?'同步中':'异常' }}
                    </el-tag>
                    <span style="color:#909399;font-size:12px">{{ form.slave_certs_last_sync_at }}</span>
                    <span v-if="form.slave_certs_last_msg" style="color:#606266;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ form.slave_certs_last_msg }}</span>
                  </div>
                </div>
              </div>
            </div>

            <el-divider />

            <!-- 黑白名单同步 -->
            <div class="slave-sync-item">
              <div class="slave-sync-header">
                <div class="slave-sync-label">
                  <el-icon style="color:#E6A23C"><Filter /></el-icon>
                  <span>黑白名单同步</span>
                </div>
                <el-switch v-model="form.slave_filter_enabled" active-value="1" inactive-value="0"
                  active-text="开启" inactive-text="关闭" />
              </div>
              <div class="slave-sync-body" :class="{ 'slave-sync-disabled': form.slave_filter_enabled === '0' }">
                <el-form :model="form" label-width="90px" size="small">
                  <el-form-item label="主节点地址">
                    <el-input v-model="form.slave_filter_url" placeholder="http://主节点IP:端口"
                      :disabled="form.slave_filter_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="主节点 Token">
                    <el-input v-model="form.slave_filter_token"
                      placeholder="主节点同步 Token" :disabled="form.slave_filter_enabled === '0'" />
                  </el-form-item>
                  <el-form-item label="同步时间">
                    <el-input v-model="form.slave_filter_time" placeholder="03:00" style="width:120px"
                      :disabled="form.slave_filter_enabled === '0'" />
                    <span style="margin-left:8px;color:#909399;font-size:13px">每天定时（HH:MM）</span>
                  </el-form-item>
                </el-form>
                <div class="slave-sync-actions">
                  <el-button size="small" type="primary" plain :loading="triggeringFilter"
                    :disabled="form.slave_filter_enabled === '0'" @click="triggerFilter">立即同步</el-button>
                  <div v-if="form.slave_filter_last_sync_at" class="sync-inline-status">
                    <el-tag :type="form.slave_filter_last_status==='ok'?'success':form.slave_filter_last_status==='syncing'?'warning':'danger'" size="small" effect="plain">
                      {{ form.slave_filter_last_status==='ok'?'正常':form.slave_filter_last_status==='syncing'?'同步中':'异常' }}
                    </el-tag>
                    <span style="color:#909399;font-size:12px">{{ form.slave_filter_last_sync_at }}</span>
                    <span v-if="form.slave_filter_last_msg" style="color:#606266;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ form.slave_filter_last_msg }}</span>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </el-card>
      </el-tab-pane>

      <!-- ── 数据管理 ── -->
      <!-- ── 系统更新 ── -->
      <el-tab-pane label="系统更新" name="update">
        <el-card shadow="never" class="section-card">
          <template #header>
            <span class="card-title">在线升级</span>
            <span class="card-subtitle">从仓库拉取最新版本，数据库与配置文件完整保留</span>
          </template>

          <!-- 版本信息 -->
          <div class="update-version-row">
            <div class="update-version-item">
              <span class="update-label">当前版本</span>
              <el-tag size="large" type="info" effect="plain">{{ updateInfo.current || '—' }}</el-tag>
            </div>
            <div class="update-version-arrow">→</div>
            <div class="update-version-item">
              <span class="update-label">最新版本</span>
              <el-tag size="large" :type="updateInfo.has_update ? 'success' : 'info'" effect="plain">
                {{ updateInfo.latest || '—' }}
              </el-tag>
            </div>
            <div v-if="updateInfo.source" class="update-source">
              <el-tag size="small" type="warning" effect="plain">{{ updateInfo.source }}</el-tag>
            </div>
          </div>

          <!-- 操作按钮 -->
          <div class="update-actions">
            <el-button :icon="Refresh" @click="checkUpdate" :loading="checking">检查更新</el-button>
            <el-button
              type="primary"
              :icon="Upload"
              :loading="upgrading"
              :disabled="!updateInfo.has_update || upgrading"
              @click="applyUpdate"
            >
              {{ upgrading ? '升级中…' : '立即升级' }}
            </el-button>
          </div>

          <!-- 更新说明 -->
          <div v-if="updateInfo.notes" class="update-notes">
            <div class="update-notes-title">更新说明</div>
            <pre class="update-notes-body">{{ updateInfo.notes }}</pre>
          </div>

          <!-- 未找到更新 -->
          <div v-if="updateChecked && !updateInfo.has_update" class="update-ok">
            <el-icon color="#67c23a"><CircleCheck /></el-icon> 已是最新版本
          </div>

          <!-- 内网 Gitea 配置 -->
          <el-divider content-position="left" style="margin-top:24px">内网 Gitea 配置（可选）</el-divider>
          <el-form label-width="130px" style="max-width:520px">
            <el-form-item label="Gitea 地址">
              <el-input v-model="form.update_gitea_url" placeholder="http://10.x.x.x:3000（留空则使用 GitHub）" clearable />
              <div class="field-hint">填写后优先从内网 Gitea 检查并下载更新，留空使用 GitHub</div>
            </el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

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
import { Refresh, Upload, CircleCheck } from '@element-plus/icons-vue'
import api from '../api'

const activeTab = ref('nginx')
const form = ref({})
const testingEmail = ref(false)
const smtpProvider = ref('')
const triggeringRules = ref(false)
const triggeringCerts = ref(false)
const triggeringFilter = ref(false)
const checking = ref(false)
const upgrading = ref(false)
const updateChecked = ref(false)
const updateInfo = ref({ current: '', latest: '', has_update: false, notes: '', source: '' })

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
  // 同步更新页面标题
  const title = data.site_title || 'AnkerYe - 流量管理平台'
  document.title = title
  localStorage.setItem('site_title', title)
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

function nowStr() {
  const d = new Date(), p = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// 轮询直到状态不再是 syncing，最多 30 秒
function pollUntilDone(statusKey, maxMs = 30000) {
  const start = Date.now()
  const check = async () => {
    await load()
    if (form.value[statusKey] === 'syncing' && Date.now() - start < maxMs)
      setTimeout(check, 3000)
  }
  setTimeout(check, 3000)
}

async function triggerRules() {
  if (!form.value.slave_rules_url) { ElMessage.warning('请先设置主节点地址'); return }
  triggeringRules.value = true
  form.value.slave_rules_last_sync_at = nowStr()
  form.value.slave_rules_last_status = 'syncing'
  form.value.slave_rules_last_msg = '同步中，请稍等...'
  try {
    await api.post('/sync/trigger_rules')
    pollUntilDone('slave_rules_last_status')
  } catch (e) { ElMessage.error('触发失败') }
  triggeringRules.value = false
}

async function triggerCerts() {
  if (!form.value.slave_certs_url) { ElMessage.warning('请先设置主节点地址'); return }
  triggeringCerts.value = true
  form.value.slave_certs_last_sync_at = nowStr()
  form.value.slave_certs_last_status = 'syncing'
  form.value.slave_certs_last_msg = '同步中，请稍等...'
  try {
    await api.post('/sync/trigger_certs')
    pollUntilDone('slave_certs_last_status')
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

async function triggerFilter() {
  if (!form.value.slave_filter_url) { ElMessage.warning('请先设置主节点地址'); return }
  triggeringFilter.value = true
  form.value.slave_filter_last_sync_at = nowStr()
  form.value.slave_filter_last_status = 'syncing'
  form.value.slave_filter_last_msg = '同步中，请稍等...'
  try {
    await api.post('/sync/trigger_filter')
    pollUntilDone('slave_filter_last_status')
  } catch (e) { ElMessage.error('触发失败') }
  triggeringFilter.value = false
}

async function checkUpdate() {
  checking.value = true
  updateChecked.value = false
  try {
    const res = await api.get('/update/check')
    updateInfo.value = res.data
    updateChecked.value = true
    if (!res.data.has_update) ElMessage.success('已是最新版本 ' + res.data.latest)
  } catch (e) {
    ElMessage.error(e?.response?.data?.msg || '检查失败，请确认仓库已发布 Release')
  }
  checking.value = false
}

async function applyUpdate() {
  try {
    await ElMessageBox.confirm(
      `确认升级到 ${updateInfo.value.latest}？\n\n• 数据库与配置文件完整保留\n• 服务将在约 3 秒后自动重启\n• 重启期间页面短暂无响应，刷新即可`,
      '确认升级', { type: 'warning', confirmButtonText: '确认升级', cancelButtonText: '取消' }
    )
  } catch { return }
  upgrading.value = true
  try {
    const res = await api.post('/update/apply')
    ElMessage.success({ message: res.data.msg, duration: 6000 })
    setTimeout(() => { upgrading.value = false; checkUpdate() }, 8000)
  } catch (e) {
    ElMessage.error(e?.response?.data?.msg || '升级失败')
    upgrading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.update-version-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}
.update-version-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}
.update-label {
  font-size: 12px;
  color: #909399;
}
.update-version-arrow {
  font-size: 20px;
  color: #c0c4cc;
  margin-top: 14px;
}
.update-source {
  margin-top: 14px;
}
.update-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}
.update-notes {
  background: #f8f9fa;
  border-radius: 6px;
  padding: 12px 16px;
  margin-top: 8px;
}
.update-notes-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 8px;
}
.update-notes-body {
  font-size: 12px;
  color: #606266;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow-y: auto;
}
.update-ok {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #67c23a;
  font-size: 14px;
  margin-top: 4px;
}

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
/* 从节点同步列表 */
.slave-sync-list {
  padding: 0 4px;
}
.slave-sync-item {
  padding: 16px 0;
}
.slave-sync-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.slave-sync-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}
.slave-sync-body {
  background: #fafafa;
  border: 1px solid #f0f2f5;
  border-radius: 8px;
  padding: 16px 20px 8px;
  transition: opacity 0.2s;
}
.slave-sync-body.slave-sync-disabled {
  opacity: 0.45;
  pointer-events: none;
}
.slave-sync-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0 4px;
  flex-wrap: wrap;
}
.sync-inline-status {
  display: flex;
  align-items: center;
  gap: 8px;
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
