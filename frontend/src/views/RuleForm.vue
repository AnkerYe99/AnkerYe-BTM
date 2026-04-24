<template>
  <div>
    <h2>{{ isEdit ? '编辑规则' : '新建规则' }}</h2>
    <el-card>
      <el-form :model="form" label-width="130px" style="max-width:820px">
        <el-divider>基本信息</el-divider>
        <el-form-item label="规则名称" required>
          <el-input v-model="form.name" placeholder="如：官网前端" />
        </el-form-item>

        <el-form-item label="代理模式" required>
          <el-radio-group v-model="mode" @change="onModeChange">
            <el-radio-button label="http">HTTP</el-radio-button>
            <el-radio-button label="https">HTTPS</el-radio-button>
            <el-radio-button label="http+https">HTTP + HTTPS</el-radio-button>
            <el-radio-button label="tcp">TCP</el-radio-button>
            <el-radio-button label="udp">UDP</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <el-form-item label="监听协议栈">
          <el-radio-group v-model="form.listen_stack">
            <el-radio-button label="both">IPv4 + IPv6</el-radio-button>
            <el-radio-button label="v4">仅 IPv4</el-radio-button>
            <el-radio-button label="v6">仅 IPv6</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <!-- HTTP / HTTP+HTTPS 共有：域名 -->
        <template v-if="isHTTP">
          <el-form-item label="域名 server_name">
            <el-input v-model="form.server_name"
              placeholder="如 www.example.com，多个空格分隔，留空表示匹配所有" />
            <div style="color:#999;font-size:12px;margin-top:4px">不区分大小写；留空匹配所有域名</div>
          </el-form-item>
        </template>

        <!-- HTTP 端口 -->
        <el-form-item v-if="mode==='http' || mode==='http+https'" label="HTTP 端口" required>
          <el-input-number v-model="form.listen_port" :min="1" :max="65535" />
        </el-form-item>

        <!-- HTTPS 相关 -->
        <template v-if="mode==='https' || mode==='http+https'">
          <el-form-item label="HTTPS 端口" required>
            <el-input-number v-model="form.https_port" :min="1" :max="65535" />
          </el-form-item>
          <el-form-item label="SSL 证书" required>
            <el-select v-model="form.ssl_cert_id" placeholder="请选择证书" style="width:100%">
              <el-option v-for="c in certs" :key="c.id"
                :label="c.domain + '  (到期: '+c.expire_at+')'" :value="c.id" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="mode==='http+https'" label="HTTP→HTTPS 跳转">
            <el-switch v-model="form.ssl_redirect" :active-value="1" :inactive-value="0" />
            <span style="margin-left:12px;color:#999;font-size:12px">开启后 HTTP 端口自动 301 跳转到 HTTPS</span>
          </el-form-item>
        </template>

        <!-- TCP/UDP 端口 -->
        <el-form-item v-if="mode==='tcp' || mode==='udp'" label="监听端口" required>
          <el-input-number v-model="form.listen_port" :min="1" :max="65535" />
        </el-form-item>

        <el-divider>负载均衡</el-divider>
        <el-form-item label="算法">
          <el-radio-group v-model="form.lb_method">
            <el-radio-button label="round_robin">轮询</el-radio-button>
            <el-radio-button label="ip_hash">IP哈希</el-radio-button>
            <el-radio-button label="least_conn">最少连接</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <el-divider>健康检查</el-divider>
        <el-form-item label="启用">
          <el-switch v-model="form.hc_enabled" :active-value="1" :inactive-value="0" />
        </el-form-item>
        <template v-if="form.hc_enabled===1">
          <el-form-item label="间隔(秒)"><el-input-number v-model="form.hc_interval" :min="3" :max="600" /></el-form-item>
          <el-form-item label="超时(秒)"><el-input-number v-model="form.hc_timeout" :min="1" :max="60" /></el-form-item>
          <el-form-item v-if="isHTTP" label="检查路径">
            <el-input v-model="form.hc_path" placeholder="/" />
          </el-form-item>
          <el-form-item label="连续失败下线"><el-input-number v-model="form.hc_fall" :min="1" :max="10" /></el-form-item>
          <el-form-item label="连续成功恢复"><el-input-number v-model="form.hc_rise" :min="1" :max="10" /></el-form-item>
        </template>

        <el-divider>日志</el-divider>
        <el-form-item label="日志轮转大小">
          <el-input v-model="form.log_max_size" placeholder="5M / 10M / 100M">
            <template #append>超过此大小自动轮转压缩</template>
          </el-input>
        </el-form-item>

        <el-divider>后端节点 <el-tag type="info" size="small">至少 1 个</el-tag></el-divider>
        <el-table :data="form.servers" size="small" border>
          <el-table-column label="地址" width="200">
            <template #default="{row}"><el-input v-model="row.address" size="small" placeholder="IP 或域名" /></template>
          </el-table-column>
          <el-table-column label="端口" width="120">
            <template #default="{row}"><el-input-number v-model="row.port" size="small" :min="1" :max="65535" style="width:100px" /></template>
          </el-table-column>
          <el-table-column label="权重" width="120">
            <template #default="{row}"><el-input-number v-model="row.weight" size="small" :min="1" :max="100" style="width:100px" /></template>
          </el-table-column>
          <el-table-column label="状态" width="140">
            <template #default="{row}">
              <el-select v-model="row.state" size="small">
                <el-option label="启用" value="up" />
                <el-option label="禁用" value="disabled" />
              </el-select>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="80">
            <template #default="{$index}">
              <el-button size="small" type="danger" link @click="form.servers.splice($index,1)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-button size="small" icon="Plus" @click="addServer" style="margin-top:8px">添加节点</el-button>

        <el-divider>高级</el-divider>
        <el-form-item label="自定义指令">
          <el-input v-model="form.custom_config" type="textarea" :rows="3" placeholder="直接追加到 nginx 配置中（高级用户）" />
        </el-form-item>

        <el-form-item style="margin-top:24px">
          <el-button type="primary" size="large" :loading="saving" @click="submit">保存</el-button>
          <el-button size="large" @click="$router.push('/rules')">取消</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const route = useRoute()
const router = useRouter()
const isEdit = computed(() => !!route.params.id)
const saving = ref(false)
const certs = ref([])

// mode: http | https | http+https | tcp | udp
const mode = ref('http')
const isHTTP = computed(() => ['http', 'https', 'http+https'].includes(mode.value))

function onModeChange(v) {
  // 切换模式时设置合理的默认端口
  if (v === 'http')       { form.value.listen_port = 80;  form.value.https_enabled = 0 }
  if (v === 'https')      { form.value.listen_port = 0;   form.value.https_enabled = 1; form.value.https_port = 443 }
  if (v === 'http+https') { form.value.listen_port = 80;  form.value.https_enabled = 1; form.value.https_port = 443 }
  if (v === 'tcp')        { form.value.listen_port = 8080; form.value.https_enabled = 0 }
  if (v === 'udp')        { form.value.listen_port = 8080; form.value.https_enabled = 0 }
}

const form = ref({
  name: '', protocol: 'http', listen_port: 80, listen_stack: 'both',
  https_enabled: 0, https_port: 443, ssl_cert_id: null, ssl_redirect: 0,
  server_name: '',
  lb_method: 'round_robin',
  hc_enabled: 1, hc_interval: 10, hc_timeout: 3, hc_path: '/',
  hc_rise: 2, hc_fall: 3, log_max_size: '5M', custom_config: '',
  servers: [{ address: '', port: 80, weight: 1, state: 'up' }]
})

function addServer() {
  form.value.servers.push({ address: '', port: 80, weight: 1, state: 'up' })
}

// mode → form.protocol + form.https_enabled
function modeToForm() {
  if (mode.value === 'tcp')        form.value.protocol = 'tcp'
  else if (mode.value === 'udp')   form.value.protocol = 'udp'
  else                             form.value.protocol = 'http'

  form.value.https_enabled = (mode.value === 'https' || mode.value === 'http+https') ? 1 : 0
  if (mode.value === 'https') form.value.listen_port = 0
  if (mode.value !== 'http+https') form.value.ssl_redirect = 0
}

// form.protocol + form.https_enabled → mode
function formToMode(protocol, httpsEnabled, listenPort) {
  if (protocol === 'tcp') return 'tcp'
  if (protocol === 'udp') return 'udp'
  if (httpsEnabled === 1) return listenPort > 0 ? 'http+https' : 'https'
  return 'http'
}

async function submit() {
  if (!form.value.name) return ElMessage.warning('请输入规则名称')
  if (form.value.servers.length === 0) return ElMessage.warning('至少一个后端节点')
  if (form.value.servers.some(s => !s.address)) return ElMessage.warning('节点地址不能为空')

  modeToForm()
  const payload = { ...form.value }

  // 域名为空时传 _ 表示匹配所有
  if (!payload.server_name || !payload.server_name.trim()) payload.server_name = '_'

  if (payload.protocol !== 'http') {
    payload.https_enabled = 0; payload.https_port = null
    payload.ssl_cert_id = null; payload.ssl_redirect = 0; payload.server_name = ''
  }
  if (payload.https_enabled !== 1) {
    payload.https_port = null; payload.ssl_cert_id = null; payload.ssl_redirect = 0
  }

  saving.value = true
  try {
    if (isEdit.value) {
      await api.put(`/rules/${route.params.id}`, payload)
    } else {
      await api.post('/rules', payload)
    }
    ElMessage.success('已保存')
    router.push('/rules')
  } catch {}
  saving.value = false
}

onMounted(async () => {
  certs.value = (await api.get('/certs')).data
  if (isEdit.value) {
    const data = (await api.get(`/rules/${route.params.id}`)).data
    Object.assign(form.value, data)
    mode.value = formToMode(data.protocol, data.https_enabled, data.listen_port)
  }
})
</script>
