<template>
  <div>
    <h2>{{ isEdit ? '编辑规则' : (isCopy ? '复制规则（另存为新规则）' : '新建规则') }}</h2>
    <el-alert v-if="isCopy" type="info" :closable="false" show-icon style="margin-bottom:12px"
      title="已复制源规则的全部参数，请修改域名等必要参数后保存。域名/端口若与现有规则重复，保存时会有提示。" />
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
            <el-radio-button label="tcpudp">TCP + UDP</el-radio-button>
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
        <el-form-item v-if="mode==='tcp' || mode==='udp' || mode==='tcpudp'" label="监听端口" required>
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
          <el-form-item v-if="isHTTP" label="检查 Host">
            <el-input v-model="form.hc_host" placeholder="留空=不设置 Host 头，填域名可精确匹配 vhost（推荐填写）" />
            <div style="color:#999;font-size:12px;margin-top:4px">填写后健康检查会携带该域名作为 Host 请求头；仅当后端返回 2xx/3xx 才视为健康</div>
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
        <el-form-item label="捕获日志上限">
          <el-input v-model="form.capture_max_size" placeholder="5M / 10M / 100M">
            <template #append>capture.log 超过此大小自动裁剪（保留最新）</template>
          </el-input>
        </el-form-item>

        <el-divider>后端节点 <el-tag type="info" size="small">至少 1 个</el-tag></el-divider>
        <el-table :data="form.servers" size="small" border>
          <el-table-column label="地址" width="200">
            <template #default="{row}"><el-input v-model="row.address" size="small" placeholder="IP 或域名" /></template>
          </el-table-column>
          <el-table-column label="端口" width="120">
            <template #default="{row}"><el-input-number v-model="row.port" size="small" :min="1" :max="65535" :controls="false" placeholder="端口" style="width:100px" /></template>
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

        <template v-if="isHTTP">
          <el-divider>访问控制</el-divider>
          <el-form-item label="IP 限制">
            <el-radio-group v-model="form.ip_acl_mode">
              <el-radio-button label="off">不限制</el-radio-button>
              <el-radio-button label="allow">白名单（仅允许名单内）</el-radio-button>
              <el-radio-button label="deny">黑名单（拒绝名单内）</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="form.ip_acl_mode !== 'off'" label="IP / CIDR 名单" required>
            <el-input
              v-model="form.ip_acl_list"
              type="textarea"
              :rows="5"
              placeholder="一行一条，例如：&#10;118.143.68.96/28&#10;161.153.89.153&#10;2001:db8::/32"
            />
            <div style="color:#999;font-size:12px;margin-top:4px;line-height:1.7">
              只能填 IP 或 CIDR 网段，一行一条（也支持逗号分隔），<code>#</code> 开头为注释。<br />
              匹配的是<strong>访客真实 IP</strong>（已做 real_ip 还原），被拒绝时返回 <strong>403</strong>。<br />
              <strong style="color:#e6a23c">注意：白名单模式下，不在名单里的所有来源都会被拒绝，请先确认自己的出口 IP 已加入，避免把自己关在门外。</strong>
              <template v-if="form.ssl_redirect === 1">
                <br /><strong style="color:#e6a23c">当前已开启 HTTP→HTTPS 跳转：HTTP 端口会先 301 跳转，IP 限制在跳转后的 HTTPS 端口上生效。</strong>
              </template>
            </div>
          </el-form-item>
        </template>

        <el-divider>高级</el-divider>
        <el-form-item label="记录请求体">
          <el-switch v-model="form.capture_body" :active-value="1" :inactive-value="0" />
          <span style="margin-left:12px;color:#999;font-size:12px">
            开启后将 POST 请求体（含 body）写到 <code>rule_X_capture.log</code>，可在「请求捕获」页查看，用于调试 / 测试数据回放。
            <strong style="color:#e6a23c">注意：会包含敏感字段（密码 / token），仅在调试时启用</strong>
          </span>
        </el-form-item>
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
const isCopy = computed(() => !route.params.id && !!route.query.copyFrom)
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
  if (v === 'tcpudp')     { form.value.listen_port = 8080; form.value.https_enabled = 0 }
}

const form = ref({
  name: '', protocol: 'http', listen_port: 80, listen_stack: 'both',
  https_enabled: 0, https_port: 443, ssl_cert_id: null, ssl_redirect: 0,
  server_name: '',
  lb_method: 'round_robin',
  hc_enabled: 1, hc_interval: 10, hc_timeout: 3, hc_path: '/', hc_host: '',
  hc_rise: 2, hc_fall: 3, log_max_size: '5M', capture_max_size: '5M', custom_config: '',
  capture_body: 0,
  ip_acl_mode: 'off', ip_acl_list: '',
  servers: [{ address: '', port: null, weight: 1, state: 'up' }]
})

function addServer() {
  form.value.servers.push({ address: '', port: null, weight: 1, state: 'up' })
}

// mode → form.protocol + form.https_enabled
function modeToForm() {
  if (mode.value === 'tcp')        form.value.protocol = 'tcp'
  else if (mode.value === 'udp')   form.value.protocol = 'udp'
  else if (mode.value === 'tcpudp') form.value.protocol = 'tcpudp'
  else                             form.value.protocol = 'http'

  form.value.https_enabled = (mode.value === 'https' || mode.value === 'http+https') ? 1 : 0
  if (mode.value === 'https') form.value.listen_port = 0
  if (mode.value !== 'http+https') form.value.ssl_redirect = 0
}

// form.protocol + form.https_enabled → mode
function formToMode(protocol, httpsEnabled, listenPort) {
  if (protocol === 'tcp') return 'tcp'
  if (protocol === 'udp') return 'udp'
  if (protocol === 'tcpudp') return 'tcpudp'
  if (httpsEnabled === 1) return listenPort > 0 ? 'http+https' : 'https'
  return 'http'
}

// IP / CIDR 校验：这里只做即时提示，最终以后端 net.ParseIP/ParseCIDR 的严格校验为准
function isIPv4(s) {
  const p = s.split('.')
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && +x <= 255)
}
function isIPv6(s) {
  if (!s.includes(':')) return false
  if ((s.match(/::/g) || []).length > 1) return false
  return /^[0-9a-fA-F:.]+$/.test(s)
}
function isIPOrCIDR(s) {
  let addr = s, prefix = null
  const slash = s.indexOf('/')
  if (slash >= 0) {
    addr = s.slice(0, slash)
    prefix = s.slice(slash + 1)
    if (!/^\d{1,3}$/.test(prefix)) return false
  }
  if (isIPv4(addr)) return prefix === null || +prefix <= 32
  if (isIPv6(addr)) return prefix === null || +prefix <= 128
  return false
}

async function submit() {
  if (!form.value.name) return ElMessage.warning('请输入规则名称')
  if (form.value.servers.length === 0) return ElMessage.warning('至少一个后端节点')
  if (form.value.servers.some(s => !s.address)) return ElMessage.warning('节点地址不能为空')
  if (form.value.servers.some(s => !s.port)) return ElMessage.warning('节点端口不能为空')

  modeToForm()
  const payload = { ...form.value }

  // 域名为空时传 _ 表示匹配所有
  if (!payload.server_name || !payload.server_name.trim()) payload.server_name = '_'

  if (!['http'].includes(payload.protocol)) {
    payload.https_enabled = 0; payload.https_port = null
    payload.ssl_cert_id = null; payload.ssl_redirect = 0
    if (payload.protocol !== 'http') payload.server_name = ''
  }
  if (payload.https_enabled !== 1) {
    payload.https_port = null; payload.ssl_cert_id = null; payload.ssl_redirect = 0
  }

  // IP 访问控制：仅 HTTP 规则支持，其余协议一律清空
  if (payload.protocol !== 'http') {
    payload.ip_acl_mode = 'off'; payload.ip_acl_list = ''
  }
  if (payload.ip_acl_mode === 'off') {
    payload.ip_acl_list = ''
  } else {
    // 先按行剥掉注释再拆条目：注释里常带空格，直接按空格切会把 "# 内网段" 拆成两个"条目"
    const items = [...new Set(
      (payload.ip_acl_list || '')
        .split('\n')
        .map(line => line.split('#')[0])
        .flatMap(line => line.split(/[\r,;\s]+/))
        .map(s => s.trim())
        .filter(Boolean)
    )]
    if (items.length === 0) return ElMessage.warning('启用 IP 限制时，名单不能为空')
    const bad = items.filter(s => !isIPOrCIDR(s))
    if (bad.length > 0) return ElMessage.warning('IP 名单格式错误：' + bad.join('、'))
    payload.ip_acl_list = items.join('\n')
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
  } else if (isCopy.value) {
    const data = (await api.get(`/rules/${route.query.copyFrom}`)).data
    // 复制源规则全部参数，但去掉身份/状态字段，作为新规则保存
    delete data.id
    delete data.status
    delete data.created_at
    delete data.updated_at
    if (Array.isArray(data.servers)) {
      data.servers = data.servers.map(s => ({
        address: s.address, port: s.port, weight: s.weight || 1, state: s.state || 'up'
      }))
    }
    Object.assign(form.value, data)
    form.value.name = (data.name || '') + ' - 副本'
    mode.value = formToMode(data.protocol, data.https_enabled, data.listen_port)
  }
})
</script>
