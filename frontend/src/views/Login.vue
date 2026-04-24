<template>
  <div class="login-wrap">
    <el-card class="login-card">
      <div class="title">
        <el-icon :size="40" color="#409EFF"><Promotion /></el-icon>
        <h2>NginxFlow</h2>
        <p>智能流量管理平台</p>
      </div>
      <el-form :model="form" @submit.prevent="onLogin">
        <el-form-item>
          <el-input v-model="form.username" placeholder="用户名" prefix-icon="User" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码" prefix-icon="Lock" @keyup.enter="onLogin" />
        </el-form-item>
        <el-button type="primary" size="large" style="width:100%" :loading="loading" @click="onLogin">登录</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const router = useRouter()
const form = ref({ username: '', password: '' })
const loading = ref(false)

async function onLogin() {
  loading.value = true
  try {
    const res = await api.post('/auth/login', form.value)
    localStorage.setItem('token', res.data.token)
    localStorage.setItem('username', res.data.username)
    ElMessage.success('登录成功')
    router.push('/dashboard')
  } catch (e) {
    // 拦截器已提示
  }
  loading.value = false
}
</script>

<style scoped>
.login-wrap { display: flex; align-items: center; justify-content: center;
  height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.login-card { width: min(400px, 90vw); padding: 20px; }
.title { text-align: center; margin-bottom: 24px; }
.title h2 { margin: 8px 0 0; }
.title p { color: #999; margin: 4px 0 0; font-size: 13px; }
</style>
