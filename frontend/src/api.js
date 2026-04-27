import axios from 'axios'
import router from './router'
import { ElMessage } from 'element-plus'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 60000
})

// 每次请求更新活跃时间，用于无操作自动退出
function touchActivity() {
  localStorage.setItem('lastActivity', Date.now())
}

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  touchActivity()
  return cfg
})

api.interceptors.response.use(
  res => {
    if (res.data && res.data.code !== undefined && res.data.code !== 0) {
      ElMessage.error(res.data.msg || '请求失败')
      return Promise.reject(res.data)
    }
    return res.data
  },
  err => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('lastActivity')
      router.push('/login')
      ElMessage.error('登录已过期，请重新登录')
    } else {
      ElMessage.error(err.response?.data?.msg || err.message || '网络错误')
    }
    return Promise.reject(err)
  }
)

export { touchActivity }
export default api
