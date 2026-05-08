import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/login', component: () => import('../views/Login.vue') },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../views/Dashboard.vue') },
      { path: 'rules', name: 'rules', component: () => import('../views/Rules.vue') },
      { path: 'rules/new', name: 'rule-new', component: () => import('../views/RuleForm.vue') },
      { path: 'rules/:id/edit', name: 'rule-edit', component: () => import('../views/RuleForm.vue') },
      { path: 'servers', name: 'servers', component: () => import('../views/Servers.vue') },
      { path: 'nodehealth', name: 'nodehealth', component: () => import('../views/NodeHealth.vue') },
      { path: 'certs', name: 'certs', component: () => import('../views/Certs.vue') },
      { path: 'traffic', name: 'traffic', component: () => import('../views/Traffic.vue') },
      { path: 'errorlogs', name: 'errorlogs', component: () => import('../views/ErrorLogs.vue') },
      { path: 'capture', name: 'capture', component: () => import('../views/Capture.vue') },
      { path: 'sync', name: 'sync', component: () => import('../views/SyncNodes.vue') },
      { path: 'filter', redirect: '/blacklist' },
      { path: 'blacklist', name: 'blacklist', component: () => import('../views/BlackList.vue') },
      { path: 'whitelist', name: 'whitelist', component: () => import('../views/WhiteList.vue') },
      { path: 'settings', name: 'settings', component: () => import('../views/Settings.vue') },
      { path: 'logs', name: 'logs', component: () => import('../views/LogsView.vue') }
    ]
  }
]

const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach((to, from, next) => {
  if (to.path !== '/login' && !localStorage.getItem('token')) {
    next('/login')
  } else {
    next()
  }
})

export default router
