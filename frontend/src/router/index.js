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
      { path: 'certs', name: 'certs', component: () => import('../views/Certs.vue') },
      { path: 'sync', name: 'sync', component: () => import('../views/SyncNodes.vue') },
      { path: 'settings', name: 'settings', component: () => import('../views/Settings.vue') }
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
