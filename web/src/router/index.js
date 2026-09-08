import { createRouter, createWebHashHistory } from 'vue-router'
import Whitelist from '../views/Whitelist.vue'
import Project from '../views/Project.vue'
import ComponentLib from '../views/ComponentLib.vue'
import ConfigView from '../views/Config.vue'

const routes = [
  { path: '/', redirect: '/whitelist' },
  { path: '/whitelist', name: 'whitelist', component: Whitelist, meta: { title: '白名单管理' } },
  { path: '/project', name: 'project', component: Project, meta: { title: '项目管理' } },
  { path: '/component', name: 'component', component: ComponentLib, meta: { title: '三方组件库' } },
  { path: '/config', name: 'config', component: ConfigView, meta: { title: '仓库配置' } }
]

export default createRouter({
  history: createWebHashHistory(),
  routes
})
