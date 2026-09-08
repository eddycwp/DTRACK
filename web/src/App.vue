<template>
  <el-container class="layout">
    <el-aside width="200px" class="aside">
      <div class="logo">DTrack</div>
      <el-menu :default-active="active" router class="menu">
        <el-menu-item index="/whitelist">
          <el-icon><Files /></el-icon><span>白名单管理</span>
        </el-menu-item>
        <el-menu-item index="/project">
          <el-icon><Box /></el-icon><span>项目管理</span>
        </el-menu-item>
        <el-menu-item index="/component">
          <el-icon><Coin /></el-icon><span>三方组件库</span>
        </el-menu-item>
        <el-menu-item index="/config">
          <el-icon><Setting /></el-icon><span>系统配置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="crumb">
          <el-icon class="crumb-icon"><component :is="icon" /></el-icon>
          <span class="title">{{ title }}</span>
        </div>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
    <ComponentDetailDrawer />
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { Files, Box, Coin, Setting } from '@element-plus/icons-vue'
import ComponentDetailDrawer from './components/ComponentDetailDrawer.vue'

const route = useRoute()
const active = computed(() => route.path)
const title = computed(() => route.meta.title || 'DTrack')
const ICONS = { whitelist: Files, project: Box, component: Coin, config: Setting }
const icon = computed(() => ICONS[route.name] || Files)
</script>

<style>
html, body, #app { height: 100%; margin: 0; }
.layout { height: 100vh; }

/* ---- 统一主题：浅色侧栏 + 品牌蓝，主区浅灰，整体协调 ---- */
.aside {
  background: #ffffff;
  border-right: 1px solid #e4e7ed;
  box-shadow: 2px 0 8px rgba(31, 45, 61, 0.04);
  display: flex;
  flex-direction: column;
}
.logo {
  height: 60px;
  line-height: 60px;
  text-align: center;
  font-size: 22px;
  font-weight: 700;
  color: #409eff;
  letter-spacing: 2px;
  border-bottom: 1px solid #f0f2f5;
}
.menu { border-right: none; background: transparent; }
.menu .el-menu-item {
  color: #606266;
  height: 46px;
  line-height: 46px;
  margin: 4px 8px;
  border-radius: 6px;
  transition: background 0.2s, color 0.2s;
}
.menu .el-menu-item:hover { background: #ecf5ff; color: #409eff; }
.menu .el-menu-item.is-active {
  background: #409eff;
  color: #fff;
  box-shadow: 0 2px 6px rgba(64, 158, 255, 0.35);
}

.header {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #fff;
  border-bottom: 1px solid #e4e7ed;
  padding: 0 20px;
}
.header .crumb {
  display: flex;
  align-items: center;
  gap: 8px;
}
.header .crumb-icon {
  font-size: 18px;
  color: #409eff;
}
.header .title {
  font-size: 17px;
  font-weight: 600;
  color: #303133;
  letter-spacing: 0.5px;
}
.header .brand {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 12px;
  color: #909399;
  font-size: 13px;
}
.header .brand-divider {
  width: 1px;
  height: 16px;
  background: #dcdfe6;
}
.header .brand-name {
  letter-spacing: 1px;
}

.main {
  background: #f5f7fa;
  padding: 16px;
  overflow-y: auto;
}
/* 统一表头工具栏：左侧功能按钮，右侧搜索/过滤 */
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 12px;
}
.toolbar .tb-left {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.toolbar .tb-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-left: auto;
}
.page .sub { color: #909399; }
.hint { color: #909399; padding: 8px; }

/* 页面容器卡片化，弱化背景差异 */
.page > .el-alert,
.page > .el-table,
.page > .el-form { border-radius: 8px; }
</style>
