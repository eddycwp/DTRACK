<template>
  <div class="page">
    <div class="toolbar">
      <div class="tb-left">
        <span class="sub">共 {{ store.components.length }} 个组件</span>
      </div>
      <div class="tb-right">
        <el-input
          v-model="store.filters.q"
          placeholder="搜索名称 / group / 坐标"
          clearable
          style="width: 220px"
          @keyup.enter="store.fetchList()"
          @clear="store.fetchList()"
        />
        <el-select v-model="store.filters.is_whitelist" placeholder="类型" clearable style="width: 130px"
                   @change="store.fetchList()">
          <el-option label="白名单" :value="true" />
          <el-option label="非白名单" :value="false" />
        </el-select>
        <el-select v-model="store.filters.severity" placeholder="漏洞等级" clearable style="width: 130px"
                   @change="store.fetchList()">
          <el-option v-for="s in SEV_META" :key="s.key" :label="s.label" :value="s.key" />
        </el-select>
        <el-button type="primary" @click="store.fetchList()">查询</el-button>
      </div>
    </div>

    <el-table
      v-loading="store.loading"
      :data="store.components"
      border
      stripe
      @row-click="(row) => store.openDetail(row.coord)"
      style="cursor: pointer"
    >
      <el-table-column prop="coord" label="坐标" min-width="280" />
      <el-table-column prop="language" label="语言" width="90" />
      <el-table-column prop="license" label="License" width="160" show-overflow-tooltip />
      <el-table-column label="类型" width="110">
        <template #default="{ row }">
          <el-tag :type="row.is_whitelist ? 'success' : 'info'" size="small">
            {{ row.is_whitelist ? '白名单' : '非白名单' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="漏洞数" min-width="130">
        <template #default="{ row }">
          <div v-if="row.vuln_count > 0" class="sev-list">
            <span
              v-for="s in sevItems(row.vuln_counts)"
              :key="s.key"
              class="sev-item"
              :style="{ color: s.color }"
            >{{ s.label }}：{{ s.val }}</span>
          </div>
          <span v-else class="muted">无漏洞</span>
        </template>
      </el-table-column>
      <el-table-column label="被引用" width="90" prop="usage_count" />
      <el-table-column label="操作" width="90">
        <template #default="{ row }">
          <el-button link type="primary" @click.stop="store.openDetail(row.coord)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <ComponentDetailDrawer />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useComponentStore } from '../stores/component'
import ComponentDetailDrawer from '../components/ComponentDetailDrawer.vue'
import { SEV_META, sevItems } from '../utils/severity'

const store = useComponentStore()

onMounted(() => store.fetchList())
</script>

<style scoped>
.sev-list {
  display: flex;
  flex-direction: column;
}
.sev-item {
  line-height: 1.7;
  font-size: 12px;
  white-space: nowrap;
}
.muted {
  color: #c0c4cc;
}
</style>
