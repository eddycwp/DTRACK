<template>
  <el-drawer title="组件详情" v-model="visible" size="62%" :destroy-on-close="true">
    <template v-if="detail">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="坐标">{{ detail.coord }}</el-descriptions-item>
        <el-descriptions-item label="语言">{{ detail.language }}</el-descriptions-item>
        <el-descriptions-item label="License">{{ detail.license || '未知' }}</el-descriptions-item>
        <el-descriptions-item label="类型">
          <el-tag :type="detail.is_whitelist ? 'success' : 'info'">
            {{ detail.is_whitelist ? '白名单组件' : '非白名单' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-divider>漏洞信息（{{ detail.vulnerabilities.length }}）</el-divider>
      <div v-if="sevStats.length" class="sev-wrap">
        <el-tag
          v-for="s in sevStats"
          :key="s.key"
          :type="s.type"
          effect="light"
          size="small"
          class="sev-tag"
        >
          {{ s.label }}：{{ s.val }}
        </el-tag>
        <span class="total">合计 <b>{{ detail.vulnerabilities.length }}</b> 个</span>
      </div>
      <el-table :data="detail.vulnerabilities" border stripe empty-text="无已知漏洞">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="vuln-detail">
              <p><b>描述：</b>{{ row.description || '—' }}</p>
              <p><b>修复版本：</b>{{ row.fixed_version || '—' }}</p>
              <p><b>CWE/CVE：</b>{{ row.cwe || '—' }} / {{ row.cve || '—' }}</p>
              <p><b>解决方案：</b>{{ row.solution || '—' }}</p>
              <p v-if="row.references && row.references.length">
                <b>参考：</b>
                <a v-for="r in row.references" :key="r" :href="r" target="_blank">{{ r }}</a>
              </p>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="等级" width="90">
          <template #default="{ row }">
            <el-tag :type="sevType(row.severity)" effect="dark">{{ sevLabel(row.severity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="vuln_id" label="编号" width="160" />
        <el-table-column prop="title" label="标题" min-width="180" show-overflow-tooltip />
      </el-table>

      <el-divider>所属白名单版本</el-divider>
      <el-table :data="detail.whitelist_versions" border stripe empty-text="未在任何白名单中">
        <el-table-column prop="name" label="白名单" min-width="180" />
        <el-table-column prop="version" label="版本" width="120" />
        <el-table-column prop="dependency_type" label="依赖类型" width="110">
          <template #default="{ row }">
            <el-tag size="small">{{ zhDep(row.dependency_type) }}</el-tag>
          </template>
        </el-table-column>
      </el-table>

      <el-divider>被以下项目使用</el-divider>
      <el-table :data="detail.project_versions" border stripe empty-text="未被任何项目使用">
        <el-table-column prop="name" label="项目" min-width="180" />
        <el-table-column prop="version" label="版本" width="120" />
        <el-table-column prop="dependency_type" label="依赖类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" type="warning">{{ zhDep(row.dependency_type) }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </template>
  </el-drawer>
</template>

<script setup>
import { ref, watch, computed } from 'vue'
import { useComponentStore } from '../stores/component'
import { SEV_META } from '../utils/severity'

const store = useComponentStore()
const visible = ref(false)

watch(
  () => store.detailVisible,
  (v) => {
    visible.value = v
  }
)
watch(visible, (v) => {
  if (!v) store.closeDetail()
})

const detail = computed(() => store.detail)

// 按级别统计漏洞数量（需求：版本/组件详情分别列出不同级别漏洞数）
const sevStats = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const v of detail.value?.vulnerabilities || []) {
    if (counts[v.severity] !== undefined) counts[v.severity] += 1
  }
  return SEV_META.filter((s) => counts[s.key] > 0).map((s) => ({ ...s, val: counts[s.key] }))
})

function sevType(s) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', unknown: 'info' }[s] || 'info'
}
function sevLabel(s) {
  return (SEV_META.find((m) => m.key === s) || {}).label || s
}
function zhDep(t) {
  return t === 'direct' ? '直接依赖' : '传递依赖'
}
</script>

<style scoped>
.sev-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
}
.sev-tag {
  font-weight: 600;
}
.total {
  color: #909399;
}
.vuln-detail p {
  margin: 4px 0;
  color: #606266;
}
.vuln-detail a {
  margin-right: 10px;
  color: #409eff;
}
</style>
