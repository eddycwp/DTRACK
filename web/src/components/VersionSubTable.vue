<template>
  <el-table :data="versions" border size="small">
    <el-table-column prop="version" label="版本" width="140" />
    <el-table-column label="来源" width="120">
      <template #default="{ row: v }">
        <el-tooltip v-if="v.source_ref" :content="v.source_ref" placement="top">
          <el-tag size="small" :type="sourceType(v.source)">{{ sourceLabel(v.source) }}</el-tag>
        </el-tooltip>
        <el-tag v-else size="small" :type="sourceType(v.source)">{{ sourceLabel(v.source) }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column prop="scan_status" label="扫描状态" width="220">
      <template #default="{ row: v }">
        <el-tag :type="statusType(v.scan_status)" effect="light">
          {{ statusText(v.scan_status) }}
        </el-tag>
        <div v-if="v.scan_status === 'done' && v.scanned_at" class="scan-time">
          {{ formatDateTime(v.scanned_at) }}
        </div>
      </template>
    </el-table-column>
    <el-table-column label="漏洞统计" min-width="320">
      <template #default="{ row: v }">
        <div v-if="v.stats && v.stats.vuln_total > 0" class="sev-list">
          <span
            v-for="s in sevItems(v.stats.vuln_counts)"
            :key="s.key"
            class="sev-item"
            :style="{ color: s.color }"
          >{{ s.label }}：{{ s.val }}</span>
        </div>
        <span v-else class="muted">无漏洞</span>
      </template>
    </el-table-column>
    <el-table-column label="操作" min-width="260" fixed="right">
      <template #default="{ row: v }">
        <ActionCell :items="actions" :row="v" @command="(cmd) => $emit('cmd', cmd, v)" />
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup>
import ActionCell from './ActionCell.vue'
import { sevItems } from '../utils/severity'
import { formatDateTime } from '../utils/format'
import { statusType, statusText } from '../utils/scanStatus'

defineProps({
  versions: { type: Array, required: true },
  actions: { type: Array, required: true }
})
defineEmits(['cmd'])

const SOURCE_LABEL = {
  pom: 'POM',
  gitlab: 'GitLab',
  'gitlab-jar': 'GitLab-Jar',
  harbor: 'Harbor',
  docker: 'Docker'
}
const SOURCE_TYPE = {
  pom: 'info',
  gitlab: 'primary',
  'gitlab-jar': 'primary',
  harbor: 'warning',
  docker: 'success'
}
function sourceLabel(s) {
  return SOURCE_LABEL[s] || s || 'POM'
}
function sourceType(s) {
  return SOURCE_TYPE[s] || 'info'
}
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
.scan-time {
  margin-top: 2px;
  font-size: 12px;
  line-height: 1.5;
  color: #909399;
  white-space: nowrap;
}
</style>
