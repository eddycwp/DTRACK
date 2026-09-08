<template>
  <div class="page">
    <div class="toolbar">
      <div class="tb-left">
        <el-button type="primary" :icon="UploadFilled" @click="importVisible = true">
          导入白名单
        </el-button>
      </div>
    </div>

    <el-table
      v-loading="store.loading"
      :data="store.owners"
      row-key="id"
      border
      :expand-row-keys="expandedKeys"
      @expand-change="onExpand"
      style="margin-top: 12px"
    >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div v-if="!store.versions[row.id]" class="hint">点击展开加载版本…</div>
          <VersionSubTable v-else :versions="store.versions[row.id]" :actions="versionActions" @cmd="onCmd" />
        </template>
      </el-table-column>
      <el-table-column prop="name" label="白名单（groupId:artifactId）" min-width="260" />
      <el-table-column prop="group_id" label="groupId" min-width="160" />
      <el-table-column prop="artifact_id" label="artifactId" min-width="160" />
      <el-table-column label="版本数" width="100">
        <template #default="{ row }">
          {{ (store.versions[row.id] || []).length || '—' }}
        </template>
      </el-table-column>
    </el-table>

    <ImportDialog ref-type="whitelist" v-model:visible="importVisible" @submit="onImportSubmit" />
    <VersionDetailDrawer v-model:visible="detailVisible" :ref-type="detailRefType" :vid="detailVid" />
    <ExportDialog
      v-model:visible="exportVisible"
      :version="exportTarget?.version"
      :exporting="exporting"
      @export="onExport"
    />
  </div>
</template>

<script setup>
import { UploadFilled } from '@element-plus/icons-vue'
import { useWhitelistStore } from '../stores/whitelist'
import { useVersionList } from '../composables/useVersionList'
import ImportDialog from '../components/ImportDialog.vue'
import VersionDetailDrawer from '../components/VersionDetailDrawer.vue'
import ExportDialog from '../components/ExportDialog.vue'
import VersionSubTable from '../components/VersionSubTable.vue'

const store = useWhitelistStore()
const {
  importVisible,
  detailVisible,
  detailVid,
  detailRefType,
  expandedKeys,
  versionActions,
  exportVisible,
  exportTarget,
  exporting,
  onExpand,
  onCmd,
  onExport,
  onImported,
  onImportSubmit
} = useVersionList({ store, refType: 'whitelist', filePrefix: 'whitelist' })
</script>

<style scoped>
.hint {
  color: #909399;
  padding: 8px 12px;
  font-size: 13px;
}
</style>
