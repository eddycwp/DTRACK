<template>
  <el-drawer
    v-model="vis"
    :title="`版本详情（${refType === 'whitelist' ? '白名单' : '项目'}）`"
    size="760px"
  >
    <div v-loading="loading">
      <el-empty v-if="!detail && !loading" description="暂无数据" />
      <template v-if="detail">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="版本">{{ detail.version }}</el-descriptions-item>
          <el-descriptions-item label="来源">
            <el-tag size="small">{{ detail.source === 'gitlab' ? 'GitLab' : 'POM' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="扫描状态">
            <el-tag :type="statusType(detail.scan_status)" effect="light">
              {{ statusText(detail.scan_status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="扫描时间">{{ detail.scanned_at || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detail.error_msg" label="说明">
            <span class="err">{{ detail.error_msg }}</span>
          </el-descriptions-item>
        </el-descriptions>

        <h4 class="blk">组件概况</h4>
        <p class="desc-line">
          共 <b>{{ stats.component_count }}</b> 个三方组件（直接
          <b>{{ stats.direct_count }}</b> 个，传递 <b>{{ stats.transitive_count }}</b> 个）。
        </p>

        <h4 class="blk">漏洞统计</h4>
        <div class="sev-wrap">
          <el-tag
            v-for="s in SEV_META"
            :key="s.key"
            :type="s.type"
            effect="light"
            size="small"
            class="sev-tag"
          >
            {{ s.label }}：{{ (stats.vuln_counts && stats.vuln_counts[s.key]) || 0 }}
          </el-tag>
          <span class="total">合计 <b>{{ stats.vuln_total }}</b> 个</span>
        </div>

        <h4 class="blk">三方组件列表（{{ components.length }}）</h4>
        <el-table
          :data="components"
          border
          stripe
          size="small"
          @row-click="(row) => componentStore.openDetail(row.coord)"
          style="cursor: pointer; margin-bottom: 8px"
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
          <el-table-column label="漏洞数" min-width="190">
            <template #default="{ row }">
              <div v-if="row.vuln_count > 0" class="cell-sev">
                <div
                  v-for="s in sevItems(row.vuln_counts)"
                  :key="s.key"
                  class="sev-line"
                  :style="{ color: s.color }"
                >{{ s.label }}：{{ s.val }}</div>
              </div>
              <span v-else class="muted">无</span>
            </template>
          </el-table-column>
          <el-table-column prop="usage_count" label="被引用" width="90" />
          <el-table-column label="操作" width="90">
            <template #default="{ row }">
              <el-button link type="primary" @click.stop="componentStore.openDetail(row.coord)">详情</el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </div>
  </el-drawer>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { api } from '../api'
import { SEV_META, sevItems } from '../utils/severity'
import { statusType, statusText } from '../utils/scanStatus'
import { useComponentStore } from '../stores/component'

const props = defineProps({
  visible: { type: Boolean, default: false },
  refType: { type: String, default: 'whitelist' },
  vid: { type: Number, required: true }
})
const emit = defineEmits(['update:visible'])
const vis = computed({
  get: () => props.visible,
  set: (v) => emit('update:visible', v)
})

const loading = ref(false)
const detail = ref(null)
const components = ref([])
const componentStore = useComponentStore()

const stats = computed(
  () =>
    detail.value?.stats || {
      component_count: 0,
      direct_count: 0,
      transitive_count: 0,
      vuln_counts: {},
      vuln_total: 0
    }
)

async function load() {
  if (!props.vid) return
  loading.value = true
  try {
    const getter = props.refType === 'whitelist' ? api.getWhitelistVersion : api.getProjectVersion
    const listGetter = props.refType === 'whitelist'
      ? api.listWhitelistVersionComponents
      : api.listProjectVersionComponents
    detail.value = await getter(props.vid)
    components.value = await listGetter(props.vid)
  } catch (e) {
    detail.value = null
    components.value = []
  } finally {
    loading.value = false
  }
}

watch(
  () => props.visible,
  (v) => {
    if (v) load()
  }
)
</script>

<style scoped>
.blk {
  margin: 18px 0 8px;
}
.desc-line {
  margin: 0;
  color: #606266;
}
.sev-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.sev-tag {
  font-weight: 600;
}
.total {
  margin-left: 4px;
  color: #909399;
}
.err {
  color: #f56c6c;
}
.cell-sev {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.sev-line {
  font-size: 12px;
  line-height: 1.6;
}
.muted {
  color: #c0c4cc;
}
</style>
