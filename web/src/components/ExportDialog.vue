<template>
  <el-dialog
    v-model="vis"
    title="导出报告"
    width="420px"
    append-to-body
    :close-on-click-modal="!exporting"
    :close-on-press-escape="!exporting"
    :show-close="!exporting"
    @closed="reset"
  >
    <p v-if="version" class="tip">版本：{{ version }}</p>
    <el-radio-group v-model="format" class="fmt-group" :disabled="exporting">
      <el-radio value="md">Markdown（.md）</el-radio>
      <el-radio value="pdf">PDF（.pdf）</el-radio>
    </el-radio-group>
    <template #footer>
      <el-button :disabled="exporting" @click="vis = false">取消</el-button>
      <el-button type="primary" :loading="exporting" @click="confirm">导出</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  visible: { type: Boolean, default: false },
  version: { type: String, default: '' },
  exporting: { type: Boolean, default: false }
})
const emit = defineEmits(['update:visible', 'export'])

const vis = computed({
  get: () => props.visible,
  set: (v) => emit('update:visible', v)
})

const format = ref('md')

function confirm() {
  emit('export', format.value)
}
function reset() {
  format.value = 'md'
}
</script>

<style scoped>
.tip {
  margin: 0 0 12px;
  color: #909399;
  font-size: 13px;
}
.fmt-group {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
}
</style>
