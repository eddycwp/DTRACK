<template>
  <div ref="root" class="ac">
    <!-- 隐藏测量层：始终保留，用于重算排版 -->
    <div ref="meas" class="ac-meas" aria-hidden="true">
      <el-link
        v-for="it in items"
        :key="it.command"
        :underline="false"
        class="ac-meas-link"
      >{{ it.label }}</el-link>
      <el-link :underline="false" class="ac-meas-link">更多</el-link>
    </div>

    <el-link
      v-for="it in shown"
      :key="it.command"
      :type="it.type || 'primary'"
      :underline="false"
      class="ac-link"
      @click.stop="emit('command', it.command, row)"
    >{{ it.label }}</el-link>

    <el-dropdown
      v-if="hidden.length"
      trigger="click"
      @command="(cmd) => emit('command', cmd, row)"
    >
      <el-link :underline="false" class="ac-link">
        更多<el-icon class="el-icon--right"><ArrowDown /></el-icon>
      </el-link>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item
            v-for="it in hidden"
            :key="it.command"
            :command="it.command"
            :divided="it.divided"
          >{{ it.label }}</el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { ArrowDown } from '@element-plus/icons-vue'

const props = defineProps({
  // [{ label, command, type?, divided? }]
  items: { type: Array, required: true },
  row: { type: Object, default: null }
})
const emit = defineEmits(['command'])

const GAP = 14
const root = ref(null)
const meas = ref(null)
const measured = ref(false)
const widths = ref([])
const moreWidth = ref(0)
const available = ref(0)

async function measure() {
  if (!root.value || !meas.value) return
  await nextTick()
  const links = meas.value.querySelectorAll('.ac-meas-link')
  if (!links.length) return
  widths.value = Array.from(links)
    .slice(0, -1)
    .map((l) => l.getBoundingClientRect().width)
  moreWidth.value = links[links.length - 1].getBoundingClientRect().width
  available.value = root.value.clientWidth
  measured.value = true
}

const shown = computed(() => {
  if (!measured.value) return props.items
  const total = widths.value.reduce((s, w) => s + w + GAP, -GAP)
  if (total <= available.value) return props.items
  // 预留“更多”按钮的空间，再逐个放入可容纳的链接
  let used = moreWidth.value + GAP
  const list = []
  for (let i = 0; i < props.items.length; i++) {
    if (used + widths.value[i] + GAP <= available.value) {
      list.push(props.items[i])
      used += widths.value[i] + GAP
    } else {
      break
    }
  }
  return list
})

const hidden = computed(() => {
  if (!measured.value || shown.value.length >= props.items.length) return []
  return props.items.slice(shown.value.length)
})

let ro = null
onMounted(() => {
  measure()
  ro = new ResizeObserver(() => measure())
  if (root.value) ro.observe(root.value)
})
onUnmounted(() => ro && ro.disconnect())
watch(() => props.items, () => measure())
</script>

<style scoped>
.ac {
  display: flex;
  align-items: center;
  gap: 14px;
  white-space: nowrap;
}
.ac-link {
  font-size: 13px;
}
/* 测量层不影响布局 */
.ac-meas {
  position: absolute;
  left: -9999px;
  top: 0;
  visibility: hidden;
  pointer-events: none;
  display: flex;
  align-items: center;
  gap: 14px;
  white-space: nowrap;
}
</style>
