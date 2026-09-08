import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

/**
 * 白名单/项目管理版本列表页的共用逻辑。
 *
 * @param {object} opts
 *   - store: 版本库 store 实例（由 createVersionStore 生成）
 *   - refType: 'whitelist' | 'project'（详情抽屉、导入弹窗使用）
 *   - filePrefix: 导出文件名前缀，如 'whitelist'
 */
export function useVersionList({ store, refType, filePrefix }) {
  const importVisible = ref(false)
  const detailVisible = ref(false)
  const detailVid = ref(0)
  const detailRefType = ref(refType)
  const expandedKeys = ref([])
  const versionActions = [
    { label: '详情', command: 'detail' },
    { label: '重新扫描', command: 'scan' },
    { label: '导出报告', command: 'export' },
    { label: '删除', command: 'delete', type: 'danger', divided: true }
  ]
  const exportVisible = ref(false)
  const exportTarget = ref(null)
  const exporting = ref(false)
  let timer = null

  function openDetail(vid) {
    detailVid.value = vid
    detailRefType.value = refType
    detailVisible.value = true
  }

  async function onExpand(row, expandedRows) {
    if (expandedRows.includes(row.id) && !store.versions[row.id]) {
      await store.fetchVersions(row.id)
    }
  }

  async function onDelete(vid) {
    await ElMessageBox.confirm('确认删除该版本？相关组件与漏洞将一并移除。', '提示', {
      type: 'warning'
    })
    await store.remove(vid)
    ElMessage.success('已删除')
  }

  function onCmd(cmd, v) {
    if (cmd === 'detail') openDetail(v.id)
    else if (cmd === 'scan') store.scan(v.id)
    else if (cmd === 'export') {
      exportTarget.value = v
      exportVisible.value = true
    } else if (cmd === 'delete') onDelete(v.id)
  }

  async function onExport(format) {
    const v = exportTarget.value
    if (!v) return
    exporting.value = true
    try {
      if (format === 'pdf') await store.exportReportPdf(v.id, `${filePrefix}_${v.version}.pdf`)
      else await store.exportReport(v.id, `${filePrefix}_${v.version}.md`)
      ElMessage.success('报告已生成，正在下载')
      exportVisible.value = false
    } catch (e) {
      ElMessage.error(e.message || '导出失败，请稍后重试')
    } finally {
      exporting.value = false
    }
  }

  function onImported() {
    expandedKeys.value = store.owners.map((o) => o.id)
  }

  // 接收 ImportDialog 提交的导入数据并调用 store（组件不再直接依赖 store）
  async function onImportSubmit(payload) {
    try {
      await store.importOwner(payload)
      ElMessage.success('导入成功，已开始漏洞扫描')
      onImported()
    } catch (e) {
      ElMessage.error('导入失败：' + e.message)
    }
  }

  // 轮询扫描中的版本
  async function poll() {
    for (const [ownerId, list] of Object.entries(store.versions)) {
      const scanning = list.filter((v) => v.scan_status === 'scanning')
      if (!scanning.length) continue
      await store.fetchVersions(Number(ownerId))
    }
  }

  onMounted(async () => {
    await store.fetchOwners()
    for (const o of store.owners) {
      await store.fetchVersions(o.id)
    }
    expandedKeys.value = store.owners.map((o) => o.id)
    timer = setInterval(poll, 3000)
  })
  onUnmounted(() => timer && clearInterval(timer))

  return {
    importVisible,
    detailVisible,
    detailVid,
    detailRefType,
    expandedKeys,
    versionActions,
    exportVisible,
    exportTarget,
    exporting,
    openDetail,
    onExpand,
    onCmd,
    onExport,
    onImported,
    onImportSubmit
  }
}
