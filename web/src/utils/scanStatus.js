// 扫描状态 → Element Plus 标签类型 / 中文文案（白名单、项目管理共用）

export const SCAN_STATUS_TYPE = {
  pending: 'info',
  scanning: 'warning',
  done: 'success',
  no_qianxin: 'info',
  failed: 'danger'
}

export const SCAN_STATUS_TEXT = {
  pending: '待扫描',
  scanning: '扫描中',
  done: '已完成',
  no_qianxin: '未配置奇安信',
  failed: '失败'
}

export function statusType(s) {
  return SCAN_STATUS_TYPE[s] || 'info'
}

export function statusText(s) {
  return SCAN_STATUS_TEXT[s] || s
}
