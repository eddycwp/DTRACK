// 漏洞严重程度的中文标签、Element Plus tag 类型与文字颜色映射（共享给各视图/抽屉）。
export const SEV_META = [
  { key: 'critical', label: '超危', type: 'danger', color: '#d03050' },
  { key: 'high', label: '高危', type: 'danger', color: '#f56c6c' },
  { key: 'medium', label: '中危', type: 'warning', color: '#e6a23c' },
  { key: 'low', label: '低危', type: 'success', color: '#67c23a' },
  { key: 'unknown', label: '未知', type: 'info', color: '#909399' }
]

// 返回有数量（>0）的严重度项，便于列表紧凑展示。
export function sevItems(counts) {
  if (!counts) return []
  return SEV_META.filter((s) => (counts[s.key] || 0) > 0).map((s) => ({ ...s, val: counts[s.key] }))
}
