// 通用格式化工具（共享给各视图/抽屉）。
// 将 "YYYY-MM-DD HH:MM:SS"（后端 _now() 格式）格式化为 "XXXX年XX月XX日 XX:XX:XX"。
export function formatDateTime(s) {
  if (!s) return ''
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/)
  if (!m) return String(s)
  return `${m[1]}年${m[2]}月${m[3]}日 ${m[4]}:${m[5]}:${m[6]}`
}
