// 与后端 /api 交互的封装层。所有视图只调用这里导出的方法，不直接发请求。

const BASE = '/api'

// 统一 query 序列化：布尔转 '1'/'0'，空值自动忽略
function qs(params = {}) {
  const s = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    s.set(k, typeof v === 'boolean' ? (v ? '1' : '0') : String(v))
  }
  const str = s.toString()
  return str ? `?${str}` : ''
}

async function request(method, path, body) {
  const opts = { method, headers: {} }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const resp = await fetch(BASE + path, opts)
  if (resp.headers.get('Content-Type')?.includes('application/json')) {
    const data = await resp.json()
    if (!resp.ok) throw new Error(data.error || `请求失败 (${resp.status})`)
    return data
  }
  // 非 JSON（例如报表下载）——返回原始内容与文件名
  if (!resp.ok) throw new Error(`请求失败 (${resp.status})`)
  const cd = resp.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="?([^";]+)"?/)
  const filename = m ? m[1] : 'report.md'
  if (resp.headers.get('Content-Type')?.includes('application/pdf')) {
    return { blob: await resp.blob(), filename }
  }
  return { text: await resp.text(), filename }
}

export const api = {
  // 配置
  getConfig: () => request('GET', '/config'),
  updateConfig: (patch) => request('POST', '/config', patch),

  // GitLab 项目列表（导入弹窗用）
  listGitlabProjects: () => request('GET', '/gitlab/projects'),
  listGitlabRefs: (project) => request('GET', '/gitlab/refs' + qs({ project })),

  // 白名单
  listWhitelists: () => request('GET', '/whitelists'),
  importWhitelist: (payload) => request('POST', '/whitelists/import', payload),
  listWhitelistVersions: (id) => request('GET', `/whitelists/${id}/versions`),
  getWhitelistVersion: (vid) => request('GET', `/whitelists/version/${vid}`),
  listWhitelistVersionComponents: (vid) => request('GET', `/whitelists/version/${vid}/components`),
  scanWhitelistVersion: (vid) => request('POST', `/whitelists/version/${vid}/scan`),
  deleteWhitelistVersion: (vid) => request('DELETE', `/whitelists/version/${vid}`),
  downloadWhitelistReport: (vid) => request('GET', `/whitelists/version/${vid}/report`),
  downloadWhitelistReportPdf: (vid) => request('GET', `/whitelists/version/${vid}/report.pdf`),

  // 项目
  listProjects: () => request('GET', '/projects'),
  importProject: (payload) => request('POST', '/projects/import', payload),
  listProjectVersions: (id) => request('GET', `/projects/${id}/versions`),
  getProjectVersion: (vid) => request('GET', `/projects/version/${vid}`),
  listProjectVersionComponents: (vid) => request('GET', `/projects/version/${vid}/components`),
  scanProjectVersion: (vid) => request('POST', `/projects/version/${vid}/scan`),
  deleteProjectVersion: (vid) => request('DELETE', `/projects/version/${vid}`),
  downloadProjectReport: (vid) => request('GET', `/projects/version/${vid}/report`),
  downloadProjectReportPdf: (vid) => request('GET', `/projects/version/${vid}/report.pdf`),

  // 组件库
  listComponents: (params = {}) => request('GET', '/components' + qs(params)),
  getComponentDetail: (coord) => request('GET', '/components/detail' + qs({ coord }))
}

// 触发浏览器下载报表（markdown / pdf 通用）
export async function downloadFile(fn, getter) {
  const res = await getter()
  if (!res) throw new Error('未获取到下载内容')
  let blob
  if (res.text != null) {
    blob = new Blob([res.text], { type: 'text/markdown;charset=utf-8' })
  } else if (res.blob) {
    blob = res.blob
  } else {
    throw new Error('未获取到下载内容')
  }
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = res.filename || fn
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  // 延迟释放，避免浏览器尚未开始下载就被回收导致"点击无响应"
  setTimeout(() => {
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, 500)
}
