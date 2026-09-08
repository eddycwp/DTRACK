import { defineStore } from 'pinia'
import { api, downloadFile } from '../api'

/**
 * 生成"白名单/项目管理"通用版本库 store。
 *
 * 两个页面（白名单、项目管理）的结构完全一致：owner(白名单/项目) → versions(版本)，
 * 仅调用不同的 API 方法，故用工厂消除重复。对外暴露统一的 action 名，
 * 视图通过组合式函数 useVersionList 访问。
 *
 * @param {string} id pinia store id
 * @param {object} methods 差异化的 API 方法：
 *   - listOwners: () => Promise<owner[]>
 *   - importOwner: (payload) => Promise<{owner_id}>
 *   - listVersions: (ownerId) => Promise<version[]>
 *   - scanVersion: (vid) => Promise
 *   - deleteVersion: (vid) => Promise
 *   - downloadReport: (vid) => Promise<response>
 *   - downloadReportPdf: (vid) => Promise<response>
 */
export function createVersionStore(id, methods) {
  return defineStore(id, {
    state: () => ({
      owners: [],
      loading: false,
      versions: {} // ownerId -> [versions]
    }),
    actions: {
      async fetchOwners() {
        this.loading = true
        try {
          this.owners = await methods.listOwners()
        } finally {
          this.loading = false
        }
      },
      async importOwner(payload) {
        const r = await methods.importOwner(payload)
        await this.fetchOwners()
        if (r.owner_id) await this.fetchVersions(r.owner_id)
        return r
      },
      async fetchVersions(ownerId) {
        this.versions[ownerId] = await methods.listVersions(ownerId)
      },
      async scan(vid) {
        await methods.scanVersion(vid)
        // 轮询状态由视图负责；这里仅置为扫描中
        const v = this.findVersion(vid)
        if (v) v.scan_status = 'scanning'
      },
      async remove(vid) {
        await methods.deleteVersion(vid)
        await this.fetchOwners()
        // 仅刷新包含该版本的 owner，避免全量重刷所有已展开列表
        const ownerId = this._ownerOf(vid)
        if (ownerId !== null) await this.fetchVersions(ownerId)
      },
      async exportReport(vid, filename) {
        await downloadFile(filename, () => methods.downloadReport(vid))
      },
      async exportReportPdf(vid, filename) {
        await downloadFile(filename, () => methods.downloadReportPdf(vid))
      },
      findVersion(vid) {
        for (const list of Object.values(this.versions)) {
          const f = list.find((v) => v.id === vid)
          if (f) return f
        }
        return null
      },
      _ownerOf(vid) {
        for (const [ownerId, list] of Object.entries(this.versions)) {
          if (list.some((v) => v.id === vid)) return Number(ownerId)
        }
        return null
      }
    }
  })
}
