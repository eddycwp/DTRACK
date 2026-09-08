import { api } from '../api'
import { createVersionStore } from './versionStore'

export const useWhitelistStore = createVersionStore('whitelist', {
  listOwners: () => api.listWhitelists(),
  importOwner: (payload) => api.importWhitelist(payload),
  listVersions: (ownerId) => api.listWhitelistVersions(ownerId),
  scanVersion: (vid) => api.scanWhitelistVersion(vid),
  deleteVersion: (vid) => api.deleteWhitelistVersion(vid),
  downloadReport: (vid) => api.downloadWhitelistReport(vid),
  downloadReportPdf: (vid) => api.downloadWhitelistReportPdf(vid)
})
