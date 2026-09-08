import { api } from '../api'
import { createVersionStore } from './versionStore'

export const useProjectStore = createVersionStore('project', {
  listOwners: () => api.listProjects(),
  importOwner: (payload) => api.importProject(payload),
  listVersions: (ownerId) => api.listProjectVersions(ownerId),
  scanVersion: (vid) => api.scanProjectVersion(vid),
  deleteVersion: (vid) => api.deleteProjectVersion(vid),
  downloadReport: (vid) => api.downloadProjectReport(vid),
  downloadReportPdf: (vid) => api.downloadProjectReportPdf(vid)
})
