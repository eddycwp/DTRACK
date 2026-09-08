import { defineStore } from 'pinia'
import { api } from '../api'

export const useComponentStore = defineStore('component', {
  state: () => ({
    components: [],
    loading: false,
    filters: { q: '', is_whitelist: null, severity: '' },
    detail: null,
    detailVisible: false
  }),
  actions: {
    async fetchList() {
      this.loading = true
      try {
        const params = {
          q: this.filters.q || undefined,
          is_whitelist: this.filters.is_whitelist,
          severity: this.filters.severity || undefined
        }
        this.components = await api.listComponents(params)
      } finally {
        this.loading = false
      }
    },
    async openDetail(coord) {
      this.detail = await api.getComponentDetail(coord)
      this.detailVisible = true
    },
    closeDetail() {
      this.detailVisible = false
      this.detail = null
    }
  }
})
