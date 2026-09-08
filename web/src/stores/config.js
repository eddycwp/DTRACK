import { defineStore } from 'pinia'
import { api } from '../api'

export const useConfigStore = defineStore('config', {
  state: () => ({
    config: {
      repos: { gitlab: {}, nexus: {}, harbor: {} },
      maven: {},
      vuln: { qianxin: {} },
      scan: { qianxin: {} }
    },
    loading: false,
    saving: false
  }),
  actions: {
    async fetch() {
      this.loading = true
      try {
        this.config = await api.getConfig()
      } finally {
        this.loading = false
      }
    },
    async save() {
      this.saving = true
      try {
        this.config = await api.updateConfig(this.config)
      } finally {
        this.saving = false
      }
    }
  }
})
