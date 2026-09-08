<template>
  <div class="page">
    <div class="toolbar">
      <div class="tb-right">
        <el-button type="primary" :loading="store.saving" @click="save">保存配置</el-button>
      </div>
    </div>
    <el-alert type="info" :closable="false"
      title="配置将写回 dtrack.toml，CLI 与 Web 共用同一份文件。GitLab / Nexus / Harbor 用于拉取项目与制品；奇安信开源卫士用于漏洞扫描（vuln 为组件查询，scan 为二进制/镜像扫描模式）。" />

    <el-tabs v-model="activeTab" class="config-tabs" v-loading="store.loading">
      <el-tab-pane label="GitLab" name="gitlab">
        <el-card header="GitLab 仓库" style="margin-top: 12px">
          <el-form label-width="110px">
            <el-form-item label="Base URL"><el-input v-model="c.repos.gitlab.base_url" placeholder="https://gitlab.com" /></el-form-item>
            <el-form-item label="Token"><el-input v-model="c.repos.gitlab.token" type="password" show-password /></el-form-item>
            <el-form-item label="启用"><el-switch v-model="c.repos.gitlab.enabled" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="Nexus" name="nexus">
        <el-card header="Nexus 仓库" style="margin-top: 12px">
          <el-form label-width="110px">
            <el-form-item label="Base URL"><el-input v-model="c.repos.nexus.base_url" /></el-form-item>
            <el-form-item label="用户名"><el-input v-model="c.repos.nexus.username" /></el-form-item>
            <el-form-item label="密码"><el-input v-model="c.repos.nexus.password" type="password" show-password /></el-form-item>
            <el-form-item label="启用"><el-switch v-model="c.repos.nexus.enabled" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="Harbor" name="harbor">
        <el-card header="Harbor 镜像仓库" style="margin-top: 12px">
          <el-form label-width="110px">
            <el-form-item label="Base URL"><el-input v-model="c.repos.harbor.base_url" /></el-form-item>
            <el-form-item label="用户名"><el-input v-model="c.repos.harbor.username" /></el-form-item>
            <el-form-item label="密码"><el-input v-model="c.repos.harbor.password" type="password" show-password /></el-form-item>
            <el-form-item label="启用"><el-switch v-model="c.repos.harbor.enabled" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="Maven" name="maven">
        <el-card header="Maven 设置" style="margin-top: 12px">
          <el-form label-width="130px">
            <el-form-item label="Maven Home"><el-input v-model="c.maven.home" placeholder="如 D:\mavendown\apache-maven-3.9.6" /></el-form-item>
            <el-form-item label="Central URL"><el-input v-model="c.maven.central_url" /></el-form-item>
            <el-form-item label="本地仓库"><el-input v-model="c.maven.local_repo" placeholder="可选，加速元数据解析" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="奇安信（漏洞查询）" name="qianxin-vuln">
        <el-card header="奇安信开源卫士 · 组件漏洞查询（vuln.qianxin）" style="margin-top: 12px">
          <el-form label-width="130px">
            <el-form-item label="网关地址"><el-input v-model="c.vuln.qianxin.base_url" placeholder="https://<host>:8449" /></el-form-item>
            <el-form-item label="鉴权方式">
              <el-select v-model="c.vuln.qianxin.auth_type" style="width: 100%">
                <el-option label="Private-Token" value="private-token" />
                <el-option label="Basic" value="basic" />
              </el-select>
            </el-form-item>
            <el-form-item label="Token"><el-input v-model="c.vuln.qianxin.token" type="password" show-password /></el-form-item>
            <el-form-item label="用户名"><el-input v-model="c.vuln.qianxin.username" /></el-form-item>
            <el-form-item label="密码"><el-input v-model="c.vuln.qianxin.password" type="password" show-password /></el-form-item>
            <el-form-item label="Page Size"><el-input v-model.number="c.vuln.qianxin.page_size" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="奇安信（二进制扫描）" name="qianxin-scan">
        <el-card header="奇安信开源卫士 · 二进制/镜像扫描（scan.qianxin）" style="margin-top: 12px">
          <el-form label-width="130px">
            <el-form-item label="项目编号"><el-input v-model="c.scan.qianxin.project_id" placeholder="必填，提交扫描任务用" /></el-form-item>
            <el-form-item label="鉴权方式">
              <el-select v-model="c.scan.qianxin.auth_type" style="width: 100%">
                <el-option label="Private-Token" value="private-token" />
                <el-option label="Basic" value="basic" />
              </el-select>
            </el-form-item>
            <el-form-item label="Token"><el-input v-model="c.scan.qianxin.token" type="password" show-password /></el-form-item>
            <el-form-item label="用户名"><el-input v-model="c.scan.qianxin.username" /></el-form-item>
            <el-form-item label="密码"><el-input v-model="c.scan.qianxin.password" type="password" show-password /></el-form-item>
            <el-form-item label="轮询间隔(s)"><el-input v-model.number="c.scan.qianxin.poll_interval" /></el-form-item>
            <el-form-item label="超时(s)"><el-input v-model.number="c.scan.qianxin.poll_timeout" /></el-form-item>
          </el-form>
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { useConfigStore } from '../stores/config'

const store = useConfigStore()
const c = computed(() => store.config)
const activeTab = ref('gitlab')

onMounted(() => store.fetch())

async function save() {
  try {
    await store.save()
    ElMessage.success('配置已保存')
  } catch (e) {
    ElMessage.error('保存失败：' + e.message)
  }
}
</script>

<style scoped>
.config-tabs {
  margin-top: 12px;
}
</style>
