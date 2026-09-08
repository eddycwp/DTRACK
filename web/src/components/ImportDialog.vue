<template>
  <el-dialog :title="title" v-model="visible" width="660px" @open="onOpen" @close="reset">
    <el-form label-width="92px">
      <el-form-item label="来源">
        <el-radio-group v-model="source">
          <el-radio value="pom">POM 文件</el-radio>
          <el-radio value="gitlab">GitLab 项目</el-radio>
          <el-radio value="harbor">Harbor 镜像</el-radio>
          <el-radio value="docker">Docker 镜像</el-radio>
        </el-radio-group>
      </el-form-item>

      <el-form-item v-if="props.refType === 'project'" label="项目名称">
        <el-input
          v-model="projectName"
          placeholder="手动填写项目名称，留空则使用镜像仓库名 / GitLab 项目名"
          maxlength="100"
        />
      </el-form-item>

      <!-- POM 文件 -->
      <template v-if="source === 'pom'">
        <el-form-item label="POM 内容">
          <el-upload
            drag
            action="#"
            :auto-upload="false"
            :show-file-list="false"
            :on-change="onFile"
            accept=".xml"
          >
            <el-icon><UploadFilled /></el-icon>
            <div>将 pom.xml 拖到此处，或点击上传</div>
            <div v-if="fileName" class="file-name">已选择：{{ fileName }}</div>
          </el-upload>
        </el-form-item>
      </template>

      <!-- GitLab 项目：源码(pom) 或 归档 jar -->
      <template v-else-if="source === 'gitlab'">
        <el-form-item label="内容类型">
          <el-radio-group v-model="gitlabContentType">
            <el-radio value="source">源码（含 pom）</el-radio>
            <el-radio value="jar">归档 jar</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="项目">
          <el-select
            v-model="gitlabProject"
            filterable
            placeholder="选择 GitLab 项目"
            style="width: 100%"
            :loading="loadingProjects"
          >
            <el-option
              v-for="p in projects"
              :key="p.id"
              :label="`${p.path} (${p.name})`"
              :value="p.path"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="分支/标签">
          <el-select
            v-model="gitRef"
            placeholder="选择分支或标签（留空用默认分支）"
            clearable
            filterable
            style="width: 100%"
            :loading="loadingRefs"
            :disabled="!gitlabProject"
          >
            <el-option-group v-if="gitRefs.branches.length" label="分支">
              <el-option
                v-for="b in gitRefs.branches"
                :key="'b-' + b"
                :label="b"
                :value="b"
              />
            </el-option-group>
            <el-option-group v-if="gitRefs.tags.length" label="标签">
              <el-option
                v-for="t in gitRefs.tags"
                :key="'t-' + t"
                :label="t"
                :value="t"
              />
            </el-option-group>
          </el-select>
        </el-form-item>
        <el-alert
          v-if="gitlabContentType === 'jar'"
          type="info"
          :closable="false"
          show-icon
          title="归档 jar 模式：下载 GitLab 归档后定位其中的 .jar，提交奇安信开源卫士二进制扫描。"
        />
      </template>

      <!-- Harbor / Docker 镜像 -->
      <template v-else>
        <el-form-item :label="source === 'harbor' ? 'Harbor 镜像' : 'Docker 镜像'">
          <el-input
            v-model="imageUrl"
            :placeholder="source === 'harbor'
              ? '如 my.harbor.com:6443/library/centos:7'
              : '如 nginx:latest 或 registry.example.com/app:1.0'"
          />
        </el-form-item>
      </template>
    </el-form>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" @click="submit">导入并扫描</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const props = defineProps({ refType: { type: String, default: 'whitelist' } })
const emit = defineEmits(['submit'])

const visible = defineModel('visible', { default: false })
const source = ref('pom')
const projectName = ref('')
const pomText = ref('')
const fileName = ref('')
const gitlabProject = ref('')
const gitRef = ref('')
const gitlabContentType = ref('source')
const imageUrl = ref('')
const projects = ref([])
const loadingProjects = ref(false)
const gitRefs = ref({ branches: [], tags: [] })
const loadingRefs = ref(false)

const title = computed(() => {
  const t = props.refType === 'whitelist' ? '白名单' : '项目'
  return `导入${t}（POM / GitLab / Harbor / Docker）`
})

function reset() {
  source.value = 'pom'
  projectName.value = ''
  pomText.value = ''
  fileName.value = ''
  gitlabProject.value = ''
  gitRef.value = ''
  gitlabContentType.value = 'source'
  imageUrl.value = ''
  gitRefs.value = { branches: [], tags: [] }
}

async function loadRefs(project) {
  loadingRefs.value = true
  gitRef.value = ''
  gitRefs.value = { branches: [], tags: [] }
  try {
    gitRefs.value = await api.listGitlabRefs(project)
  } catch (e) {
    ElMessage.warning('分支/标签获取失败：' + e.message)
  } finally {
    loadingRefs.value = false
  }
}

async function onOpen() {
  if (source.value === 'gitlab' && projects.value.length === 0) await loadProjects()
}

async function loadProjects() {
  loadingProjects.value = true
  try {
    projects.value = await api.listGitlabProjects()
  } catch (e) {
    ElMessage.warning('GitLab 项目列表获取失败：' + e.message)
  } finally {
    loadingProjects.value = false
  }
}

function onFile(file) {
  fileName.value = file.name
  const reader = new FileReader()
  reader.onload = () => {
    pomText.value = reader.result
  }
  reader.readAsText(file.raw)
}

async function submit() {
  let payload = {}
  if (source.value === 'pom') {
    if (!pomText.value.trim()) {
      ElMessage.warning('请上传 pom.xml 文件')
      return
    }
    payload = { pom_text: pomText.value }
  } else if (source.value === 'gitlab') {
    if (!gitlabProject.value) {
      ElMessage.warning('请选择 GitLab 项目')
      return
    }
    payload = {
      gitlab_project: gitlabProject.value,
      ref: gitRef.value || undefined,
      gitlab_content_type: gitlabContentType.value
    }
    // 归档 jar 走奇安信二进制扫描，标记 source=gitlab-jar
    if (gitlabContentType.value === 'jar') payload.source = 'gitlab-jar'
  } else {
    // harbor / docker
    if (!imageUrl.value.trim()) {
      ElMessage.warning('请填写镜像地址')
      return
    }
    payload = {
      source: source.value,
      image_url: imageUrl.value.trim()
    }
  }
  if (props.refType === 'project') payload.name = projectName.value.trim() || undefined
  emit('submit', payload)
  visible.value = false
}

// 切换来源时按需加载 GitLab 项目列表
watch(source, (v) => {
  if (v === 'gitlab' && projects.value.length === 0) loadProjects()
})
// 选定 GitLab 项目后，自动读取其分支/标签供下拉选择
watch(gitlabProject, (v) => {
  if (v) loadRefs(v)
  else gitRefs.value = { branches: [], tags: [] }
})
</script>

<style scoped>
.file-name {
  margin-top: 4px;
  font-size: 12px;
  color: #909399;
  word-break: break-all;
}
</style>
