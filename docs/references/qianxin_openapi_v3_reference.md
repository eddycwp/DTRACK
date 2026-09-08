# 奇安信网神开源卫士 OpenAPI V3 — 二进制/镜像扫描接口速查

> 来源：本地手册 `docs/references/奇安信网神开源卫士系统V2.18.4_OpenAPI-V3.pdf`（279 页）。
> 本文件为开发速查，避免每次联网。DTrack 的 `dtrack/scan/qianxin_scan.py` 即依据本节实现。

## 0. 鉴权（全局通用）

接口认证支持 **BasicAuth** 与 **Private-Token** 两种方式，均放在请求头 `Authorization`：

- BasicAuth：`Authorization: Basic <base64(username:password)>`
- Private-Token：`Authorization: Private-Token <token>`

扫描类接口（4.x）与组件漏洞查询接口（3.x：`/open-api/v3/component/vulnerability`）使用同一套鉴权。

## 1. 二进制制品扫描发起（`scan-center/task/...`）

> 注意：同一 `projectId + taskName` 重复调用会复用同一任务并返回相同 `taskId`。

| 场景 | API Path | 方法 | 请求体格式 | 关键参数 |
| --- | --- | --- | --- | --- |
| 本地二进制文件上传 | `/zuul/scan-center/task/binary-file/analysis` | POST | multipart/form-data | `file`(jar/war/zip/iso… ≤10G)、`projectId`、`taskName`、`tags?`、`analyseModes?`(默认 `[8]` 二进制识别；`9` 敏感信息)、`scanAdvancedOption?` |
| 服务器本地目录 | `/scan-center/task/binary-dir/analysis` | POST | JSON | `dirPath`、`projectId`、`taskName`、`analyseModes?` |
| Nexus 二进制 | `/scan-center/task/binary-nexus/analysis` | POST | JSON | `projectId`、`taskName`、`url`、`username`、`password`、`token?`、`authType`(1用户名密码/2 apikey/3 identity token)、`retentionAudit?`、`analyseModes?` |
| Artifactory 二进制 | `/scan-center/task/binary-artifactory/analysis` | POST | JSON | 同 Nexus 二进制（`url` 指向 jar 等制品 uri） |

## 2. 容器镜像扫描发起（`scan-center/task/...`）

| 场景 | API Path | 方法 | 请求体格式 | 关键参数 |
| --- | --- | --- | --- | --- |
| 镜像文件上传(tar) | `/zuul/scan-center/task/image-file/analysis` | POST | multipart/form-data | `file`(tar)、`projectId`、`taskName` |
| 镜像特征文件(zip) | `/scan-center/task/image-feature/analysis` | POST | multipart/form-data | `file`(zip)、`projectId`、`taskName` |
| Artifactory 镜像 | `/scan-center/task/image-artifactory/analysis` | POST | JSON | `projectId`、`taskName`、`url`、`username`、`password`、`token?`、`authType`、`retentionAudit?` |
| Harbor 镜像 | `/scan-center/task/image-harbor/analysis` | POST | JSON | `projectId`、`taskName`、`url`(如 `my.harbor.com:6443/oss/centos@sha256:...`)、`username`、`password`、`retentionAudit?` |
| DockerHub 镜像 | `/scan-center/task/image-dockerhub/analysis` | POST | JSON | `projectId`、`taskName`、`url`(如 `centos:latest`)、`username`、`password`、`retentionAudit?` |
| Nexus 镜像 | `/scan-center/task/image-nexus/analysis` | POST | JSON | `projectId`、`taskName`、`url`、`username`、`password`、`retentionAudit?` |

## 3. 结果拉取（`open-api/v3/task/binary/...`）

所有结果接口使用 `taskId`（来自发起接口响应 `data.taskId`）。

### 3.1 检测结果概览 `GET /open-api/v3/task/binary/result?taskId=`

`code`: `1`=成功完成，`9`=检测中（需轮询）；`data` 含：

- `componentCount`、`componentIds[]`
- `moduleCount`、`moduleIds[]`
- `vulnerabilityCount`、`vulnerabilityInfos[]`（每项含 `vulnerabilityId`、`qaxOssId`、`level`、`taskBeginTime`、`taskEndTime`）
- `licenseCount`、`licenseInfos[]`（`licenseId`/`licenseShortName`/`licenseName`/`licenseLevel`/`fsf`/`osi`/`spdx`/`licenseContent`）
- 等级统计：`componentSuperLevelCount`(超危)、`componentHighLevelCount`(高危)、`componentMiddleLevelCount`(中危)、`componentLowLevelCount`(低危)、`componentUnknownLevelCount`(未知)、`componentNoneLevelCount`(无漏洞)、`componentUnknownVersionCount`(未知版本)
- `taskBeginTime`、`taskEndTime`

### 3.2 组件列表 `POST /open-api/v3/task/binary/component/list`

请求：`{taskId, componentIds?, pageIndex=0, pageSize=100, strategyTypes?, componentLevels?}`

`data.content[]` 每项：

- `componentId`、`componentName`、`componentVersion`、`componentLevel`
- `componentDescription`、`componentSourceCount`、`componentSourceInfos[]`（含 `path`、`matchedType`、`sourceType`、`source`(如 `org.apache.activemq:activemq-broker:5.15.15`)、`moduleName`、`versionNo`、`sha1`、`sha256`、`languageType`、`lastModified`）
- `recommendedVersion`、`latestVersion`、`otherVersions[]`
- `communityAddress`、`licenseInfos[]`（`licenseId`/`licenseShortName`/`licenseName`/`licenseLevel`/`licenseContent`/`fsf`/`osi`/`spdx`）
- `vulnerabilityCount`、`componentType`(0开源/1私有)、`projectName`、`projectVersionNO`
- `packageType`(如 pypi)、`coordinates[]`、`markStatus`、`markDescription`

### 3.3 漏洞列表 `POST /open-api/v3/task/binary/vulnerability/list`

请求：`{taskId, vulnerabilityIds?, pageIndex=0, pageSize=100}`

`data.content[]` 每项：

- `vulnerabilityId`、`qaxOssId`、`cnnvd?`、`cve?`、`vulnerabilityName`、`level`(1超危/2高危/3中危/4低危/5未知)
- `utilizeDegree`、`releaseDate`、`vulnerabilityType`、`attackType?`、`vulnerabilitySource`
- `vulnerabilityDescription`、`solution?`、`updateTime`、`createTime`
- `affectVersionList[]`（每项 `componentId`、`componentName`、`componentVersion`、`sourceType`）— 用于把漏洞关联到组件
- `referenceUrls[]`（每项 `source`、`url`）
- `markcode`、`auditExplain?`、`patch[]`(url)、`fixed`(bool)、`workaround?`
- `cvss2Info{}`(`vectorString`/`baseScore`/…)、`cvss3Info{}`(`vectorString`/`baseScore`/…)

### 3.4 未知版本组件列表 `POST /open-api/v3/task/binary/unknown/component/list`

请求：`{taskId, moduleIds?, pageIndex=0, pageSize=100}`。`data.content[]` 仅含组件名/来源信息（无精确版本），仍计入组件清单。

### 3.5 异常文件列表 `GET /open-api/v3/task/binary/fail-file?taskId=`

返回 `data[]`（`id`、`taskId`、`path`、`sha1`、`sha256`），用于识别未能识别的二进制。

## 4. DTrack 集成要点

- 复用 `vuln.qianxin` 的 `base_url` / `auth_type` / `token` / `username` / `password` / `verify_ssl`；扫描专用段 `scan.qianxin` 可覆盖，并额外需要 `project_id`（提交任务必填）、`poll_interval`、`poll_timeout`、`page_size`。
- 组件归一化：优先解析 `coordinates[]` 或 `componentSourceInfos[].source`（`group:artifact:version`），再取 `componentName`/`componentVersion`；`languageType` → `Language`。
- 漏洞关联：以 `vulnerability.affectVersionList[].componentId` 反查 `component.content.componentId`，把 `Vulnerability` 挂到对应 `Component.vulnerabilities`。
- 等级 `level`：1超危/2高危/3中危/4低危/5未知 → `Severity.CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN`（见 `qx_level_to_severity`）。
- `vuln_id`：`cve` 优先，否则 `qaxOssId`，否则 `vulnerabilityId`。
