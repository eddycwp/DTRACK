# DTrack 项目记忆（长期站立知识）

> 每次新会话先读本文件，可避免"从头开始"。流水细节见各 `YYYY-MM-DD.md`。

## 1. 项目定位
DTrack = 纯 Python stdlib（**零三方依赖**）的"开发模块漏洞分析管理系统"。CLI 入口 `dtrack`，另有 `dtrack web` 子命令提供 Web 管理界面。核心能力：解析 Java(pom)/C/C++(cmake) 依赖 → 调漏洞源（奇安信/OSV/NVD/GitHub）查漏洞 → 生成 Markdown 报告。离线 zip（`DTrack_offline.zip`，64 项，docs 不打包）可整包部署。

## 2. 硬约束（改动前必读）
- **禁止引入三方库**：仅标准库。新增依赖需用户明确同意（Node 前端除外）。
- **单测必须保持通过**：当前 **74 个 unittest**（`tests/test_*.py`）。任何改动后跑 `python -m unittest discover -s tests -p "test_*.py"`。
- **改动后重建离线包**：`cd E:/workspace/python/DTrack && python -m dtrack build-offline`（或等价脚本），zip 含 64 项、排除 `docs/`。

## 3. 后端目录与职责
- `dtrack/core/`：`models.py`(Component/Vulnerability/AnalysisResult)、`types.py`(Severity/Language/ScanType 等枚举)。
- `dtrack/analyzers/java/`：`java_analyzer.py`(主解析，复用 Maven)、`pom_parser.py`、`maven_resolver.py`(mvn dependency:tree + 临时 settings.xml + 多模块 -N)、`license.py`。
- `dtrack/analyzers/cc/`：`cmake_parser.py`(命令名大小写不敏感+与`(`间可空格+续行/嵌套括号用括号深度匹配)。
- `dtrack/sources/`：gitlab/nexus/harbor 三个 `SourceFetcher`（list projects/repos/tags）。
- `dtrack/vuln/`：`qianxin.py`(组件坐标→漏洞查询，Basic/Private-Token 鉴权，兼容 list/dict/data 三态返回，pageSize≤20)、`osv.py`/`nvd.py`/`github.py`、`aggregator.py`、`registry.py`。
- `dtrack/scan/qianxin_scan.py`：`QianxinScanner` + `ScanKind`(8 种 jar/image 本地/nexus/artifactory/harbor/dockerhub) + `scan_target()` —— **二进制/镜像扫描模式**（与 vuln 查询模式不同）。
- `dtrack/utils/http.py`：`HttpClient.post_multipart()`（multipart 上传，扫描用）。
- `dtrack/report/markdown.py`：`render_markdown()`，章节顺序：一概览/二漏洞分布/三License(3.1-3.3)/四修复建议/五组件全集/**六组件漏洞明细(末)**。
- `dtrack/config.py`：`DEFAULT_CONFIG` + `Config`。关键段：`maven`(central_url/central_username/password)、`vuln.qianxin`(base_url/auth_type/username/password/token/page_size=20)、`scan.qianxin`(复用 vuln 回退 + project_id 必填)、`analyze`(exclude_scopes 默认 ['test']、exclude_test_frameworks 默认 True)。
- `dtrack/cli.py`：`build_parser()` + 子命令 `analyze`/`scan`/`web`/`build-offline` 等。

## 4. Web 管理平台（2026-08-20 新增）
**后端**（`dtrack/web/`，纯 stdlib，`http.server` + SQLite）：
- `store.py`：sqlite3。表：`config_mirror`(配置镜像)、`whitelist`+`whitelist_version`、`project`+`project_version`、`component`(coord 唯一, is_whitelist 标记)、`component_usage`(组件被哪些 owner 版本以 direct/transitive 引用)、`vulnerability`(按 component_id+vuln_key 去重)。`get_component_detail()` 返回漏洞+所属白名单版本+使用项目。
- `service.py`：`WebService`。导入编排复用 `JavaAnalyzer.analyze()`（pom 自身坐标=owner 版本标识，自动剔除 test 范围/测试框架）；扫描复用 `QianxinSource.query()`（pom 坐标查询模式，后台线程 pending→scanning→done/no_qianxin/failed）；配置读写回写 `dtrack.toml`；报表复用 `render_markdown`。
- `handlers.py`+`server.py`：REST `/api/whitelists|/projects|/components|/config|/gitlab/projects` + 报表下载（md）+ 静态托管 `web/dist`(SPA fallback)。**路由坑已修**：`/version/<id>/report` 与 `/version/<id>` 详情用 `not endswith('/report','/scan')` 区分。
- 启动：`python -m dtrack web --host 127.0.0.1 --port 8080 --db ./dtrack_web.db --config dtrack.toml`（dist 默认 web/dist）。

**前端**（`web/`，Vite+Vue3+Element Plus+Pinia+Vue Router，已 build 出 `web/dist`）：
- 分层：**api 层** `src/api/index.js`(fetch 封装+报表下载) → **pinia stores**(whitelist/project/component/config 4 个) → **views**(Whitelist/Project/ComponentLib/Config) → **components**(ImportDialog 导入弹窗、ComponentDetailDrawer 详情抽屉)。**视图只渲染，业务逻辑全在 api/store**。
- 功能：白名单/项目以 pom 上传或 GitLab 拉取导入、以 pom `<version>` 多版本管理；组件库筛选+详情抽屉(漏洞+白名单版本+使用项目)；配置页编辑仓库/奇安信参数；版本级 md 报表下载。
- 改前端后需 `cd web && npm run build`（npmmirror 源）。

## 5. 关键约定与已知坑
- **版本标识**：白名单/项目均以 pom 自身 `<version>` 为版本号（多版本共存），不是扫描时间。
- **白名单 vs 非白名单**：白名单导入的组件 `is_whitelist=1`；项目导入的组件若不在白名单则标"非白名单"（仍入库）。
- **test 范围剔除**：`exclude_scopes=['test']` 默认生效，`junit` 等测试依赖不进扫描（除非在依赖管理且非 test）。
- **奇安信两种模式**：(a) `vuln.qianxin` 组件坐标查询（Web 导入走此）；(b) `scan.qianxin` 二进制/镜像上传扫描（CLI `dtrack scan` 走此，需 project_id）。
- **project-id 来源**：奇安信开源卫士 Web 控制台"项目"页复制，非 DTrack 生成；缺失时返回 code 811「项目不存在」（已优化报错文案）。
- **本地化手册**：`docs/references/奇安信网神开源卫士系统V2.18.4_OpenAPI-V3.pdf` + `qianxin_openapi_v3_reference.md`，**勿联网查接口**。

## 6. 当前状态 / 待办
- 已完成：CLI 全功能 + Web 平台（白名单/项目/组件库/配置/报表）+ 8 种二进制镜像扫描 CLI。
- 已完成（2026-08-26）：Web 导入来源扩展 **Harbor 镜像 / Docker 镜像 / GitLab 归档 jar**，
  均经奇安信开源卫士（`scan.qianxin` 二进制扫描模式）扫描入库；GitLab 源码含 pom 仍走 legacy 解析路径。
  前端 `ImportDialog` 提供 POM/GitLab/Harbor/Docker 来源，GitLab 内嵌"源码(含pom)/归档jar"切换。
- 验证基线：91 单测全过（含 7 个 qianxin 导入用例）；Web API 端到端跑通（导入/扫描/查询/报表/配置）。
  注：`scan.qianxin.base_url`+`project_id` 为必经项，离线沙箱不可达网关，仅验证到路由/持久化层。

## 7. 常用命令
```
cd E:/workspace/python/DTrack
python -m unittest discover -s tests -p "test_*.py"   # 跑测试
python -m dtrack web                                  # 起 Web
python -m dtrack analyze --help                       # CLI 分析
cd web && npm run build                               # 构建前端（输出到 dtrack/static）
```
