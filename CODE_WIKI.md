# DTrack — Code Wiki

> 开发模块（三方组件）漏洞分析管理系统

---

## 目录

1. [项目概述](#1-项目概述)
2. [整体架构](#2-整体架构)
3. [目录结构](#3-目录结构)
4. [核心数据模型（core）](#4-核心数据模型core)
5. [模块详解](#5-模块详解)
   - 5.1 [analyzers — 语言分析器](#51-analyzers--语言分析器)
   - 5.2 [vuln — 漏洞数据源](#52-vuln--漏洞数据源)
   - 5.3 [scan — 二进制/镜像扫描](#53-scan--二进制镜像扫描)
   - 5.4 [sources — 仓库拉取器](#54-sources--仓库拉取器)
   - 5.5 [report — 报告生成](#55-report--报告生成)
   - 5.6 [utils — 通用工具](#56-utils--通用工具)
   - 5.7 [web — Web 管理平台](#57-web--web-管理平台)
   - 5.8 [config — 配置管理](#58-config--配置管理)
   - 5.9 [cli — 命令行入口](#59-cli--命令行入口)
6. [模块依赖关系](#6-模块依赖关系)
7. [关键数据流](#7-关键数据流)
8. [配置系统](#8-配置系统)
9. [项目运行方式](#9-项目运行方式)
10. [测试](#10-测试)
11. [打包与部署](#11-打包与部署)

---

## 1. 项目概述

**DTrack** 是一个模块化的三方软件组件（Java/JAR、C/C++、Docker 镜像）漏洞分析管理系统。它完成以下核心工作：

1. **依赖解析**：解析项目（Maven `pom.xml`、CMake `CMakeLists.txt`、库文件）得到组件清单，区分直接/传递依赖。
2. **漏洞查询**：对接多个漏洞情报源（NVD、GitHub Advisory、OSV、奇安信开源卫士），对每个组件查询已知漏洞并归一化、去重、聚合。
3. **二进制/镜像扫描**：通过奇安信开源卫士 OpenAPI V3 对 jar/so/dll 二进制制品与 Docker 镜像进行深度扫描。
4. **报告生成**：输出 Markdown / PDF 格式的漏洞分析报告（含严重程度分布、License 分布、修复建议）。
5. **Web 管理平台**：提供 Vue3 前端 + Python 标准库 HTTP 后端，支持白名单/项目导入、组件库管理、漏洞扫描、配置管理。

**核心设计原则**：

- **零第三方依赖**：核心分析引擎仅使用 Python 标准库（`urllib`、`sqlite3`、`http.server`、`xml.etree`、`tomllib` 等），可在无网络、无 `pip` 的离线环境直接运行。
- **插件化架构**：分析器（analyzers）、漏洞源（vuln）、仓库拉取器（sources）均通过注册表模式扩展。
- **CLI 与 Web 共用同一套引擎**：Web 服务层复用 `JavaAnalyzer`、`VulnerabilityAggregator`、`QianxinScanner` 等核心组件。

---

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                          用户入口层                                  │
│   CLI (dtrack.cli)          Web 前端 (Vue3 + Element Plus)          │
│   analyze/scan/fetch/web    白名单/项目/组件库/配置 页面             │
└──────────┬──────────────────────────────┬───────────────────────────┘
           │                              │
           ▼                              ▼
┌──────────────────────┐    ┌─────────────────────────────────────────┐
│     CLI 命令处理      │    │       Web 服务层 (dtrack.web)            │
│  cmd_analyze         │    │  handlers.py  → HTTP 路由 (/api/*)      │
│  cmd_scan            │    │  service.py   → 业务编排                 │
│  cmd_fetch           │    │  store.py     → SQLite 持久化            │
│  cmd_config          │    │  server.py    → 启动入口                 │
└──────────┬───────────┘    └──────────────┬──────────────────────────┘
           │                               │
           ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        核心分析引擎                                  │
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐  │
│  │  analyzers    │  │    vuln       │  │       scan             │  │
│  │  (依赖解析)   │→│  (漏洞聚合)   │  │  (奇安信二进制/镜像)   │  │
│  │  Java / C&C   │  │  NVD/GH/OSV/  │  │  QianxinScanner        │  │
│  │               │  │  Qianxin      │  │                        │  │
│  └───────┬───────┘  └───────┬───────┘  └───────────┬────────────┘  │
│          │                  │                      │               │
│          ▼                  ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              core (数据模型: Component / Vulnerability)      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────┐  │
│  │   sources     │  │    report     │  │       utils            │  │
│  │  (仓库拉取)   │  │  (报告渲染)   │  │  (HTTP/缓存/版本/许可) │  │
│  │  GitLab/Nexus │  │  MD / PDF     │  │                        │  │
│  │  /Harbor      │  │               │  │                        │  │
│  └───────────────┘  └───────────────┘  └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
           │                  │                      │
           ▼                  ▼                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        外部系统                                      │
│  Maven Central / Nexus    NVD API    GitHub API    OSV API          │
│  GitLab API               Harbor API                                 │
│  奇安信开源卫士网关 (OpenAPI V3)                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. 目录结构

```
DTrack/
├── dtrack/                    # Python 核心源码包
│   ├── __init__.py            # 版本号、日志初始化
│   ├── __main__.py            # python -m dtrack 入口
│   ├── cli.py                 # CLI 命令解析与调度
│   ├── config.py              # 配置加载/合并/序列化
│   ├── core/                  # 核心数据模型
│   │   ├── types.py           # 枚举: Language, Severity, SourceType, DependencyType
│   │   └── models.py          # 数据类: Component, Vulnerability, AnalysisResult
│   ├── analyzers/             # 语言/包分析器（插件化）
│   │   ├── base.py            # PackageAnalyzer 抽象基类
│   │   ├── registry.py        # 分析器注册表
│   │   ├── java/              # Java (Maven) 分析器
│   │   │   ├── java_analyzer.py
│   │   │   ├── pom_parser.py
│   │   │   ├── maven_resolver.py
│   │   │   └── license.py
│   │   └── cc/                # C/C++ 分析器
│   │       ├── cc_analyzer.py
│   │       ├── cmake_parser.py
│   │       └── lib_scanner.py
│   ├── vuln/                  # 漏洞数据源（插件化）
│   │   ├── base.py            # VulnerabilitySource 抽象基类
│   │   ├── registry.py        # 漏洞源注册表
│   │   ├── aggregator.py      # 多源聚合与去重
│   │   ├── nvd.py             # NVD (NIST) 漏洞源
│   │   ├── github.py          # GitHub Advisory 漏洞源
│   │   ├── osv.py             # OSV.dev 漏洞源
│   │   └── qianxin.py         # 奇安信开源卫士漏洞源
│   ├── scan/                  # 二进制/镜像扫描
│   │   └── qianxin_scan.py    # 奇安信 OpenAPI V3 扫描器
│   ├── sources/               # 仓库拉取器（插件化）
│   │   ├── base.py            # SourceFetcher 抽象基类
│   │   ├── registry.py        # 拉取器注册表
│   │   ├── gitlab.py          # GitLab 项目/归档拉取
│   │   ├── nexus.py           # Nexus 制品拉取
│   │   └── harbor.py          # Harbor 镜像列表
│   ├── report/                # 报告渲染
│   │   ├── markdown.py        # Markdown 报告
│   │   └── pdf.py             # PDF 报告（可选依赖 reportlab）
│   ├── utils/                 # 通用工具
│   │   ├── http.py            # HTTP 客户端（stdlib urllib）
│   │   ├── cache.py           # 磁盘文件缓存
│   │   ├── versions.py        # Maven 版本比较与范围判定
│   │   ├── license_normalize.py  # 许可证名称归一化
│   │   ├── license_detect.py  # LICENSE 文件文本识别
│   │   └── archive.py         # 目录打包为 zip
│   ├── web/                   # Web 管理平台后端
│   │   ├── server.py          # 启动入口与默认路径
│   │   ├── handlers.py        # HTTP 路由 + 静态文件服务
│   │   ├── service.py         # 业务逻辑层
│   │   └── store.py           # SQLite 数据访问层
│   └── static/                # 前端构建产物（由 web/ 构建输出）
├── web/                       # Vue3 前端源码
│   ├── src/                   # 视图、组件、状态管理、路由
│   ├── dist/                  # 前端构建输出
│   └── package.json           # 前端依赖（vue3, element-plus, pinia, vite）
├── config/                    # 配置文件目录
│   ├── dtrack.toml            # 实际运行配置
│   └── dtrack.example.toml    # 配置示例
├── db/                        # SQLite 数据库
├── tests/                     # 单元测试
├── samples/                   # 演示项目（Java / C++）
├── reports/                   # 报告输出目录
├── docs/references/           # 奇安信 OpenAPI 参考文档
├── packaging/                 # PyInstaller 打包脚本
├── build_windows.bat          # Windows 一键打包脚本
├── pyproject.toml             # Python 项目元数据
└── requirements.txt           # 第三方依赖声明（仅开发/可选功能需要）
```

---

## 4. 核心数据模型（core）

### 4.1 枚举类型 — [types.py](file:///workspace/dtrack/core/types.py)

| 枚举 | 值 | 说明 |
|------|-----|------|
| `Language` | `java`, `c/c++`, `docker` | 分析目标语言/类型 |
| `DependencyType` | `direct`, `transitive` | 依赖类型（直接/传递） |
| `Severity` | `critical`, `high`, `medium`, `low`, `unknown` | 漏洞严重程度，带 `rank` 属性用于排序 |
| `SourceType` | `nvd`, `github`, `qianxin`, `osv`, `manual` | 漏洞记录来源 |

`Severity` 提供：
- `rank` 属性：critical=5 > high=4 > medium=3 > low=2 > unknown=1
- `label_zh()`：中文标签（超危/严重、高危、中危、低危、未知）
- `from_rank()` / `max()`：辅助比较

### 4.2 数据类 — [models.py](file:///workspace/dtrack/core/models.py)

#### `Vulnerability`

归一化的单条漏洞记录，跨所有漏洞源统一结构。

| 字段 | 类型 | 说明 |
|------|------|------|
| `vuln_id` | str | 规范 ID（CVE-xxxx / GHSA-xxxx / QAX-xxxx） |
| `source` | SourceType | 首次发现该漏洞的源 |
| `title` | str | 漏洞标题 |
| `severity` | Severity | 归一化严重程度 |
| `description` | str | 漏洞描述 |
| `fixed_version` | str? | 修复版本 |
| `vulnerable_range` | str? | 受影响版本范围 |
| `references` | list[str] | 参考链接 |
| `cve` | str? | 关联 CVE 编号 |
| `cwe` | str? | CWE 分类 |
| `solution` | str? | 修复建议 |
| `sources` | list | 报告该漏洞的所有源 |
| `raw` | dict | 原始响应数据 |

关键方法：
- `dedup_key()` → 优先使用 CVE 编号作为去重键，使 NVD/GitHub/奇安信报告的同一漏洞合并为一条。

#### `Component`

软件组件（制品/包/镜像层）。

| 字段 | 类型 | 说明 |
|------|------|------|
| `group` | str? | Maven groupId（C/C++ 为 None） |
| `name` | str | 组件名 |
| `version` | str? | 版本号 |
| `language` | Language | 所属语言 |
| `purl` | str? | Package URL |
| `dependency_type` | DependencyType? | 直接/传递 |
| `direct` / `transitive` | bool | 依赖类型标记 |
| `source` | str? | 发现位置（pom 路径等） |
| `license` | str? | SPDX 许可证标识 |
| `lib_type` | str? | C/C++ 库类型（dynamic/static） |
| `vulnerabilities` | list[Vulnerability] | 关联漏洞列表 |
| `extra` | dict | 扩展信息 |

关键属性：
- `key` → `group:name:version` 唯一标识
- `coordinate` → 人类可读坐标
- `worst_severity` → 该组件最严重的漏洞等级

#### `AnalysisResult`

一次分析运行的聚合结果。

| 字段 | 说明 |
|------|------|
| `target` | 分析目标描述 |
| `language` | 目标语言 |
| `generated_at` | 生成时间（北京时间） |
| `components` | 组件列表 |
| `vulnerabilities` | 漏洞列表 |
| `summary` | 统计摘要（由 `enrich_summary()` 计算） |
| `sources_used` | 使用的漏洞源 |
| `notes` | 附加说明 |

`enrich_summary()` 计算：组件总数、有漏洞组件数、漏洞总数、按严重程度/来源/许可证分布计数、直接/传递依赖数。

---

## 5. 模块详解

### 5.1 analyzers — 语言分析器

**职责**：将分析目标（项目目录/文件）解析为 `Component` 列表。采用插件化设计，通过注册表按语言分发。

#### 基类 — [base.py](file:///workspace/dtrack/analyzers/base.py)

```python
class PackageAnalyzer(ABC):
    language: Language
    def analyze(self, target: str) -> list[Component]       # 解析目标
    def describe_target(self, target: str) -> str           # 目标描述
```

#### 注册表 — [registry.py](file:///workspace/dtrack/analyzers/registry.py)

| 函数 | 说明 |
|------|------|
| `get_analyzer(language, config)` | 按语言获取分析器实例 |
| `register_analyzer(language, cls)` | 注册新分析器 |
| `supported_languages()` | 返回已注册语言列表 |

当前注册：`Language.JAVA → JavaAnalyzer`，`Language.CC → CCAnalyzer`

#### Java 分析器 — [java/](file:///workspace/dtrack/analyzers/java/)

| 文件 | 关键类/函数 | 职责 |
|------|------------|------|
| `java_analyzer.py` | `JavaAnalyzer.analyze(target)` | 主流程：收集 pom → 解析声明依赖 → 选择解析器 → 生成 Component → 剔除测试依赖 → 补充 license |
| `pom_parser.py` | `parse_pom_file(path)` → `Pom` | 解析 pom.xml：提取 groupId/artifactId/version、直接依赖、dependencyManagement、properties、modules、licenses |
| | `Dep` / `Pom` 数据类 | 结构化 POM 数据 |
| `maven_resolver.py` | `MvnTreeResolver.resolve(project_dir)` | 优先策略：调用 `mvn dependency:tree` 解析完整依赖树 |
| | `MavenCentralResolver.resolve(deps)` | 回退策略：纯 Python BFS 展开 Maven Central 元数据 |
| | `resolve_mvn_executable(config)` | 定位 mvn 可执行文件 |
| | `_is_test_framework(artifact)` | 判断是否为测试框架（junit/mockito 等） |
| `license.py` | `maven_central_license(config, g, a, v)` | 从 Maven Central 拉取 POM 中的 `<licenses>` 信息 |

**Java 分析流程**：

```
收集所有 pom.xml（支持多模块）
    ↓
解析每个 pom 的 <dependencies> + <dependencyManagement>
    ↓
选择解析策略：
  ├─ mvn dependency:tree 可用 → MvnTreeResolver（完整、准确）
  └─ 不可用 → MavenCentralResolver（BFS 拉取远程 POM）
    ↓
生成 Component 列表（标记 direct/transitive）
    ↓
回补：dependencyManagement 中声明但未被 tree 输出的组件
    ↓
剔除：test 作用域 + 测试框架（junit/mockito/assertj 等）
    ↓
补充：从 Maven Central 获取每个组件的 license
```

#### C/C++ 分析器 — [cc/](file:///workspace/dtrack/analyzers/cc/)

| 文件 | 关键类/函数 | 职责 |
|------|------------|------|
| `cc_analyzer.py` | `CCAnalyzer.analyze(target)` | 主流程：CMake 声明依赖 + 磁盘库文件扫描 → 合并生成 Component |
| `cmake_parser.py` | `parse_cmake_text(text)` → `CMakeProject` | 解析 CMakeLists.txt：识别 `find_package`、`target_link_libraries`、`add_library` |
| | `external_dependencies(projects)` | 过滤本地目标，提取外部依赖 |
| | `collect_cmake(target)` | 递归查找所有 CMakeLists.txt |
| `lib_scanner.py` | `classify(filename)` → `LibFile?` | 按扩展名识别 .so/.dll/.a/.lib，提取名称与版本 |
| | `scan_libraries(root)` | 递归扫描目录中的库文件并去重 |

---

### 5.2 vuln — 漏洞数据源

**职责**：对给定 `Component` 查询已知漏洞，返回归一化的 `Vulnerability` 列表。多源结果由 `VulnerabilityAggregator` 聚合去重。

#### 基类 — [base.py](file:///workspace/dtrack/vuln/base.py)

```python
class VulnerabilitySource(ABC):
    name: str
    source_type: SourceType
    def enabled(self) -> bool                    # 是否满足启用条件
    def disabled_reason(self) -> str             # 未启用原因（诊断用）
    def query(self, component) -> list[Vulnerability]  # 查询漏洞
    # 工具方法
    def _sx_severity(label) -> Severity          # 文本标签 → Severity
    def severity_from_score(score) -> Severity   # CVSS 分数 → Severity
```

#### 注册表 — [registry.py](file:///workspace/dtrack/vuln/registry.py)

| 函数 | 说明 |
|------|------|
| `get_source(name, config)` | 按名称实例化漏洞源 |
| `get_enabled_sources(config)` | 读取 `vuln.sources` 配置，返回所有已启用源（跳过未满足条件的并记录警告） |

已注册源：`nvd`、`github`、`qianxin`、`osv`

#### 聚合器 — [aggregator.py](file:///workspace/dtrack/vuln/aggregator.py)

```python
class VulnerabilityAggregator:
    def __init__(config, sources=None)
    def analyze_component(component) -> list[Vulnerability]   # 单组件：查询所有源 → 去重合并
    def analyze_components(components) -> None                # 批量：线程池并发，结果写入 comp.vulnerabilities
```

**去重合并逻辑**：
- 以 `vuln.dedup_key()`（优先 CVE 编号）为键
- 合并时取最高 severity、合并 references、补充缺失的 solution/fixed_version/vulnerable_range/description
- 记录所有报告该漏洞的 sources

#### 各漏洞源实现

| 源 | 文件 | 启用条件 | 查询方式 |
|----|------|---------|---------|
| **NVD** | [nvd.py](file:///workspace/dtrack/vuln/nvd.py) | 始终启用（可选 api_key 提升速率） | 构造 CPE → 调用 NVD REST API 2.0 → 按版本范围过滤 |
| **GitHub** | [github.py](file:///workspace/dtrack/vuln/github.py) | 需要 `vuln.github.token` | GraphQL 查询 Maven 包的安全建议 → 按版本范围过滤 |
| **OSV** | [osv.py](file:///workspace/dtrack/vuln/osv.py) | 始终启用 | 调用 OSV query API（支持 Maven ecosystem 与 C/C++ generic） |
| **奇安信** | [qianxin.py](file:///workspace/dtrack/vuln/qianxin.py) | 需要 `vuln.qianxin.base_url` | 分页调用 `/open-api/v3/component/vulnerability` |

**奇安信严重程度映射** — `qx_level_to_severity(level)`：
- 1=超危(critical)、2=高危(high)、3=中危(medium)、4=低危(low)、5=未知(unknown)
- 大于 5 的值按 CVSS 分数映射

---

### 5.3 scan — 二进制/镜像扫描

**职责**：通过奇安信开源卫士 OpenAPI V3 提交二进制制品（jar/dll/so/lib）或 Docker 镜像的扫描任务，轮询结果，归一化为 DTrack 模型。

#### 核心文件 — [qianxin_scan.py](file:///workspace/dtrack/scan/qianxin_scan.py)

| 类/函数 | 说明 |
|---------|------|
| `ScanKind` (枚举) | 扫描类型：`jar-local`, `jar-nexus`, `jar-artifactory`, `image-local`, `image-harbor`, `image-dockerhub`, `image-nexus`, `image-artifactory` |
| `ScanTarget` (数据类) | 扫描目标描述：kind、path/url、凭据、auth_type、language_hint |
| `QianxinScanner` | 核心扫描器 |
| `scan_target(config, target, task_name)` | CLI 便捷入口 |

#### `QianxinScanner` 主要方法

| 方法 | 说明 |
|------|------|
| `run(target, task_name)` → `AnalysisResult` | 完整流程：提交 → 等待 → 收集 → 归一化 |
| `_submit_for_target(target)` → task_id | 按 ScanKind 分发到对应提交接口 |
| `submit_binary_file(content, filename, ...)` | 上传文件（multipart） |
| `submit_binary_dir(dir_path, ...)` | 提交目录路径 |
| `submit_binary_nexus/artifactory(...)` | 提交仓库制品 URL |
| `submit_image_file/feature/harbor/dockerhub/nexus/artifactory(...)` | 镜像扫描各入口 |
| `wait_done(task_id, ...)` | 轮询任务状态直到完成（code=9 表示检测中） |
| `collect(task_id, language)` | 拉取组件列表 + 漏洞列表 + 未知组件 → 归一化 |
| `_qx_to_component(qx, language)` | 奇安信组件 → DTrack Component |
| `_qx_to_vulnerability(qxv)` | 奇安信漏洞 → DTrack Vulnerability |

**配置回退**：`scan.qianxin.*` 未设置时自动回退到 `vuln.qianxin.*`（共用网关与凭据）。

**扫描流程**：

```
提交扫描任务（按 kind 选择 API 端点）
    ↓
获取 taskId
    ↓
轮询 /open-api/v3/task/binary/result（间隔 poll_interval，超时 poll_timeout）
    ↓
分页拉取：组件列表 / 漏洞列表 / 未知组件列表
    ↓
归一化为 Component + Vulnerability（按 affectVersionList 关联）
    ↓
组装 AnalysisResult
```

---

### 5.4 sources — 仓库拉取器

**职责**：从外部仓库（GitLab、Nexus、Harbor）拉取项目/制品/镜像信息，供 CLI `fetch` 命令和 Web 导入使用。

#### 基类 — [base.py](file:///workspace/dtrack/sources/base.py)

```python
class SourceFetcher(ABC):
    name: str
    def enabled(self) -> bool
    def list_projects(self) -> list[dict]
    def list_images(self) -> list[dict]       # 可选，默认 NotImplementedError
```

#### 注册表 — [registry.py](file:///workspace/dtrack/sources/registry.py)

| 函数 | 说明 |
|------|------|
| `get_fetcher(name, config)` | 按名称获取拉取器实例 |
| `list_fetchers()` | 返回已注册名称列表 |

已注册：`gitlab`、`nexus`、`harbor`

#### 各实现

| 拉取器 | 文件 | 主要方法 |
|--------|------|---------|
| `GitLabFetcher` | [gitlab.py](file:///workspace/dtrack/sources/gitlab.py) | `list_projects()`, `list_refs(project_path)`, `download_repository(project_path, ref, dest_dir)` |
| `NexusFetcher` | [nexus.py](file:///workspace/dtrack/sources/nexus.py) | `list_projects()`, `download_maven_artifact(repo, g, a, v)`, `list_docker_tags(repo)` |
| `HarborFetcher` | [harbor.py](file:///workspace/dtrack/sources/harbor.py) | `list_projects()`, `list_images()` |

启用条件：配置中对应 `repos.<name>.base_url` 非空。

---

### 5.5 report — 报告生成

**职责**：将 `AnalysisResult` 渲染为人类可读的报告文件。

#### Markdown 报告 — [markdown.py](file:///workspace/dtrack/report/markdown.py)

| 函数 | 说明 |
|------|------|
| `render_markdown(result)` → str | 渲染完整 Markdown 报告 |
| `write_report(result, out_dir, filename)` → path | 写入文件并返回路径 |

**报告结构**（六章）：

1. **概览** — 目标、语言、时间、组件/漏洞统计
2. **漏洞分布** — 按严重程度、按来源、按依赖类型、中危及以上清单汇总
3. **组件 License 分布** — 许可证总体分布、Copyleft 传染型许可证、未识别 License 明细
4. **修复建议汇总** — 按组件聚合的修复方案
5. **组件全集** — 所有组件表格（含 License、依赖类型、漏洞数）
6. **组件漏洞明细** — 每个有漏洞组件的详细漏洞列表

辅助函数：
- `_is_copyleft(lic)` — 判断传染性许可证（GPL/LGPL/AGPL/MPL/EPL 等）
- `_should_show_affected(c)` — 判定组件是否展示"影响项目"列（中危以上或 copyleft）
- `_src_label(name)` — 漏洞源展示名映射

#### PDF 报告 — [pdf.py](file:///workspace/dtrack/report/pdf.py)

| 函数 | 说明 |
|------|------|
| `render_pdf(result)` → bytes | 使用 reportlab 生成 A4 PDF（可选依赖） |

- 中文字体：reportlab 内置 CID 字体 `STSong-Light`
- 未安装 reportlab 时抛出明确错误提示

---

### 5.6 utils — 通用工具

| 文件 | 关键类/函数 | 职责 |
|------|------------|------|
| [http.py](file:///workspace/dtrack/utils/http.py) | `HttpClient` | 基于 `urllib` 的 HTTP 客户端：超时、重试、TLS 跳过、GET/POST/multipart |
| | `HttpResponse` | 响应封装（`.text`, `.json()`, `.ok`） |
| | `basic_auth_header(u, p)` | 构造 Basic Auth 头 |
| [cache.py](file:///workspace/dtrack/utils/cache.py) | `FileCache(cache_dir, ttl)` | 磁盘 JSON 缓存：`get(key)`, `set(key, data)`, `clear()` |
| [versions.py](file:///workspace/dtrack/utils/versions.py) | `maven_cmp(a, b)` | Maven 版本号比较 |
| | `parse_range_to_bounds(rng)` → `Bounds` | 解析版本范围字符串（如 `[1.0,2.0)`） |
| | `is_affected(version, bounds)` | 判断版本是否在受影响范围内 |
| [license_normalize.py](file:///workspace/dtrack/utils/license_normalize.py) | `normalize_license(name)` | 许可证名称归一化（"Apache License 2.0" → "Apache-2.0"） |
| [license_detect.py](file:///workspace/dtrack/utils/license_detect.py) | `detect_license_text(text)` | 从 LICENSE 文件文本识别 SPDX 标识 |
| | `find_license_file(directory)` | 在目录中查找 LICENSE/COPYING 文件 |
| [archive.py](file:///workspace/dtrack/utils/archive.py) | `zip_directory(dir_path)` → bytes | 将目录打包为 zip（用于奇安信上传） |

---

### 5.7 web — Web 管理平台

**职责**：提供 REST API + 静态文件服务，支持白名单/项目管理、三方组件库、漏洞扫描、配置管理。完全基于 Python 标准库 `http.server` + `sqlite3`。

#### 架构分层

```
handlers.py (HTTP 路由)  →  service.py (业务逻辑)  →  store.py (SQLite 持久化)
```

#### server.py — [server.py](file:///workspace/dtrack/web/server.py)

| 函数 | 说明 |
|------|------|
| `run_web(host, port, db_path, config_path, dist_dir)` | 启动 Web 服务 |
| `default_db_path()` | 默认 `./db/dtrack.db` |
| `default_config_path()` | 默认 `./config/dtrack.toml` |
| `default_dist_dir()` | 默认 `dtrack/static/`（打包后的前端） |

#### handlers.py — [handlers.py](file:///workspace/dtrack/web/handlers.py)

`_Router.dispatch(method, path, body)` 路由所有 `/api/*` 请求，非 API 路径服务前端静态文件（SPA fallback）。

**API 端点列表**：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/config` | 获取当前配置（可编辑子集） |
| POST | `/api/config` | 更新配置（写回 dtrack.toml） |
| GET | `/api/gitlab/projects` | 列出 GitLab 项目 |
| GET | `/api/gitlab/refs?project=` | 列出项目分支/标签 |
| GET | `/api/whitelists` | 白名单列表 |
| POST | `/api/whitelists/import` | 导入白名单（pom 上传 / GitLab / 镜像扫描） |
| GET | `/api/whitelists/{id}` | 白名单版本列表 |
| GET | `/api/whitelists/{id}/versions` | 同上 |
| GET | `/api/whitelists/version/{vid}` | 版本详情 |
| GET | `/api/whitelists/version/{vid}/components` | 版本的组件列表 |
| POST | `/api/whitelists/version/{vid}/scan` | 触发扫描 |
| GET | `/api/whitelists/version/{vid}/report` | 下载 Markdown 报告 |
| GET | `/api/whitelists/version/{vid}/report.pdf` | 下载 PDF 报告 |
| DELETE | `/api/whitelists/version/{vid}` | 删除版本 |
| GET | `/api/projects` | 项目列表 |
| POST | `/api/projects/import` | 导入项目 |
| GET | `/api/projects/{id}` | 项目版本列表 |
| GET | `/api/projects/version/{vid}` | 版本详情 |
| GET | `/api/projects/version/{vid}/components` | 版本的组件列表 |
| POST | `/api/projects/version/{vid}/scan` | 触发扫描 |
| GET | `/api/projects/version/{vid}/report` | 下载 Markdown 报告 |
| GET | `/api/projects/version/{vid}/report.pdf` | 下载 PDF 报告 |
| DELETE | `/api/projects/version/{vid}` | 删除版本 |
| GET | `/api/components?q=&is_whitelist=&severity=` | 三方组件库列表（支持过滤） |
| GET | `/api/components/detail?coord=` | 组件详情（含漏洞、引用关系） |

#### service.py — [service.py](file:///workspace/dtrack/web/service.py)

`WebService` 类编排所有业务操作：

| 方法 | 说明 |
|------|------|
| `get_config()` / `update_config(patch)` | 读取/更新配置（写回 TOML 文件） |
| `import_whitelist(pom_text, gitlab_project, ref)` | 导入白名单（pom 解析路径） |
| `import_project(pom_text, gitlab_project, ref, name)` | 导入项目 |
| `import_whitelist_scan(payload)` / `import_project_scan(payload)` | 二进制/镜像导入（奇安信扫描路径） |
| `scan_version_async(ref_type, vid)` | 异步触发扫描（后台线程） |
| `_do_scan(ref_type, vid)` | pom 解析路径：在线源查询 + 奇安信扫描模式 |
| `_do_scan_qianxin(ref_type, vid)` | 二进制路径：完全由奇安信扫描产出组件与漏洞 |
| `_qianxin_scan_mode(...)` | 下载组件 jar → 打包 → 提交奇安信二进制扫描 |
| `list_components(filters)` | 组件库查询 |
| `get_component_detail(coord)` | 组件详情（漏洞 + 引用项目） |
| `get_report(ref_type, vid)` / `get_report_pdf(...)` | 获取报告 |
| `list_gitlab_projects()` / `list_gitlab_refs(project)` | GitLab 数据代理 |

**扫描状态机**：`pending → scanning → done / failed / no_qianxin`

#### store.py — [store.py](file:///workspace/dtrack/web/store.py)

`Db` 类封装所有 SQLite 操作。

**数据表结构**：

| 表 | 说明 |
|----|------|
| `config_mirror` | 配置镜像（key-value） |
| `whitelist` | 白名单 owner（group_id, artifact_id, name） |
| `whitelist_version` | 白名单版本（source, pom_text, scan_meta, summary_json, report_md, scan_status） |
| `project` | 项目 owner |
| `project_version` | 项目版本（结构同 whitelist_version） |
| `component` | 三方组件目录（coord 唯一, license, is_whitelist） |
| `component_usage` | 组件引用关系（哪个版本引用了哪个组件，direct/transitive） |
| `vulnerability` | 归一化漏洞记录（关联 component_id） |

**关键方法**（37 个）：`upsert_whitelist`, `add_whitelist_version`, `upsert_component`, `add_usage`, `add_vulnerability`, `list_components`, `get_component_detail`, `components_for_version`, `version_stats`, `set_version_status`, `set_version_report`, `delete_version` 等。

---

### 5.8 config — 配置管理

**文件**：[config.py](file:///workspace/dtrack/config.py)

**配置优先级**（低→高）：内置默认值 < 配置文件 < 环境变量 < CLI 参数

**配置文件发现顺序**：
1. `--config` 参数指定路径
2. `./config/dtrack.toml` / `./config/dtrack.json`
3. `./dtrack.toml` / `./dtrack.json`
4. `~/.dtrack.toml` / `~/.dtrack.json`

**环境变量覆盖**：`DTRACK__SECTION__KEY` 格式，如 `DTRACK__VULN__QIANXIN__BASE_URL`

**主要配置段**：

| 段 | 说明 |
|----|------|
| `general` | 缓存目录/TTL、日志级别/文件、超时、并发数 |
| `maven` | Maven 路径、Central URL、传递解析深度、license 解析开关 |
| `analyze` | 排除作用域、排除测试框架 |
| `repos` | GitLab/Nexus/Harbor 地址与凭据 |
| `vuln` | 漏洞源列表与各源配置 |
| `scan` | 奇安信二进制/镜像扫描配置 |
| `report` | 输出目录、格式、是否展示 license |

**关键函数**：

| 函数 | 说明 |
|------|------|
| `load_config(explicit_path)` → `Config` | 加载并合并配置 |
| `Config.get(dotted, default)` | 点路径访问（如 `"vuln.qianxin.base_url"`） |
| `write_example_config(path)` | 生成示例配置文件 |

---

### 5.9 cli — 命令行入口

**文件**：[cli.py](file:///workspace/dtrack/cli.py)

**子命令**：

| 命令 | 说明 |
|------|------|
| `dtrack web` | 启动 Web 管理平台 |
| `dtrack config init` | 生成示例配置 |
| `dtrack config show` | 显示当前配置 |
| `dtrack analyze TARGET` | 分析目标并生成报告 |
| `dtrack fetch SOURCE` | 从仓库拉取项目/制品 |
| `dtrack scan` | 二进制/镜像漏洞扫描 |

**`analyze` 流程**：

```
加载配置 → 获取分析器 → 解析组件 → [可选] 漏洞聚合 → 组装 AnalysisResult → 渲染报告 → 输出
```

**`scan` 流程**：

```
加载配置 → 构造 ScanTarget → QianxinScanner.run() → 渲染报告 → 输出
```

---

## 6. 模块依赖关系

```
cli.py
 ├── config.py
 ├── core/ (models, types)
 ├── analyzers/ (registry → java/, cc/)
 ├── vuln/ (aggregator → registry → nvd/github/osv/qianxin)
 ├── scan/ (qianxin_scan)
 ├── sources/ (registry → gitlab/nexus/harbor)
 ├── report/ (markdown, pdf)
 └── web/ (server → handlers → service → store)

依赖方向（单向，无循环）：

  cli ──→ analyzers ──→ core
   │          │
   │          └──→ utils (http, cache)
   │
   ├──→ vuln ──→ core
   │       └──→ utils (http, cache, versions)
   │
   ├──→ scan ──→ core, vuln.qianxin, utils (http, archive)
   │
   ├──→ sources ──→ utils (http)
   │
   ├──→ report ──→ core, utils (license_normalize)
   │
   └──→ web ──→ analyzers.java, vuln, scan, sources, report, core, config
              └──→ store (sqlite3)
```

**关键设计**：
- `base.py` 与 `registry.py` 分离，避免循环导入（具体实现导入基类，注册表导入具体实现）。
- `core` 是最底层模块，不依赖任何其他 dtrack 模块。
- `utils` 是纯工具层，不依赖 `core` 以外的业务模块。
- `web.service` 是唯一同时依赖 `analyzers`、`vuln`、`scan`、`sources`、`report` 的模块（编排层）。

---

## 7. 关键数据流

### 7.1 CLI analyze（Java 项目）

```
用户: dtrack analyze ./my-project --lang java --sources nvd,osv

1. load_config() → Config
2. get_analyzer(JAVA, config) → JavaAnalyzer
3. JavaAnalyzer.analyze("./my-project")
   a. 收集所有 pom.xml
   b. parse_pom_file() → Pom (直接依赖 + managed 依赖)
   c. MvnTreeResolver.resolve() 或 MavenCentralResolver.resolve()
   d. 生成 Component 列表（direct/transitive 标记）
   e. 剔除 test 作用域 + 测试框架
   f. maven_central_license() 补充 license
4. VulnerabilityAggregator(config).analyze_components(components)
   a. 线程池并发，每组件查询所有启用源
   b. 各源: query(component) → list[Vulnerability]
   c. 按 dedup_key() 去重合并
   d. 结果写入 component.vulnerabilities
5. AnalysisResult(target, language, components, sources_used)
6. result.enrich_summary() → 统计摘要
7. render_markdown(result) → Markdown 文本
8. write_report() → reports/dtrack_report_xxx.md
```

### 7.2 Web 导入与扫描

```
用户: POST /api/whitelists/import {pom_text: "..."}

1. WebService.import_whitelist(pom_text, None, None)
2. _resolve_pom_dir() → 写入临时目录
3. _project_coords() → 提取 groupId:artifactId:version
4. _analyze_components() → JavaAnalyzer.analyze()
5. db.upsert_whitelist() + db.add_whitelist_version()
6. 每个组件: db.upsert_component() + db.add_usage()
7. scan_version_async("whitelist", vid) → 后台线程
   a. _do_scan(): 在线源查询 + 奇安信扫描模式
   b. 漏洞入库: db.add_vulnerability()
   c. _build_report(): render_markdown() → db.set_version_report()
   d. db.set_version_status("done")
```

### 7.3 奇安信二进制扫描

```
用户: dtrack scan --kind jar-local --path ./libs

1. ScanTarget(kind=JAR_LOCAL, path="./libs")
2. QianxinScanner.run(target)
   a. _submit_for_target(): 目录 → zip → multipart 上传
   b. 获取 taskId
   c. wait_done(): 轮询直到完成
   d. collect(): 拉取组件/漏洞/未知组件 → 归一化
3. AnalysisResult(components, vulnerabilities)
4. render_markdown() → 报告
```

---

## 8. 配置系统

### 配置文件示例（config/dtrack.toml）

```toml
[general]
cache_dir = "~/.dtrack/cache"
cache_ttl = 86400
log_level = "INFO"
timeout = 30
concurrency = 4

[maven]
home = "D:\\mavendown\\apache-maven-3.9.6"
central_url = "https://repo1.maven.org/maven2"
resolve_transitive = true
max_depth = 5
use_mvn_tree = true
resolve_license = true

[analyze]
exclude_scopes = ["test"]
exclude_test_frameworks = true

[repos.gitlab]
base_url = "https://gitlab.com"
token = ""
enabled = false

[vuln]
sources = ["nvd", "github", "qianxin", "osv"]

[vuln.qianxin]
base_url = "https://<host>:8449"
auth_type = "private-token"
token = ""
page_size = 20

[scan.qianxin]
project_id = ""
poll_interval = 5
poll_timeout = 1800

[report]
out_dir = "./reports"
format = "markdown"
include_license = true
```

### 环境变量覆盖

```bash
export DTRACK__VULN__QIANXIN__BASE_URL="https://10.0.0.1:8449"
export DTRACK__ANALYZE__EXCLUDE_TEST_FRAMEWORKS=false
```

---

## 9. 项目运行方式

### 9.1 环境要求

- **Python ≥ 3.11**（使用 `tomllib`）
- 核心功能零第三方依赖，无需 `pip install`
- 可选：`reportlab`（PDF 导出）、Maven（`mvn dependency:tree`）

### 9.2 CLI 使用

```bash
# 分析 Java 项目
python -m dtrack.cli analyze ./my-project --lang java --sources nvd,osv --out reports

# 分析 C/C++ 项目
python -m dtrack.cli analyze ./my-cpp-project --lang c/c++ --sources osv --out reports

# 仅解析依赖，不查询漏洞
python -m dtrack.cli analyze ./my-project --skip-vuln

# 二进制扫描（奇安信）
python -m dtrack.cli scan --kind jar-local --path ./libs --project-id 123

# 镜像扫描
python -m dtrack.cli scan --kind image-harbor --url harbor.example.com/app:v1 \
    --username admin --password xxx

# 从 GitLab 拉取项目
python -m dtrack.cli fetch gitlab --list-projects
python -m dtrack.cli fetch gitlab --download group/project --ref main

# 配置管理
python -m dtrack.cli config init
python -m dtrack.cli config show
```

### 9.3 Web 平台

```bash
# 启动 Web 服务（默认 127.0.0.1:8080）
python -m dtrack.cli web

# 指定端口和数据库
python -m dtrack.cli web --host 0.0.0.0 --port 9090 --db ./data/dtrack.db
```

启动后访问 `http://127.0.0.1:8080`，功能包括：
- **白名单管理**：导入 pom / GitLab 项目 / 镜像，查看版本与漏洞
- **项目管理**：同上，面向业务项目
- **三方组件库**：全局组件目录，支持搜索/过滤/详情
- **系统配置**：在线编辑仓库/漏洞源配置

### 9.4 前端开发

```bash
cd web
npm install
npm run dev      # 开发模式 (Vite HMR)
npm run build    # 构建到 web/dist/（同时输出到 dtrack/static/）
```

前端技术栈：Vue 3 + Vue Router + Pinia + Element Plus + Vite

### 9.5 Windows 打包

```bash
# 一键打包（构建前端 + PyInstaller 生成单文件 exe）
build_windows.bat

# 产物：dist/DTrack.exe
# 双击运行 → 默认启动 Web 平台 (http://127.0.0.1:8080)
```

---

## 10. 测试

测试位于 `tests/` 目录，使用 `unittest` / `pytest`：

```bash
# 运行全部测试
python -m pytest tests/ -v

# 或使用 unittest（离线兼容）
python -m unittest discover -s tests -p "test_*.py"
```

| 测试文件 | 覆盖范围 |
|---------|---------|
| `test_pom_parser.py` | POM XML 解析 |
| `test_maven_resolver.py` | Maven 依赖解析 |
| `test_java_analyzer.py` | Java 分析器集成 |
| `test_cmake_parser.py` | CMake 解析 |
| `test_lib_scanner.py` | C/C++ 库文件扫描 |
| `test_osv.py` | OSV 漏洞源 |
| `test_scan_qianxin.py` | 奇安信扫描 |
| `test_qianxin_source.py` | 奇安信漏洞查询 |
| `test_report.py` | 报告生成 |
| `test_license_detect.py` / `test_license_normalize.py` | 许可证识别与归一化 |
| `test_web_*.py` | Web API 集成测试 |

---

## 11. 打包与部署

### PyInstaller 打包

- 入口脚本：[packaging/boot.py](file:///workspace/packaging/boot.py)（无参数时默认启动 `web`）
- Spec 文件：[packaging/dtrack.spec](file:///workspace/packaging/dtrack.spec)
- 打包命令：`python -m PyInstaller --noconfirm --clean packaging/dtrack.spec`
- 产物：`dist/DTrack.exe`（单文件，含前端静态资源）

### 离线部署要点

1. 核心引擎完全离线可用（解析、报告生成不依赖网络）
2. 漏洞在线查询需网络（NVD/GitHub/OSV）；奇安信为内网部署
3. Maven 依赖解析：有 Maven 用 `mvn dependency:tree`；无 Maven 回退到纯 Python 解析（需网络或本地仓库缓存）
4. SQLite 数据库自动创建，无需外部数据库服务

---

## 附录：技术栈总结

| 层 | 技术 |
|----|------|
| 后端语言 | Python 3.11+（核心零第三方依赖） |
| 前端 | Vue 3 + Element Plus + Pinia + Vite |
| 数据库 | SQLite（stdlib sqlite3） |
| HTTP 服务 | stdlib http.server (ThreadingHTTPServer) |
| HTTP 客户端 | stdlib urllib.request（封装为 HttpClient） |
| 配置格式 | TOML (stdlib tomllib) / JSON |
| 报告 | Markdown（纯文本拼接）/ PDF（可选 reportlab） |
| 打包 | PyInstaller（Windows 单文件 exe） |
| 外部 API | NVD 2.0, GitHub GraphQL, OSV v1, 奇安信 OpenAPI V3, GitLab v4, Harbor v2, Nexus REST |
