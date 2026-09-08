# DTrack — 开发模块漏洞分析管理系统（离线运行版）

DTrack 是一个模块化的开发组件（Java/JAR、C/C++）漏洞分析管理系统。
**本包为纯标准库（stdlib）实现，不含任何第三方依赖，可在无互联网环境直接运行。**

## 运行环境

- Python 3.13.12（与目标/构建环境版本一致即可；官方要求 `>=3.11`，因使用了 `tomllib`）。
- 无需 `pip install`，无需任何第三方包。
- 解压后目录结构（节选）：
  ```
  DTrack/
  ├── dtrack/            # 核心源码包（直接执行入口：dtrack.cli）
  ├── dtrack.example.toml # 配置示例
  ├── samples/           # 演示项目（Java / C++）
  ├── tests/             # 离线自测用例（可选）
  ├── pyproject.toml
  └── requirements.txt   # 声明：零第三方依赖
  ```

## 快速开始

1. 解压到目标机器任意目录。
2. （可选）自定义配置：复制示例并修改
   ```bash
   cp config/dtrack.example.toml config/dtrack.toml
   # 用编辑器调整：maven.home、漏洞源开关、exclude_scopes 等
   ```
   不创建 `config/dtrack.toml` 也会使用代码内置的默认配置，可直接运行。
   （SQLite 数据库默认位于 `db/dtrack.db`，可通过 `dtrack web --db <路径>` 指定其他位置。）
3. 运行分析（使用内置 Python）：
   ```bash
   # Java 项目（解析 pom.xml）
   python -m dtrack.cli analyze <项目目录或pom.xml> --lang java --sources nvd,osv --out reports

   # C/C++ 项目（解析 CMakeLists + 扫描库文件）
   python -m dtrack.cli analyze <项目目录> --lang c/c++ --sources osv --out reports
   ```
   报告默认输出为 Markdown，存放于 `--out` 指定的目录。

## 常用命令

```bash
# 生成示例配置文件
python -m dtrack.cli config init

# 查看当前生效配置
python -m dtrack.cli config show

# 离线校验本包是否完整（需目标机有 Python，且与构建版本一致）
python -m unittest discover -s tests -p "test_*.py"
```

## 离线说明

- **工具本身完全离线运行**：解析、报告生成、依赖图构建均不依赖网络。
- **漏洞在线查询才需要网络**：`nvd` / `github` / `osv` / `qianxin` 等源需访问外网
  API。无法联网的目标环境将无法获取在线漏洞数据（可用 `--sources` 关闭，或后续接入
  内网漏洞镜像，超出本包范围）。
- Maven 依赖解析：本机已安装 Maven 时优先 `mvn dependency:tree`；未安装时自动回退为
  纯 Python 解析 Maven Central 元数据（同样需要网络下载 pom，离线场景建议提前缓存或
  提供本地仓库 `maven.local_repo`）。

## 配置要点（dtrack.example.toml）

- `maven.home`：Maven 安装路径（用于 `mvn dependency:tree`）。
- `analyze.exclude_scopes`：默认 `["test"]`，剔除 test 作用域依赖。
- `analyze.exclude_test_frameworks`：默认 `true`，剔除被误标为 compile 的测试框架
  （junit / mockito 等）。
- `vuln.sources`：启用的漏洞源列表。
- 环境变量覆盖：`DTRACK__SECTION__KEY`，例如 `DTRACK__ANALYZE__EXCLUDE_TEST_FRAMEWORKS=false`。
