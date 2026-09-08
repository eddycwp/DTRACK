# 三方组件漏洞分析报告

## 一、概览

- **分析目标**：Maven project(s): com.example:demo-app:1.0.0
- **分析语言**：java
- **生成时间**：2026年08月17日  14时:14分，北京时间。
- **使用的漏洞源**：NVD, OSV
- **组件总数**：5
- **存在漏洞的组件数**：4
- **漏洞总数**：17
- **直接依赖 / 传递依赖**：3 / 2

**备注**：
  - 已剔除 47 个测试相关依赖（test 作用域及 junit/mockito 等测试框架），因其不参与发布产物，不计入漏洞分析。

## 二、漏洞分布

### 2.1 按严重程度

| 严重程度 | 数量 |
| --- | ---: |
| 超危/严重 | 3 |
| 高危 | 6 |
| 中危 | 7 |
| 低危 | 1 |
| 未知 | 0 |

### 2.2 按漏洞来源

| 来源 | 漏洞数 |
| --- | ---: |
| OSV | 11 |
| NVD | 6 |

### 2.3 依赖类型分布

| 类型 | 组件数 |
| --- | ---: |
| 直接依赖 | 3 |
| 传递依赖 | 2 |

### 2.4 组件 License 分布

| License | 类型 | 组件数 |
| --- | --- | ---: |
| Apache License, Version 2.0 | 宽松型 | 2 |
| 未知/未识别 | 未知 | 3 |

## 三、组件漏洞明细

<a id="comp-detail-0"></a>
### [超危/严重] commons-collections:commons-collections:3.2.1 （直接依赖）

- **漏洞数**：2
- **漏洞列表**：
<a id="comp-detail-0-sev-critical"></a>
  - **CVE-2015-7501** （超危/严重） 来源：[OSV] — Deserialization of Untrusted Data in Apache commons collections
    - 影响版本：>=0 <3.2.2
    - **修复建议**：将 commons-collections 从 3.2.1 升级到 3.2.2 版本
    - 描述：It was found that the Apache commons-collections library permitted code execution when deserializing objects involving a specially constructed chain of classes. A remote attacker could use this flaw to execute arbitrary code with the permissions of the application using the commons-collections libra…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2015-7501> <https://access.redhat.com/security/vulnerabilities/2059393> <https://access.redhat.com/solutions/2045023>
<a id="comp-detail-0-sev-high"></a>
  - **CVE-2015-6420** （高危） 来源：[OSV] — Insecure Deserialization in Apache Commons Collection
    - 影响版本：>=0 <3.2.2
    - **修复建议**：将 commons-collections 从 3.2.1 升级到 3.2.2 版本
    - 描述：Serialized-object interfaces in Java applications using the Apache Commons Collections (ACC) library may allow remote attackers to execute arbitrary commands via a crafted serialized Java object.
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2015-6420> <https://arxiv.org/pdf/2306.05534> <https://github.com/apache/commons-collections>

<a id="comp-detail-1"></a>
### [超危/严重] org.apache.logging.log4j:log4j-core:2.14.0 （直接依赖）

- **漏洞数**：10
- **漏洞列表**：
<a id="comp-detail-1-sev-critical"></a>
  - **CVE-2021-45046** （超危/严重） 来源：[OSV] — Incomplete fix for Apache Log4j vulnerability
    - 影响版本：>=2.13.0 <2.16.0; >=0 <2.12.2
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.16.0 版本
    - 描述：# Impact  The fix to address [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allow attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-defau…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-45046> <https://www.oracle.com/security-alerts/cpujul2022.html> <https://www.oracle.com/security-alerts/cpujan2022.html>
  - **CVE-2021-44228** （超危/严重） 来源：[OSV] — Remote code injection in Log4j
    - 影响版本：>=2.13.0 <2.15.0; >=2.0-beta9 <2.3.1; >=2.4 <2.12.2
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.15.0 版本
    - 描述：# Summary  Log4j versions prior to 2.16.0 are subject to a remote code execution vulnerability via the ldap JNDI parser. As per [Apache's Log4j security guide](https://logging.apache.org/log4j/2.x/security.html): Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameter…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-44228> <https://github.com/apache/logging-log4j2/pull/608> <https://github.com/github/advisory-database/pull/5501>
<a id="comp-detail-1-sev-high"></a>
  - **CVE-2026-34479** （高危） 来源：[NVD] — CVE-2026-34479
    - 影响版本：>= 2.7, < 2.25.4
    - **修复建议**：暂无明确修复版本，建议将 log4j-core 升级到官方发布的最新安全版本，并关注厂商安全公告
    - 描述：The Log4j1XmlLayout from the Apache Log4j 1-to-Log4j 2 bridge fails to escape characters forbidden by the XML 1.0 standard, producing malformed XML output. Conforming XML parsers are required to reject documents containing such characters with a fatal error, which may cause downstream log processing…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4078> <https://lists.apache.org/thread/gd0hp6mj17rn3kj279vgy4p7kd4zz5on> <https://logging.apache.org/cyclonedx/vdr.xml>
  - **CVE-2026-34480** （高危） 来源：[NVD, OSV] — CVE-2026-34480
    - 影响版本：>= 2.0, < 2.25.4
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.25.4 版本
    - 描述：Apache Log4j Core's  XmlLayout https://logging.apache.org/log4j/2.x/manual/layouts.html#XmlLayout , in versions up to and including 2.25.3, fails to sanitize characters forbidden by the  XML 1.0 specification https://www.w3.org/TR/xml/#charsets  producing invalid XML output whenever a log message or…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4077> <https://lists.apache.org/thread/5x0hcnng0chhghp6jgjdp3qmbbhfjzhb> <https://logging.apache.org/cyclonedx/vdr.xml>
  - **CVE-2026-34481** （高危） 来源：[NVD] — CVE-2026-34481
    - 影响版本：>= 2.14.0, < 2.25.4
    - **修复建议**：暂无明确修复版本，建议将 log4j-core 升级到官方发布的最新安全版本，并关注厂商安全公告
    - 描述：Apache Log4j's  JsonTemplateLayout https://logging.apache.org/log4j/2.x/manual/json-template-layout.html , in versions up to and including 2.25.3, produces invalid JSON output when log events contain non-finite floating-point values (NaN, Infinity, or -Infinity), which are prohibited by RFC 8259. Th…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4080> <https://lists.apache.org/thread/n34zdv00gbkdbzt2rx9rf5mqz6lhopcv> <https://logging.apache.org/cyclonedx/vdr.xml>
  - **CVE-2021-45105** （高危） 来源：[OSV] — Apache Log4j2 vulnerable to Improper Input Validation and Uncontrolled Recursion
    - 影响版本：>=2.4.0 <2.12.3; >=2.13.0 <2.17.0; >=0 <2.3.1
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.12.3 版本
    - 描述：Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in …
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-45105> <https://www.zerodayinitiative.com/advisories/ZDI-21-1541> <https://www.oracle.com/security-alerts/cpujul2022.html>
<a id="comp-detail-1-sev-medium"></a>
  - **CVE-2025-68161** （中危） 来源：[NVD, OSV] — CVE-2025-68161
    - 影响版本：>= 2.0.1, < 2.25.3
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.25.3 版本
    - 描述：The Socket Appender in Apache Log4j Core versions 2.0-beta9 through 2.25.2 does not perform TLS hostname verification of the peer certificate, even when the  verifyHostName https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName  configuration attribut…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4002> <https://lists.apache.org/thread/xr33kyxq3sl67lwb61ggvm1fzc8k7dvx> <https://logging.apache.org/cyclonedx/vdr.xml>
  - **CVE-2026-34477** （中危） 来源：[NVD, OSV] — CVE-2026-34477
    - 影响版本：>= 2.12.0, < 2.25.4
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.25.4 版本
    - 描述：The fix for  CVE-2025-68161 https://logging.apache.org/security.html#CVE-2025-68161  was incomplete: it addressed hostname verification only when enabled via the  log4j2.sslVerifyHostName https://logging.apache.org/log4j/2.x/manual/systemproperties.html#log4j2.sslVerifyHostName  system property, but…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4075> <https://lists.apache.org/thread/lkx8cl46t2bvkcwfcb2pd43ygc097lq4> <https://logging.apache.org/cyclonedx/vdr.xml>
  - **CVE-2026-49844** （中危） 来源：[NVD] — CVE-2026-49844
    - 影响版本：>= 2.13.1, < 2.25.5
    - **修复建议**：暂无明确修复版本，建议将 log4j-core 升级到官方发布的最新安全版本，并关注厂商安全公告
    - 描述：Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON. This issue affects Apache Log4j API versions 2.13.1 through 2.25.4 and version 2.26.0.  The fix for CVE-2026-34481 did not cover all code paths: when…
    - 参考：<https://github.com/apache/logging-log4j2/pull/4163> <https://logging.apache.org/cyclonedx/vdr.xml> <https://logging.apache.org/log4j/2.x/manual/json-template-layout.html#event-template-resolver-message>
  - **CVE-2021-44832** （中危） 来源：[OSV] — Improper Input Validation and Injection in Apache Log4j2
    - 影响版本：>=2.0-beta7 <2.3.2; >=2.4 <2.12.4; >=2.13.0 <2.17.1
    - **修复建议**：将 log4j-core 从 2.14.0 升级到 2.3.2 版本
    - 描述：Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to an attack where an attacker with permission to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data source referencing a JND…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-44832> <https://cert-portal.siemens.com/productcert/pdf/ssa-784507.pdf> <https://github.com/apache/logging-log4j2>

<a id="comp-detail-2"></a>
### [高危] org.springframework:spring-core:5.3.3 （直接依赖）

- **License**：Apache License, Version 2.0
- **漏洞数**：4
- **漏洞列表**：
<a id="comp-detail-2-sev-high"></a>
  - **CVE-2025-41249** （高危） 来源：[OSV] — Spring Framework annotation detection mechanism may result in improper authorization
    - 影响版本：>=5.3.0 <=5.3.44; >=6.0.0 <=6.1.22; >=6.2.0 <6.2.11
    - **修复建议**：将 spring-core 从 5.3.3 升级到 6.2.11 版本
    - 描述：The Spring Framework annotation detection mechanism may not correctly resolve annotations on methods within type hierarchies with a parameterized super type with unbounded generics. This can be an issue if such annotations are used for authorization decisions.  Your application may be affected by th…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2025-41249> <https://github.com/spring-projects/spring-framework/issues/35342> <https://github.com/spring-projects/spring-framework/commit/6d710d482a6785b069e35022e81758953afc21ff>
<a id="comp-detail-2-sev-medium"></a>
  - **CVE-2021-22060** （中危） 来源：[OSV] — Log entry injection in Spring Framework
    - 影响版本：>=5.3.0 <5.3.14; >=5.2.0 <5.2.19
    - **修复建议**：将 spring-core 从 5.3.3 升级到 5.3.14 版本
    - 描述：In Spring Framework versions 5.3.0 - 5.3.13, 5.2.0 - 5.2.18, and older unsupported versions, it is possible for a user to provide malicious input to cause the insertion of additional log entries. This is a follow-up to CVE-2021-22096 that protects against additional types of input and in more places…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-22060> <https://tanzu.vmware.com/security/cve-2021-22060> <https://www.oracle.com/security-alerts/cpuapr2022.html>
  - **CVE-2021-22096** （中危） 来源：[OSV] — Improper Output Neutralization for Logs in Spring Framework
    - 影响版本：>=5.3.0 <5.3.11; >=5.2.0 <5.2.18
    - **修复建议**：将 spring-core 从 5.3.3 升级到 5.3.11 版本
    - 描述：In Spring Framework versions 5.3.0 - 5.3.10, 5.2.0 - 5.2.17, and older unsupported versions, it is possible for a user to provide malicious input to cause the insertion of additional log entries.
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2021-22096> <https://github.com/spring-projects/spring-framework> <https://security.netapp.com/advisory/ntap-20211125-0005>
<a id="comp-detail-2-sev-low"></a>
  - **CVE-2026-41848** （低危） 来源：[OSV] — Spring Framework Denial of Service via AntPathMatcher
    - 影响版本：>=7.0.0 <7.0.8; >=6.2.0 <6.2.19; >=6.1.0 <=6.1.21; >=0 <=5.3.39
    - **修复建议**：将 spring-core 从 5.3.3 升级到 7.0.8 版本
    - 描述：Applications may be vulnerable to a Regular Expression Denial of Service (ReDoS) attack if an attacker is able to provide a pattern which is then directly or indirectly supplied to one of the following methods in AntPathMatcher: match(String pattern, String path), matchStart(String pattern, String p…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2026-41848> <https://github.com/spring-projects/spring-framework/commit/12b44f2545a1bec6150c7a05e66092c732597a94> <https://github.com/spring-projects/spring-framework>

<a id="comp-detail-3"></a>
### [中危] org.apache.logging.log4j:log4j-api:2.14.0 （传递依赖）

- **漏洞数**：1
- **漏洞列表**：
<a id="comp-detail-3-sev-medium"></a>
  - **CVE-2026-49844** （中危） 来源：[OSV] — Apache Log4j API: Improper encoding of non-finite floating-point values during MapMessage JSON serialization
    - 影响版本：>=2.13.1 <2.25.5; >=2.26.0 <2.26.1
    - **修复建议**：将 log4j-api 从 2.14.0 升级到 2.25.5 版本
    - 描述：Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON. This issue affects Apache Log4j API versions 2.13.1 through 2.25.4 and version 2.26.0.  The fix for CVE-2026-34481 did not cover all code paths: when…
    - 参考：<https://nvd.nist.gov/vuln/detail/CVE-2026-49844> <https://github.com/apache/logging-log4j2/pull/4163> <https://github.com/apache/logging-log4j2/commit/19edb23e162d6c728a8c2221a240037d389ed300>
- **依赖路径**：`org.apache.logging.log4j:log4j-core:2.14.0`

## 四、修复建议汇总

| 组件 | 依赖类型 | 最高严重度 | License | 修复建议 |
| --- | --- | --- | --- | --- |
| commons-collections:commons-collections:3.2.1 | 直接 | 超危/严重 | — | 升级 commons-collections 至 3.2.2 |
| org.apache.logging.log4j:log4j-core:2.14.0 | 直接 | 超危/严重 | — | 升级 log4j-core 至 2.25.4 |
| org.springframework:spring-core:5.3.3 | 直接 | 高危 | Apache License, Version 2.0 | 升级 spring-core 至 7.0.8 |

## 五、组件全集

_共 5 个组件。下表为全部组件汇总：有漏洞的组件在「漏洞分级」列按严重级别逐行列出各级别漏洞数量，每一行均为链接，点击可跳转到第三章中该级别的第一个漏洞；无漏洞组件标记为「无」。_

| # | 组件 | 依赖类型 | 版本 | License | 漏洞分级 |
| --- | --- | --- | --- | --- | --- |
| 1 | commons-collections:commons-collections | 直接 | 3.2.1 | — | [超危/严重 1](#comp-detail-0-sev-critical)<br>[高危 1](#comp-detail-0-sev-high) |
| 2 | org.apache.logging.log4j:log4j-core | 直接 | 2.14.0 | — | [超危/严重 2](#comp-detail-1-sev-critical)<br>[高危 4](#comp-detail-1-sev-high)<br>[中危 4](#comp-detail-1-sev-medium) |
| 3 | org.springframework:spring-core | 直接 | 5.3.3 | Apache License, Version 2.0 | [高危 1](#comp-detail-2-sev-high)<br>[中危 2](#comp-detail-2-sev-medium)<br>[低危 1](#comp-detail-2-sev-low) |
| 4 | org.apache.logging.log4j:log4j-api | 传递 | 2.14.0 | — | [中危 1](#comp-detail-3-sev-medium) |
| 5 | org.springframework:spring-jcl | 传递 | 5.3.3 | Apache License, Version 2.0 | 无 |

---
_由 DTrack 生成 · 漏洞数据来源：NVD, OSV · 报告仅供安全加固参考_
