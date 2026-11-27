# AI-Net-Guard 仓库结构说明（Repository Layout）

> 适用版本：v5.8.6 及之后。本文只描述**目录职责与边界**，不重复 [`README.md`](../README.md) 的功能介绍和 [`CURRENT-IMPLEMENTATION.md`](../CURRENT-IMPLEMENTATION.md) 的实现复盘。

## 1. 一句话分区

仓库分成 6 类：`scripts/`（真正会跑到系统上的代码）、`gui/`（配置中心源码与构建脚本）、`tests/`（构建期回归门禁）、`docs/`（长期文档与版本历史）、根目录 9 个文件（GitHub 标准入口 + 两份运行时数据）、`.github/`（CI 与发版工作流）。**其余目录一律不入库**，由 `.gitignore` 排除。

判断一个文件该放哪，只看一个问题：**它会不会被 `gui/build.ps1` 打进 `payload.zip`？** 会 → 放 `scripts/`；不会但是构建期必须验证的 → 放 `tests/`；都不是且需要留档 → 放 `docs/`。

## 2. 目录地图

| 路径 | 入库 | 由谁生成 | 说明 |
| :--- | :---: | :--- | :--- |
| `scripts/` | 是 | 手工维护 | **唯一发行脚本源**。`gui/build.ps1` 用 `Get-ChildItem scripts -Filter *.ps1` 自动打包，新增脚本无需登记名单；所有 `.ps1` 强制纯 ASCII + AST 语法检查。 |
| `gui/` | 是 | 手工维护 | WPF 配置中心源码、`build.ps1`、UAC 清单。`gui/obj/` 与 `gui/bin/` 是构建产物，已忽略。 |
| `tests/` | 是 | 手工维护 | 构建期回归门禁，由 `build.ps1` 在 ASCII/AST 检查后强制调用，失败即 `throw`。**只进门禁，不进 `payload.zip`**（打包段独立从 `scripts/` 取文件）。 |
| `docs/` | 是 | 手工维护 | 长期技术文档。`releases/` 是**发布说明的权威副本**，纳入版本控制以便追溯。 |
| `patches/` | 是 | 手工维护 | 上游内核补丁（当前 1 份：Xray 在 Win11 24H2 的 TUN 修复）。 |
| `.github/` | 是 | 手工维护 | `ci.yml`（push main / PR 触发构建+冒烟，纯文档变更由 `paths-ignore` 跳过）、`release-exe.yml`（`v*` tag 触发构建并创建 Release）、Issue 模板。 |
| `dist/` | 否 | `build.ps1` | 本地构建产物：exe、`.sha256`、portable zip、Rescue.bat，以及发版时用的 release notes **工作副本**。CI 会自行重新生成，故不入库。 |
| `backup/` | 否 | 运行时/运维脚本 | ACL 快照、`guard-policy.json`、`mode-state.json`、`b1-guard.meta`、v2rayN 数据库备份、临时探针工具。**含不可再生的现场证据，不属于仓库整理范围**。 |
| `scratch/` | 否 | 历次调试 | 一次性脚本、AB 对照、抓包输出等。体量大但不入库，**清理需单独确认**（见第 6 节）。 |
| `logs/` | 否 | `07-mode.ps1` | `watchdog.log` 等活体运行证据。 |
| `.workbuddy/` | 否 | 本地助手 | 会话工作记忆，按平台约定不入库。 |

## 3. 根目录 9 个文件逐项说明

| 文件 | 为什么必须在根目录 |
| :--- | :--- |
| `README.md` / `README_EN.md` | GitHub 自动展示入口，移动会失去仓库主页渲染。 |
| `LICENSE` / `SECURITY.md` | GitHub 标准识别路径。 |
| `CURRENT-IMPLEMENTATION.md` | 逐版本实现复盘与审查记录（16.x 章节按版本递增，**历史章节标题不随新版本改写**）。 |
| `Emergency-Rescue.bat` | 离线脱困脚本，用户按文档直接双击根目录路径。 |
| `cn-ipv4.txt` | 由 `scripts/11-geo-cn.ps1` 生成的 6,516 条国内网段基线。 |
| `ai-domains.txt` | 国内域名直连清单。 |
| `.gitignore` | 见第 2 节忽略策略。 |

> **根目录不是脚本入口。** 生产目录 `C:\AI-Net-Guard` 曾残留 15 个 2026-11-03 的同名旧副本，照文档从根目录运行会执行旧代码；它们已于 2026-11-23 移动到 `C:\AI-Net-Guard\archive\stale-root-20261123`（含 `MANIFEST.tsv` 逐条 SHA-256），生产根目录只保留 `07-mode.ps1` 一个入口且与 `scripts\` 那份字节相同。仓库根目录本来就**没有**这些副本。

## 4. 运行时数据的同步边界（不可越界）

`scripts/13-harden-acl.ps1 -SyncWorkspace` **只同步 `scripts\*.ps1`**，并重新锁定 ACL。

- `cn-ipv4.txt` / `ai-domains.txt` / `backup\guard-policy.json` / `backup\*.meta` 由**生产目录独立维护**，禁止从仓库反向覆盖。
- `-WorkspaceRoot` 必须显式给出，否则从 `scripts\` 启动时相对路径会把脚本铺到生产根目录。
- 发版与部署是两步：`git tag` 只更新 Release，实机要同步后才用上新逻辑；同步前 `07 -Status` 不会有 `B1 route guard` 行，也不会生成 `backup\b1-guard.meta`，这是时间差而非故障。
- `b1-guard.meta` 由 SYSTEM 计划任务写入，非提权会话写不进去属 ACL 设计内，不算失败。

## 5. 构建与发版链路

```
scripts/*.ps1 ─┐
               ├─> gui/build.ps1 ─> (ASCII + AST 门禁) ─> tests/*.ps1 回归 ─> gui/obj/payload.zip
gui/*         ─┘                                                              │
                                                                              ├─> dist/AI-Net-Guard.exe (+ .sha256)
                                                                              ├─> dist/AI-Net-Guard-portable.zip
                                                                              └─> dist/Emergency-Rescue.bat

git tag v5.8.x ─> .github/workflows/release-exe.yml ─> GitHub Release（自动生成英文 body）
                                                        └─> 用 docs/releases/v5.8.x.md 整体覆写为中文说明
```

- 本地 exe 与 CI exe 的 SHA-256 **必然不同**（.NET 编译非确定性）；以 Release 资产里那份 `.sha256` 与 API digest 一致为准。
- `build.ps1` 把 HEAD 写进 `ProductVersion`，所以**提交之后要再构建一次**，让本地产物与 commit 对应。
- 版本号是纯展示串，散落在 `scripts/*.ps1` 头部、GUI 5 个文件、`CURRENT-IMPLEMENTATION.md`；仓库内没有版本号解析逻辑。改版本时不要把文档里的历史章节标题一起替换。

## 6. 清理边界（重要）

`scratch/` 与 `backup/` 中的文件**不因"整理仓库"而删除**：它们包含历次实验脚本、ACL/数据库备份、隔离探针原始输出等不可再生证据，且全部已被 `.gitignore` 排除，对仓库结构没有任何影响。

如需清理，必须单独走「列清单 → 逐项确认 → 备份 → 小批量移动/回收站」流程；本仓库的交付物是结构说明与索引，不是删文件。

## 7. 版本历史入口

| 文件 | 内容 |
| :--- | :--- |
| [`docs/releases/v5.7.3.md`](releases/v5.7.3.md) | v5.7.3 发布说明 |
| [`docs/releases/v5.8.0.md`](releases/v5.8.0.md) | v5.8.0 发布说明 |
| [`docs/releases/v5.8.1.md`](releases/v5.8.1.md) | v5.8.1 发布说明 |
| [`docs/releases/v5.8.2.md`](releases/v5.8.2.md) | v5.8.2 发布说明（含 `PASSED WITH CAVEAT` 三条披露与 B1 隔离归因测试） |
| [`docs/releases/v5.8.3.md`](releases/v5.8.3.md) | v5.8.3 发布说明（B1 漂移检测、端口单一定义、构建门禁） |
| [`docs/releases/v5.8.4.md`](releases/v5.8.4.md) | v5.8.4 发布说明（第三方 review 复核与修复、B1 纳入全量体检、UTF-8 无 BOM 缓存、卸载闭环、门禁 19 项） |
| [`docs/releases/v5.8.5.md`](releases/v5.8.5.md) | v5.8.5 发布说明（SKIP 归因修正、`protocol` 判定补全、路径兜底对齐、门禁 21 项、发布收尾） |
| [`docs/releases/v5.8.6.md`](releases/v5.8.6.md) | v5.8.6 发布说明（GUI 跳过项三态归因、`ip` fall-through 与 `attrs` 判定、去除绝对化健康结论、门禁 24 项） |
| [`docs/releases/v5.8.7.md`](releases/v5.8.7.md) | v5.8.7 发布说明（ActiveStore `/32` 防污染、`sing-box` B1 适配、物理网卡 IPv6 显式阻断、门禁 33 项） |
| [`docs/releases/v5.8.8.md`](releases/v5.8.8.md) | v5.8.8 发布说明（`/32` 路由与嵌套数组自愈修复、RFC 5389 STUN、WFP 5157 与 ActiveStore 回读、门禁 39 项） |
| [`docs/releases/v5.8.9.md`](releases/v5.8.9.md) | v5.8.9 发布说明（ACL/回滚/退出码 P0 安全加固、Fail-Closed 策略与写锁、10 IPv6 联动、门禁 45 项） |
| [`docs/releases/v5.9.0.md`](releases/v5.9.0.md) | v5.9.0 发布说明（轻量安全收口：全入口 ACL/Global 锁前置、策略/回滚 Fail-Closed、GUI 哈希增量同步、Protected 持久化、真实双进程互斥门禁） |
| [`docs/releases/v5.9.1.md`](releases/v5.9.1.md) | v5.9.1 稳定维护版发布说明（Protected 不跳过自修复、策略事务回滚、参数作用域修复、自动回滚防自杀与顺序保护，进入维护模式） |
| [`docs/releases/v5.9.2.md`](releases/v5.9.2.md) | v5.9.2 冻结封版发布说明（显式 `PolicyCommitted` 事务、锁定重读保留 `V2rayNRoot`、`06-boot-guard` 退出码传播、54 项门禁含真实异常路径实测，正式冻结） |
| [`docs/releases/v5.9.3.md`](releases/v5.9.3.md) | v5.9.3 维护修复发布说明（PS 5.1 `auto-disabled-outbound-allow.json` 嵌套数组自愈、`scripts\` 默认 `$Root` 与 Check 7 守卫、58 项门禁） |
| [`docs/releases/v5.9.4.md`](releases/v5.9.4.md) | v5.9.4 热修发布说明（PowerShell 7.x `MutexAcl::Create` 写锁兼容、PS 5.1 & PS 7.7 双引擎 59/59 门禁通过） |
| [`docs/releases/v5.9.5.md`](releases/v5.9.5.md) | v5.9.5 脱敏发布说明（基于脱敏基线重构 `AI-Net-Guard.exe` 与 `portable.zip`，第 60 条防 PII 门禁与双引擎 60/60 通过） |
| [`docs/releases/v5.9.6.md`](releases/v5.9.6.md) | v5.9.6 发布说明（新增 `-IncludeAllNodes` 候选节点按需测速伴生白名单与 `62/62` 双引擎门禁） |
| [`docs/releases/v5.9.7.md`](releases/v5.9.7.md) | v5.9.7 发布说明（新增 `-TemporaryIpv6 On|Off` 临时 IPv6 开关与 `/128` 节点同步、PS 7 闭包与 `sing-tun` 误报修复、Hysteria2 `ProtoExtra.Ports` 解析，双引擎 72/72 门禁） |

`dist/release-notes-v*.md` 是同样内容的工作副本，发版前需核对两者哈希一致；**以 `docs/releases/` 为权威来源**。
