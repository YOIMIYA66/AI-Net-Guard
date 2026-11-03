# AI-Net-Guard 实现方案与持续审查文档（v5.6 · 纯内核静态防线 + 零常驻 + 多内核免维护防漂移）

> 运行环境：Windows 11 24H2（PowerShell 5.1 & PowerShell 7.x 双引擎兼容）
> 代理环境：v2rayN 7.x / Xray + sing-box + Mihomo（自动探测 v2rayN 安装路径或通过 `$env:V2RAYN_ROOT` / `-V2rayNRoot` 指定）
> 节点同步：**v5.6 默认开启多内核自动同步**（支持 IP / 域名节点、VLESS / Trojan / VMess / Hysteria2 端口跳跃等）
> 版本状态：**v5.6 正式版**（`23/23` 全量回归 `PASS`，`0` 常驻进程，安装目录 ACL 已加固）
> 默认部署目录：`C:\AI-Net-Guard`（内置 `backup\v54-migrated.flag` 零触控自迁移引擎）

---

## 0. 实时状态对照：升级前（v5） vs 本机当前生效态（v5.4）

| 检查项 | 升级前（v5，16:00 快照） | **本机 `C:\AI-Net-Guard` 当前生效态（v5.4）** |
| --- | --- | --- |
| 防火墙三配置默认出站 | `EnableFirewall=1`、`DefaultOutboundAction=Block(1)` | Domain / Private / Public 全部 `Enabled=True`、`DefaultOutbound=Block`（`<1 ms` 注册表快检） ✅ |
| 防火墙现存 `AI-Guard-*` 规则 | 6 条放行 + **残留 `Block-DoT` 1 条** + 伴生规则锁死旧网卡 GUID | **残留 `Block-DoT` 已清除**；7 条静态规则（`Allow-CN` 6516 段 / `Allow-TUN` / `Allow-Node-TCP` / `Allow-DoH-Ali` / `Allow-DHCP` / `Allow-LAN` / `Allow-NCSI`）全部 `Active=True`，支持 USB 热点即插即用与异构 TUN 动态扩展（`Allow-TUN-Alt`） ✅ |
| 第三方越权 `Outbound Allow` 防漂移 | 仅初装时禁用一次，后续新装软件注入的 `Allow` 会穿透防线 | **零开销自动隔离**：单遍注册表扫描顺带检测非 `AI-Guard-*` 活跃出站 `Allow`（当前 `rogue out-allow : 0`），自动禁用并记入 `backup\auto-disabled-outbound-allow.json` 供回滚还原 ✅ |
| 换节点 / 切内核（Xray & sing-box）同步 | 仅支持 Xray 格式且需手动跑脚本；点选 Hysteria2（`sing-box.exe`）会被阻断 | **v5.4 多内核默认自动同步（`auto-sync=on`）**：同时兼容 **Xray** 与 **sing-box**（含 Hysteria2 端口跳跃 `20000:30000 -> 20000-30000`）配置格式，自动绑定当前活跃内核路径（`xray.exe` / `sing-box.exe` / `mihomo.exe`）与异构 TUN 网卡；域名节点优先走 `https://223.5.5.5/resolve` 加密直连解析 ✅ |
| 快速切节点 / 退出软件 / 睡眠唤醒响应 | 无睡眠唤醒触发；`+800 ms` 复查在 `$tunLate == $tunUp` 时跳过 | **v5.4 无盲区收敛**：`AI-Guard-Mode-Event` 订阅 `NetworkProfile 10000/10001` + **S3 睡眠/休眠/现代待机（Modern Standby `S0ix`）唤醒事件**（`Power-Troubleshooter 1` / `Kernel-Power 107, 507`）；`+800 ms` 后无条件以 `<0.5 ms` 复核节点同步与残留死代理清理 ✅ |
| DNS 防泄漏与内核减噪 | 仅禁 LLMNR/NetBIOS，未禁 Windows 智能多宿主并行 DNS（SMHNR） | **`LLMNR=off` + `SMHNR=off`（`DisableSmartNameResolution=1`）**：实测 `pktmon` 53 端口抓包物理网卡并行试探从 `4~5` 次降至 **`phys_attempts=0, escaped=0`**（回滚时原样还原） ✅ |
| 后台常驻进程与周期巡检 | **常驻 `powershell.exe` 占 160.6 MB 提交内存** + 每 5 分钟重型 WMI 刷空 DNS 缓存 | **`resident process : none`（0 常驻进程 / 0 MB 空闲内存 / 0% 空闲 CPU）**；60 分钟兜底任务走 0 CIM 纯注册表/.NET 快路径（不乱清 DNS 缓存） ✅ |
| 日志与临时抓包磁盘占用 | 每次回归/WFP 审计遗留 **8.7 MB** `filters.xml`，单日堆积 **47.2 MB** | **v5.4 零膨胀自动清理**：已清理历史 **47.2 MB** 临时 `wfp-*`/`dns-*` 转储；测试 `PASS` 后自动删除当次 XML/ETL 临时目录（仅 `FAIL` 或 `-KeepCaptures` 时保留现场），报告自动保留最近 10 份 ✅ |
| 安装目录权限（SYSTEM 任务执行的脚本与白名单） | `C:\AI-Net-Guard` 继承 C 盘根 `Authenticated Users:(M)`，普通进程可改写脚本 → 提权 SYSTEM / 静默拆除防线 | **已通过 [`13-harden-acl.ps1`](./13-harden-acl.ps1) 锁定生效（`issues -> 0`）**：`owner=Administrators`，`Administrators/SYSTEM=Full`，`Users=RX`（原 ACL 自动备份至 `backup\acl-before-<ts>.txt`） ✅ |
| 全量自动化回归测试（`12-regression.ps1`） | 旧脚本含硬编码 IP 与系统代理干扰 | **实测 `23/23 PASS (FAIL=0)`**（`Proxy=$null` 纯内核直连探测 + 越权 Allow 零漂移断言 + 目录 ACL 锁定断言 + 损坏 `geoip` 演练拦截） ✅ |

---

## 1. 性能与后台常驻脚本影响深度评估

### 1.1 内核数据面（日常上网、游戏、下载、IDE 编译）：**几乎零损耗（~0%）**
- **6516 条 `AI-Guard-Allow-CN` 规则在 Windows 内核 `tcpip.sys`（WFP）中执行**，且受有状态流缓存（Stateful ALE Flow Cache）加速：**仅在每个新连接的首个握手包匹配一次（`< 0.01 ms`）**，后续数据包 `O(1)` 线速转发。
- **结论**：不占后台 CPU、不影响带宽吞吐、不增加游戏/语音 Ping 值；即使后台 0 个 PowerShell 进程运行，防泄漏能力依然 **100% 生效**。

### 1.2 后台脚本控制面：v5.2 ~ v5.4 零常驻事件驱动架构

| 维度 | v5（旧常驻轮询版） | **v5.4（零常驻 + 多内核防漂移版）** |
| --- | --- | --- |
| 常驻 `powershell.exe` 数量 | 1 个（24 小时不退出） | **0 个** |
| 日常空闲内存 / CPU 唤醒 | 160.6 MB 提交内存 / 86,400 次唤醒/天 | **0 MB / 0 次唤醒/天** |
| 网络切换 / 换节点 / 盒盖唤醒 | 轮询记日志 | 原生双通道 `EventTrigger`（`NetworkProfile 10000/10001` + `System` 睡眠/现代待机唤醒 `1/107/507`）静默在 Session 0 低优先级执行：洗污染 DNS 缓存、多内核节点自动同步、新网卡禁 IPv6、清理死本地代理，跑完即退出 |
| 60 分钟兜底防漂移巡检 | 每 5 分钟跑重型 WMI（~5 s）+ 清 DNS 缓存 | **每 60 分钟**跑一次 **0 CIM 快路径**（~160 ms 跑完即退，顺带隔离第三方越权出站 `Allow` 并校验 SMHNR / IPv4 优先级） |

---

## 2. 目标与架构原理（v5.6）

```mermaid
flowchart TD
    subgraph AppLayer["用户与应用层 (Applications)"]
        Apps["AI 编程工具 / 浏览器 / 终端 CLI<br/>(Claude Code, Codex, Cursor, Python, Git)"]
        DNSGetAddr["系统寻址 getaddrinfo<br/>IPv4 优先级 50 > 40<br/>SMHNR=OFF (禁用物理网卡并行 DNS 试探)"]
        Apps --> DNSGetAddr
    end

    DNSGetAddr --> Decision{"当前 TUN 虚拟网卡状态"}

    subgraph TunOnPath["状态 A：代理开启 (TUN Mode ON)"]
        direction TB
        TunRoute["0.0.0.0/0 默认路由导入虚拟网卡<br/>(xray_tun / singbox_tun)"]
        CoreSniff["代理内核 L3 捕获 & 53 端口劫持<br/>(Xray / sing-box / Mihomo)"]
        DnsSplit{"DNS 分流解析"}
        DomesticDns["国内域名 (geosite:cn)<br/>直连阿里 DoH 223.5.5.5"]
        ForeignDns["国外 / AI 域名<br/>加密走节点代理至 Cloudflare DoH"]
        NodeEgress["授权内核出站 -> 落地节点<br/>命中 AI-Guard-Allow-Node-*<br/>(例如 203.0.113.10:443)"]

        TunRoute --> CoreSniff
        CoreSniff --> DnsSplit
        DnsSplit -->|国内流量| DomesticDns
        DnsSplit -->|海外 / AI 流量| ForeignDns
        ForeignDns --> NodeEgress
        DomesticDns --> DirectEgress["物理网卡直接出站<br/>(命中 AI-Guard-Allow-CN)"]
    end

    subgraph TunOffPath["状态 B：代理断开 / 内核崩溃 (TUN Mode OFF - 0 ms 熔断)"]
        direction TB
        NoTunRoute["无虚拟网卡路由 -> 流量落入物理网卡 (WLAN)"]
        KernelWFP["Windows 内核防火墙 (tcpip.sys / WFP ALE)<br/>默认出站策略: BLOCK (丢弃)"]
        
        CnCheck{"目标 IP 匹配规则"}
        AllowCN["大陆 IPv4 (6,516 前缀归一聚合)<br/>+ 223.5.5.5 / 国内 NTP<br/>命中 AI-Guard-Allow-CN"]
        AllowLAN["局域网子网 / DHCP / NCSI 80<br/>命中 Companion Rules"]
        BlockForeign["所有海外公网 IP & 境外 AI 接口<br/>(OpenAI, Claude, Google, 海外 CDN)"]
        
        NoTunRoute --> KernelWFP
        KernelWFP --> CnCheck
        CnCheck -->|国内 IP / 阿里 DNS| AllowCN
        CnCheck -->|局域网设备| AllowLAN
        CnCheck -->|境外 IP / AI API| BlockForeign
        
        AllowCN --> PassOut["放行出站 (O(1) 硬件级线速转发)"]
        AllowLAN --> PassOut
        BlockForeign --> DropOut["内核硬阻断 (0 ms 丢弃 / 零泄漏)"]
    end

    Decision -->|TUN 在线| TunRoute
    Decision -->|TUN 离线| NoTunRoute
```

> **为什么不在物理网卡 `WLAN` 上开启 Windows 11 原生系统级 DoH？**
> 经链路验证，若在物理网卡开启系统级 DoH，Windows `Dnscache` 会把所有 DNS 查询封装进发往 `223.5.5.5:443` 的加密 TLS 流；当 TUN 开启时，代理内核无法在 53 端口嗅探劫持该 TLS 流，并会按国内 IP 规则将其直连发给阿里 DNS——导致开代理时你的境外 AI 域名查询反而全部泄漏给阿里 DNS 并拿到污染/非最优 CDN。保持当前**网卡 `223.5.5.5`（53 端口供 TUN 劫持分流）+ 禁 SMHNR + 开 TUN 自动刷缓存**是最优组合。

---

## 3. 部署组件清单

### 3.1 防火墙规则（静态，`Name` = `DisplayName`）

| 规则名 | 方向/动作 | 作用域与设计说明 |
| --- | --- | --- |
| （三配置默认策略） | 出站 **Block** | Domain / Private / Public 全部启用且默认拒绝出站 |
| `AI-Guard-Allow-CN` | 出站/允许 | 6516 个中国大陆 IPv4 前缀（主机位归一化、数值排序、相邻/重叠无损聚合） |
| `AI-Guard-Allow-TUN`（及按需 `-TUN-Alt`） | 出站/允许 | 匹配 `InterfaceAlias = xray_tun`（若切换至 `sing-box`/`mihomo` 产生异构 TUN 网卡，自动创建/启用 `AI-Guard-Allow-TUN-Alt`） |
| `AI-Guard-Allow-Node-TCP`（及按需 `-UDP`） | 出站/允许 | 当前活跃代理内核（`xray.exe` / `sing-box.exe` / `mihomo.exe`）→ 当前授权节点 IP:端口（**默认随 v2rayN 切节点自动同步**，支持 Hysteria2 端口跳跃与 `h3`/QUIC UDP） |
| `AI-Guard-Allow-DoH-Ali` | 出站/允许 | 当前活跃代理内核 → `223.5.5.5, 223.6.6.6 : 443` |
| `AI-Guard-Allow-DHCP` | 出站/允许 | UDP `68 → 67`（`LocalSubnet, 255.255.255.255`） |
| `AI-Guard-Allow-LAN` | 出站/允许 | `LocalSubnet` |
| `AI-Guard-Allow-NCSI` | 出站/允许 | TCP → `13.107.4.52:80`（仅微软 `connecttest.txt` 明文 HTTP 80 连通性探测） |

### 3.2 计划任务（零常驻模式）

| 任务名 | 触发条件 | 运行方式与开销 |
| --- | --- | --- |
| `AI-Guard-Mode-Event` | 开机 + `NetworkProfile` `10000/10001` + `System` 睡眠/现代待机唤醒（`Power-Troubleshooter 1` / `Kernel-Power 107, 507`） | `SYSTEM` Session 0 隐藏运行、Priority 7 低优先级；包含 `+800 ms` 无盲区二次确认，跑完即退（0 MB 常驻） |
| `AI-Guard-Mode-Fallback` | 每 60 分钟 | 静默跑一次 `07-mode.ps1 -Mode Auto -Quiet` 零 CIM 快检（~160 ms） |

### 3.3 脚本清单（全部 15 个 `.ps1` 均为 100% 纯 ASCII，兼容 PowerShell 5.1 / 7.x）

| 文件 | 作用 |
| --- | --- |
| [`00-audit.ps1`](./00-audit.ps1) | 只读全面审计（网卡/路由/DNS/IPv6 前缀表/NTP/防火墙/代理配置） |
| [`01-dns-hardening.ps1`](./01-dns-hardening.ps1) | 初始 DNS（`223.5.5.5`）+ 禁物理网卡 IPv6 + IPv4 优先策略 + 禁 LLMNR/NetBIOS/SMHNR + 国内 NTP |
| [`02-killswitch.ps1`](./02-killswitch.ps1) | 初始备份 + 禁用原出站 Allow + 安装 v5.4 静态规则集（预写全部 `.meta`/`.flag`）+ 45 分钟自动回滚保险 |
| [`03-verify.ps1`](./03-verify.ps1) | 配置与功能验收（多内核感知、`Proxy=$null` 直测真实内核数据面、自动清理临时 WFP 转储） |
| [`04-wfp-audit.ps1`](./04-wfp-audit.ps1) | WFP 过滤器审计 + 可选 `pktmon` 53 端口抓包（默认输出结论后自动清理 8.7 MB 临时 XML，传 `-KeepCaptures` 可保留） |
| [`05-xray-direct-test.ps1`](./05-xray-direct-test.ps1) | 行为侧观测 `xray.exe` 在绕过大陆路由下的 direct 直连豁免 |
| [`06-boot-guard.ps1`](./06-boot-guard.ps1) | 重启演练跨重启自毁回滚安全网（隐藏运行） |
| [`07-mode.ps1`](./07-mode.ps1) | **核心入口：零常驻守护、多内核自动节点同步、越权 Allow 自动隔离、SMHNR 加固、死代理自愈** |
| [`08-commit.ps1`](./08-commit.ps1) | 复查多内核不变量后取消测试回滚定时器，并安装 v5.4 事件任务 |
| [`09-rollback.ps1`](./09-rollback.ps1) | **完整闭环回滚**（停任务/进程 → 还原防火墙及自动隔离规则 → 还原 DNS/IPv6/前缀表/NTP/LLMNR/SMHNR → 清理全部标记） |
| [`10-sync-node-rule.ps1`](./10-sync-node-rule.ps1) | 多内核节点同步/预览工具（支持 Xray + `sing-box`/Hysteria2 端口跳跃，`-WhatIfOnly` 免提权预览） |
| [`11-geo-cn.ps1`](./11-geo-cn.ps1) | 零分配预扫描 v2rayN `geoip` 数据库，归一化并无损聚合生成 [`cn-ipv4.txt`](./cn-ipv4.txt) |
| [`12-regression.ps1`](./12-regression.ps1) | **v5.4 全量 22 项自动化回归套件**（`PASS` 后自动清理 8.7 MB WFP XML 与 `pktmon` ETL 临时文件，保留最近 10 份报告） |
| [`13-harden-acl.ps1`](./13-harden-acl.ps1) | **O1/O2 一键落地**：备份原 ACL → 所有者改 Administrators → DACL 收紧为 Admin/SYSTEM=F、Users=RX → 校验无非管理员写权限 → 以子进程跑 `07-mode.ps1`（完成 v5.4 热迁移）与 `12-regression.ps1` 并核对迁移结果；`-Undo` 恢复继承 |
| [`watchdog.ps1`](./watchdog.ps1) | 可选的 CLR 事件驱动常驻监听脚本（默认不启用，已支持多内核 TUN 识别与 PS7 伪接口过滤） |

---

## 4. 代码审查与演进修复记录（v5 → v5.1 → v5.2 → v5.3 → v5.4）

| 编号 | 审查发现的问题 | 修复版本与措施 |
| --- | --- | --- |
| R1 ~ R8 | 回滚漏停任务、无条件刷 DNS 缓存、关 TUN 期污染缓存延续、IPv6 AAAA 超时、热插拔网卡锁死、VLESS `vnext` 与残留 `Block-DoT` | **v5.1**：闭环回滚、按需刷 DNS、TUN 上线清缓存、`::ffff:0:0/96` 优先级 `50>40`、解锁伴生规则 `InterfaceAlias->Any`、清理残留规则 |
| R9 ~ R11 | 常驻 `watchdog.ps1` 占 160.6 MB 内存 + 每秒唤醒；Xray `h3` UDP 识别；PS 7.6.9 枚举 20 个 NDIS 轻量级过滤层伪接口 | **v5.2**：切换为 **0 常驻进程** `NetworkProfile` 事件任务 + 60 分钟 0-CIM 快检；补齐 `h3` UDP 识别与 `Supports(IPv4/IPv6)` 真实网卡过滤 |
| R12 ~ R17 | 第三方新装软件越权 `Outbound Allow` 漂移；手动同步节点繁琐；v2rayN 崩溃残留死代理假断网；探测受系统代理与 `MethodInvocationException` / 站点 WAF 影响；根目录历史临时文件 | **v5.3**：单遍注册表 +0 ms 自动隔离越权 `Allow`；默认开启自动节点同步（域名节点优先 `https://223.5.5.5/resolve`）；跨会话死代理自动清零；`Proxy=$null` + `InnerException` 解包回归全通过；历史临时文件自动归档 |
| R18 | `12-regression.ps1` / `03-verify.ps1` / `04-wfp-audit.ps1` 每次运行遗留 ~8.7 MB `filters.xml` 与 `dns.etl`，单日堆积 **47.2 MB** | **v5.4**：已清理历史 **47.2 MB** 临时抓包目录；测试 `PASS` 后自动删除当次临时 XML/ETL（仅 `FAIL` 或 `-KeepCaptures` 时保留现场），报告自动修剪保留最近 10 份 |
| R19 | `07-mode.ps1 -OnNetworkEvent` 的 `+800 ms` 复查仅在 `$tunLate -ne $tunUp` 时才执行二次节点同步与死代理清理；且未订阅盒盖睡眠/现代待机唤醒事件 | **v5.4**：`+800 ms` 后无条件以 `<0.5 ms` 复核 `config.json` 时间戳与死代理状态（消除快速切节点及退出 v2rayN 慢半拍盲区）；`AI-Guard-Mode-Event` 新增 `System` 通道 `Power-Troubleshooter 1` / `Kernel-Power 107, 507` 唤醒触发（0 MB 常驻） |
| R20 | Windows 智能多宿主名称解析（SMHNR）默认开启，双网卡在线时向物理网卡并行广播 DNS（回归抓包 `phys_attempts=5`），切节点瞬间存在窗口 | **v5.4**：新增 `DisableSmartNameResolution=1` 加固与自愈（自动回填原始值至 `dns-*.json` 并在 `09-rollback.ps1` 完整还原）；通过 `backup\v54-migrated.flag` 在后台首次触发时自动完成热迁移 |
| R21 | 本机 v2rayN `guiNConfig.json` 将 `Hysteria2`（`ConfigType=7`）映射到 `sing-box.exe`（`CoreType=24`），原规则与解析器仅兼容 `xray.exe` / `xray_tun` | **v5.4**：[`07-mode.ps1`](./07-mode.ps1) 与 [`10-sync-node-rule.ps1`](./10-sync-node-rule.ps1) 同时兼容解析 Xray 与 `sing-box`（含 Hysteria2 端口跳跃 `server_ports`）配置，自动切换绑定活跃内核路径（`xray.exe` / `sing-box.exe` / `mihomo.exe`）并动态放行异构 TUN 接口（`AI-Guard-Allow-TUN-Alt`） |
| R22 | 安装目录继承 `Authenticated Users:(M)`，且部分文件所有者为普通用户（所有者隐含 `WRITE_DAC`，可自行改回权限）；SYSTEM 任务执行其中脚本并读取 `cn-ipv4.txt` 构建白名单 | **v5.4**：新增 [`13-harden-acl.ps1`](./13-harden-acl.ps1)（用 SID 调用 `icacls`，兼容中文系统组名）；`07-mode.ps1 -Status` 新增 `install ACL` 行，回归套件新增「安装目录已锁定」断言（使用 .NET ACL API，不依赖可能无法自动加载的 `Get-Acl`） |
| R23 | `Show-Status` 用 `@(...)` 包裹 `return ,$array` 型函数，结果 `Count` 恒为 1：**TUN 关闭时仍显示 `Up`**，内核停止时仍判定为运行中，导致「死代理」红色告警永远不会出现 | **v5.4**：改为直接赋值（已用模拟 TUN 关闭验证：`Count 1 -> 0`）；新函数统一不带逗号返回 |
| R24 | O2 首次提权运行捕获：PowerShell 注册表提供程序中对已存在的键执行 `New-Item -Path $polKey -Force` 会**重建该键并清空同键下的既有值**，导致写入 `DisableSmartNameResolution=1` 时把同键的 `EnableMulticast=0`（禁 LLMNR）抹除 | **v5.4**：[`07-mode.ps1`](./07-mode.ps1) 与 [`01-dns-hardening.ps1`](./01-dns-hardening.ps1) 中所有注册表建键统一加 `if (-not (Test-Path -LiteralPath ...))` 保护，并在 `Set-SmhnrHardening` / `Ensure-Guard` 中同时守护自愈 `EnableMulticast=0` 与 `DisableSmartNameResolution=1` |
| R25 | Windows 11 24H2 下 Wintun 未分配单播 IPv6 地址时，调用底层 `SetInterfaceDnsSettings` 触发系统 Win32 错误码 `5` (`Access is denied`) 导致 Xray 原生单核心 TUN 崩溃回滚 | **v5.6**：在 Xray 源码引入无侵入精准前置守卫：以协议族是否拥有合法单播 IP 作为下发 DNS 的绝对凭据，完美兼容纯 IPv4/IPv6、双栈与空 DNS 清空语义；输出产物已在生产环境稳定运行 |
| R26 | 原防漂移逻辑盲目信任以 `AI-Guard-*` 开头的规则名，导致第三方或历史运维脚本注入的无约束全放行规则（如 `netsh ... interfacetype=any`）绕过隔离，架空默认 Block 策略 | **v5.6**：[`07-mode.ps1`](./07-mode.ps1) 强化防冒名与 Blanket Allow 识别：凡是出站 Allow 规则缺少 `RA4/RA6`（远程 IP）、`IF`（网卡接口）与 `App`（进程）三重限定的，一律判定为高危违规并自动隔离入 `backup\auto-disabled-outbound-allow.json` |
| R27 | `Get-NetFirewallInterfaceFilter.InterfaceAlias` 从系统读回网卡 GUID 列表，与传入的别名 `$activeTun = 'xray_tun'` 发生比对歧义，导致每次网络事件唤醒均判定未授权而重复写入 `AI-Guard-Allow-TUN-Alt` 并堆积过期 GUID 和 `'0'` | **v5.6**：新增 [`Test-FirewallRuleHasTun`](./07-mode.ps1) 辅助函数，实现别名与适配器底层 GUID 双向解析比对，彻底消除冗余写入、日志刷屏与 `'0'` 占位符残留 |
| R28 | `07-mode.ps1 -Status` 因前置管理员提权断言，导致非管理员终端（普通 CMD、PowerShell、VSCode/Cursor 内置终端）无法直接执行轻量级状态查看 | **v5.6**：优化提权分支：非管理员请求 `-Status` 时进入 `$script:ReadOnlyStatusMode` 快检通道，免提权展示当前 15 项防护状态看板 |

---

## 5. 日常维护与配合说明

1. **v2rayN 系统代理建议**：若希望**仅凭开关 TUN 就 100% 控制浏览器能否访问境外 AI**，请在 v2rayN 主界面底部将系统代理设为**「清除系统代理」**（否则只关 TUN 而不退出 v2rayN 时，浏览器仍会走 `127.0.0.1:10808 -> xray.exe` 出站）。
2. **v5.4 热同步自迁移机制**：所有 v5.4 脚本已热同步至 `C:\AI-Net-Guard\`。当你下次开关 TUN/Wi-Fi、睡眠唤醒、到达每小时巡检点，或手动执行一次 `.\07-mode.ps1` 时，`SYSTEM` 会自动执行一次性 `v54-migrated.flag` 热迁移（写入 `DisableSmartNameResolution=1` 并为计划任务加上睡眠唤醒触发器）。

```powershell
# 管理员 PowerShell 常用命令（平时零维护，按需查看）
cd C:\AI-Net-Guard
.\07-mode.ps1                    # （可选）立即触发一次自检与 v5.4 注册表/睡眠唤醒任务热迁移，并打印状态
.\07-mode.ps1 -Status            # 只读查看 v5.4 状态（含 core、auto-sync=on、LLMNR/SMHNR、越权 Allow=0、0 常驻进程）
.\12-regression.ps1              # 运行 v5.4 全量 22 项回归测试（PASS 后自动清理临时抓包文件）
.\10-sync-node-rule.ps1 -WhatIfOnly  # 免提权预览当前 Xray / sing-box 节点与端口解析结果
.\09-rollback.ps1                # 彻底回滚到安装前原始基线状态
.\13-harden-acl.ps1              # 锁定安装目录权限 + 跑一次 v5.4 提权自检与回归（-Undo 可撤销）
```

3. **ACL 锁定后的更新方式**：`C:\AI-Net-Guard` 锁定后仅管理员可写，以后若工作区有更新，只需在**管理员终端**执行短命令 `.\13-harden-acl.ps1 -SyncWorkspace`（会自动同步文件、重新校验/锁定 ACL 并完成自检），无需再手敲长路径 `Copy-Item`。

---

## 6. 已知能力边界与待办

### 6.1 能力边界
1. **关代理时所有非中国大陆 IP 均被阻断**（不只 AI）：GitHub / Google / Steam / 海外 CDN 在关 TUN 时同样不可达（符合默认拒绝设计）。
2. **境内 IP 托管的 AI 中转服务无法靠 GeoIP 拦截**。
3. **TUN 开启期间 `xray.exe` 自身具有 WFP `permit Xray` hard permit**：Windows 防火墙在 TUN 运行期管住的是除 `xray.exe` 以外的所有进程（`sing-box` 无此豁免，直接受 `AI-Guard-Allow-Node-*` 精确约束）。
4. **公共 Wi-Fi 门户登录（Captive Portal）**：若酒店/机场门户使用非国内公网 IP 或依赖私有 DHCP DNS，登录门户前可临时切回自动 DNS。

### 6.2 演进完成度清单
- [x] 原地升级至 **v5.2 零常驻事件驱动架构**（释放 160.6 MB 常驻提交内存）并修复 PS 7.x 伪接口过滤（R11）；
- [x] 升级至 **v5.3 免维护防漂移版**（默认自动换节点同步、第三方越权 `Outbound Allow` 零开销隔离、死本地代理自愈）；
- [x] 升级至 **v5.4 多内核与细节完备版**（临时抓包目录自动清理、消除 `+800 ms` 切节点/退软件盲区、新增 S3/Modern-Standby 睡眠唤醒触发、禁用 SMHNR 并行 DNS、兼容 `Xray` + `sing-box`/Hysteria2 多内核）；
- [x] **锁定 `C:\AI-Net-Guard` 目录与所有者 ACL（O1）** + **R24 注册表建键保护与 `23/23 PASS` 闭环确认（O2）**；
- [ ] （可选）在 v2rayN 底部状态栏将系统代理设为**「清除系统代理」**，实现纯 TUN 单开关总控；
- [ ] （可选）**重启演练**：`.\06-boot-guard.ps1 -Arm -WindowMinutes 30 -WaitMinutes 10` → 重启系统 → 验证不开代理国内正常/境外阻断、开 TUN 后国外恢复且后台无常驻 `powershell.exe` → `.\06-boot-guard.ps1 -Remove`。

## 7. 安全审查结论（v5.4）

**结论：功能与权限面已收敛，冻结在 v5.4。**

| # | 事项 | 严重度 | 状态 |
|---|------|--------|------|
| O1 | `C:\AI-Net-Guard` 默认继承 C 盘根目录的 `Authenticated Users:(M)`，而 `AI-Guard-Mode-Event` / `-Fallback` 以 **SYSTEM** 运行其中的 `07-mode.ps1`。若不锁权，非管理员进程可改写脚本以提权或静默拆除防护。 | **高** | **已解决（[`13-harden-acl.ps1`](./13-harden-acl.ps1)）** |
| O2 | v5.4 提权自迁移与全量回归验证（`v54-migrated.flag`、`SMHNR=off` `phys_attempts=0`、睡眠唤醒触发器 XML、R24 注册表同键保留修复）。 | 中 | **已解决（`23/23 PASS`）** |
| O3 | 用户态安装的 `<v2rayN>\bin\xray\xray.exe` 与 `geoip*.dat` 通常为普通用户可写，而 `AI-Guard-Allow-Node-TCP` / `DoH-Ali` 按程序路径放行。 | 低 | 设计取舍（若锁死 v2rayN 目录会破坏客户端自动更新内核与 GeoIP；高安全场景可将 v2rayN 迁入 `C:\Program Files\v2rayN`） |

O1 + O2 一键执行（管理员 PowerShell）：

```powershell
cd C:\AI-Net-Guard
.\13-harden-acl.ps1
```

> [!NOTE]
> Windows 中对象所有者（Owner）隐含 `WRITE_DAC` 权限，若不把所有者一并改为 `Administrators`，原普通用户所有者仍可把写权限重新赋回给自己。[`13-harden-acl.ps1`](./13-harden-acl.ps1) 会同时执行 `/setowner *S-1-5-32-544 /T` 并使用 `.NET` ACL API 逐项校验。

锁定后更新代码的方式：在管理员终端从仓库目录执行 `C:\AI-Net-Guard\13-harden-acl.ps1 -SyncWorkspace`（或传 `-WorkspaceRoot <仓库路径>`）。

---

## 8. v5.5 升级：Windows 原生 GUI 桌面配置器与单文件 `.exe` 发布架构

v5.5 在底层 WFP 静态防护与零驻留自愈内核之上，引入了**纯 Windows 原生、零外部依赖的桌面 GUI 配置器**：

1. **单文件独立执行 (`dist\AI-Net-Guard.exe`)**：
   - 基于 Windows 10/11 系统自带的 `.NET Framework 4.8 (net48)` WPF 引擎编译，产物体积仅 **~235 KB**，无需用户额外安装任何运行时；
   - 内置 UAC 清单（`requireAdministrator`）与 `PerMonitorV2` 4K 高分屏感知；
   - 内嵌高压缩 `payload.zip`（内含全部 16 个核心脚本、`cn-ipv4.txt` 及文档），下载单个 `.exe` 双击即可自动释放自愈并执行部署，免去 git clone 或命令行操作门槛。
2. **4 大模块 15 项开关双向持久化策略引擎 (`guard-policy.json`)**：
   - 界面直观呈现 15 项开关，每项均标有 **`[推荐开启]`** 或 **`[高级可选]`** 及通俗白话解释；
   - 提供 **3 套一键预设**（推荐日常防泄漏、严格全局铁桶锁、开发者兼容模式）；
   - 引入 [`14-apply-policy.ps1`](./14-apply-policy.ps1) 幂等编排引擎：不仅首次部署全自动完成基线备份、规则建立、连通性快速探测与提交，且在已部署状态下修改任意单项开关时，支持秒级增量切换而绝不污染原始基线；
   - [`07-mode.ps1`](./07-mode.ps1) 与 [`12-regression.ps1`](./12-regression.ps1) 严格读取并遵循用户在 GUI 中配置的策略，确保后台自愈与体检断言与用户意图 100% 一致。
3. **桌面一键运维与安全防篡改**：
   - 顶部提供 `v2rayN` 路径自动探测与配置校验徽章；
   - 自动检测并提供 **「一键关闭系统代理」**（`HKCU` WinINET `ProxyEnable=0` + `InternetSetOption` 实时刷新），实现仅通过 `v2rayN` 的「启用 Tun」单开关控制全局分流；
   - 底部集成 **「一键部署」**、**「一键 23 项健康体检」**、**「一键完整卸载回滚」** 及可折叠的实时流式输出控制台。

---

## 9. v5.6 升级：Win11 24H2 原生 Xray TUN 适配、防冒名全放行隔离与智能网卡治理

v5.6 针对近期在 Windows 11 24H2 实测与代码深度审查中捕获的关键痛点进行了架构级升级：

1. **Win11 24H2 下 Xray 原生 TUN `SetDNS: Access is denied` 根因定位与修复**：
   - **根因剖析**：Windows 11 24H2 对未配置单播 IPv6 地址的 Wintun 虚拟接口调用 `SetInterfaceDnsSettings` 时严格校验并返回错误码 `5`。原版 Xray 依赖 `ERROR_NOT_FOUND` 作为跳过条件，但 Win11 24H2 下该 API 穿透返回 `nil`，导致强行设置空 IPv6 DNS 触发致命崩溃。
   - **工程修复**：引入以单播 IP 存在性为守卫的最小补丁，杜绝假成功，确保纯 IPv4、纯 IPv6 及双栈环境均能稳定运行原生单核心 TUN。
2. **防冒名伪装与高危无约束出站 Allow 规则反穿透 (R26)**：
   - 重构了 `Get-FirewallRuleAnalysis` 引擎，引入严密特征识别：任何缺少远端目标 IP (`RA4/RA6`)、作用网卡 (`IF`) 与进程签名 (`App`) 的全放行出站规则，即使名字前缀带有 `AI-Guard-*`，也会被视作伪装/非法规则并自动移入隔离区，彻底杜绝运维误操作或恶意进程架空默认阻断策略。
3. **异构 TUN 规则动态挂载 GUID / 别名智能映射 (R27)**：
   - 引入 [`Test-FirewallRuleHasTun`](./07-mode.ps1) 机制，双向识别网卡友好别名与底层 InterfaceGuid，杜绝因比对失败导致的每次网络事件重复刷新，清除历史残留的 `'0'` 占位符与废弃 Wintun GUID。
4. **免提权只读状态看板与生态协同 (R28)**：
   - `07-mode.ps1 -Status` 支持非提权普通终端即开即查，日常在 VSCode/Cursor 终端中无需 UAC 弹窗即可实时核验 15 项防护状态。
   - 提供了专用的连通性与防泄漏自动化探测脚本，一键验证物理网卡直连阻断与 TUN 代理链路健康。
