# AI-Net-Guard 实现方案与持续审查文档（v5.8.2 · 路由层 STUN 封锁 + 自愈快路径重构 + 显式物理境外硬阻断）

> 运行环境：Windows 11 24H2（PowerShell 5.1 & PowerShell 7.x 双引擎兼容）
> 代理环境：v2rayN 7.x / Xray + sing-box + Mihomo（自动探测 v2rayN 安装路径或通过 `$env:V2RAYN_ROOT` / `-V2rayNRoot` 指定）
> 节点同步：**v5.8.1 默认开启多内核自动同步**（支持 `sing-box` 多出站/hy2 `server_ports` 端口跳跃、双核心 DoH 伴生规则、域名周期刷新与旧 `/32` 路由清理）
> 版本状态：**v5.8.2 正式版**（v5.8.1 全部内容 + 按外部审查修正 `18` 的库写入守卫与 `verify-leak-test` 第 9 段的验收逻辑，详见 16.7）
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
| 安装目录权限（SYSTEM 任务执行的脚本与白名单） | `C:\AI-Net-Guard` 继承 C 盘根 `Authenticated Users:(M)`，普通进程可改写脚本 → 提权 SYSTEM / 静默拆除防线 | **已通过 [`scripts/13-harden-acl.ps1`](./scripts/13-harden-acl.ps1) 锁定生效（`issues -> 0`）**：`owner=Administrators`，`Administrators/SYSTEM=Full`，`Users=RX`（原 ACL 自动备份至 `backup\acl-before-<ts>.txt`） ✅ |
| 全量自动化回归测试（`12-regression.ps1`） | 旧脚本含硬编码 IP 与系统代理干扰 | **实测 `24/24 PASS (FAIL=0)`**（`Proxy=$null` 纯内核直连探测 + 越权 Allow 零漂移断言 + 目录 ACL 锁定断言 + 损坏 `geoip` 演练拦截） ✅ |

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

## 2. 目标与架构原理（v5.7）

```mermaid
flowchart TD
    subgraph APP_LAYER ["💻 用户与应用层 (Applications & AI Tools)"]
        direction TB
        Apps["AI 编程工具 / 浏览器 / 终端 CLI<br/>Claude Code · Cursor · Codex · Python · Git"]:::client
        DNS_Resolver["⚡ 系统寻址与协议优先级决策<br/>IPv4 寻址优先 (权重 50 &gt; 40) · SMHNR=OFF 禁用多网卡抢答"]:::client
        Apps --> DNS_Resolver
    end

    DNS_Resolver --> TUN_STATE{"🔀 虚拟网卡状态判定<br/>TUN Mode ON / OFF"}:::decision

    %% State A: TUN ON
    subgraph TUN_ON ["🟢 状态 A：代理接管 (TUN Mode ON - 加密通道)"]
        direction TB
        TunRoute["🔌 0.0.0.0/0 默认路由接入虚拟网卡<br/>xray_tun / singbox_tun"]:::tunnel
        CoreSniff["🧠 代理内核捕获 &amp; 53 端口流量劫持<br/>Xray / sing-box / Mihomo"]:::tunnel
        DnsSplit{"🌐 域名分流路由<br/>geosite 智能解析"}:::decision
        DomesticDns["🇨🇳 国内域名 (geosite:cn)<br/>直接请求阿里 DoH (223.5.5.5)"]:::allowed
        ForeignDns["🌍 境外 / AI 目标域名<br/>加密走节点代理至远程 DoH"]:::tunnel
        NodeEgress["🚀 物理网卡授权出站 (至落地节点)<br/>放行规则: AI-Guard-Allow-Node-*"]:::allowed
        DirectEgress["⚡ 物理网卡国内直连 (线速转发)<br/>放行规则: AI-Guard-Allow-CN"]:::allowed

        TunRoute --> CoreSniff
        CoreSniff --> DnsSplit
        DnsSplit -->|国内域名| DomesticDns
        DnsSplit -->|海外及AI域名| ForeignDns
        ForeignDns --> NodeEgress
        DomesticDns --> DirectEgress
    end

    %% State B: TUN OFF
    subgraph TUN_OFF ["🔴 状态 B：代理断开 / 内核崩溃 (TUN Mode OFF - 0ms 硬件级熔断)"]
        direction TB
        NoTunRoute["⚠️ 代理离线 / 虚拟网卡注销<br/>流量直接落入物理网卡 (WLAN / Ethernet)"]:::blocked
        KernelWFP["🛡️ Windows 内核防火墙 (tcpip.sys / WFP ALE)<br/>默认出站策略: BLOCK (全局丢弃)"]:::blocked
        CnCheck{"🎯 目标 IP / 子网规则判定"}:::decision
        AllowCN["🇨🇳 大陆 IPv4 (6,516 归一聚合前缀)<br/>放行规则: AI-Guard-Allow-CN"]:::allowed
        AllowLAN["🏠 局域网 / DHCP / NCSI (80)<br/>放行规则: AI-Guard-Allow-LAN"]:::allowed
        BlockForeign["🛑 所有海外公网 IP &amp; 境外 AI 接口<br/>OpenAI · Claude · Google · GitHub · 海外 CDN"]:::blocked
        DropOut["🚫 内核硬阻断 (0 ms 丢弃 / 绝对零泄漏)"]:::dropNode

        NoTunRoute --> KernelWFP
        KernelWFP --> CnCheck
        CnCheck -->|国内 IP / 阿里 DNS| AllowCN
        CnCheck -->|局域网设备| AllowLAN
        CnCheck -->|境外 IP / AI API| BlockForeign
        AllowCN --> PassOut["🟢 放行出站 (O(1) 硬件线速)"]:::allowed
        AllowLAN --> PassOut
        BlockForeign --> DropOut
    end

    TUN_STATE -->|TUN 在线| TunRoute
    TUN_STATE -->|TUN 离线| NoTunRoute

    classDef client fill:#e0f2fe,stroke:#0284c7,stroke-width:2px,color:#0369a1;
    classDef decision fill:#fef3c7,stroke:#f59e0b,stroke-width:2px,color:#92400e;
    classDef tunnel fill:#ede9fe,stroke:#8b5cf6,stroke-width:2px,color:#5b21b6;
    classDef allowed fill:#dcfce7,stroke:#10b981,stroke-width:2px,color:#065f46;
    classDef blocked fill:#fee2e2,stroke:#ef4444,stroke-width:2px,color:#991b1b;
    classDef dropNode fill:#fecaca,stroke:#dc2626,stroke-width:3px,color:#7f1d1d;
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

### 3.3 脚本清单（`scripts/` 下 25 个 `.ps1` 全部为 100% 纯 ASCII，兼容 PowerShell 5.1 / 7.x）

| 文件 | 作用 |
| --- | --- |
| [`scripts/00-audit.ps1`](./scripts/00-audit.ps1) | 只读全面审计（网卡/路由/DNS/IPv6 前缀表/NTP/防火墙/代理配置） |
| [`scripts/01-dns-hardening.ps1`](./scripts/01-dns-hardening.ps1) | 初始 DNS（`223.5.5.5`）+ 禁物理网卡 IPv6 + IPv4 优先策略 + 禁 LLMNR/NetBIOS/SMHNR + 国内 NTP |
| [`scripts/02-killswitch.ps1`](./scripts/02-killswitch.ps1) | 初始备份 + 禁用原出站 Allow + 安装 v5.4 静态规则集（预写全部 `.meta`/`.flag`）+ 45 分钟自动回滚保险 |
| [`scripts/03-verify.ps1`](./scripts/03-verify.ps1) | 配置与功能验收（多内核感知、`Proxy=$null` 直测真实内核数据面、自动清理临时 WFP 转储） |
| [`scripts/04-wfp-audit.ps1`](./scripts/04-wfp-audit.ps1) | WFP 过滤器审计 + 可选 `pktmon` 53 端口抓包（默认输出结论后自动清理 8.7 MB 临时 XML，传 `-KeepCaptures` 可保留） |
| [`scripts/05-xray-direct-test.ps1`](./scripts/05-xray-direct-test.ps1) | 行为侧观测 `xray.exe` 在绕过大陆路由下的 direct 直连豁免 |
| [`scripts/06-boot-guard.ps1`](./scripts/06-boot-guard.ps1) | 重启演练跨重启自毁回滚安全网（隐藏运行） |
| [`scripts/07-mode.ps1`](./scripts/07-mode.ps1) | **核心入口：零常驻守护、多内核自动节点同步、越权 Allow 自动隔离、SMHNR 加固、死代理自愈** |
| [`scripts/08-commit.ps1`](./scripts/08-commit.ps1) | 复查多内核不变量后取消测试回滚定时器，并安装 v5.4 事件任务 |
| [`scripts/09-rollback.ps1`](./scripts/09-rollback.ps1) | **完整闭环回滚**（停任务/进程 → 还原防火墙及自动隔离规则 → 还原 DNS/IPv6/前缀表/NTP/LLMNR/SMHNR → 清理全部标记） |
| [`scripts/10-sync-node-rule.ps1`](./scripts/10-sync-node-rule.ps1) | 多内核节点同步/预览工具（支持 Xray + `sing-box`/Hysteria2 端口跳跃，`-WhatIfOnly` 免提权预览） |
| [`scripts/11-geo-cn.ps1`](./scripts/11-geo-cn.ps1) | 零分配预扫描 v2rayN `geoip` 数据库，归一化并无损聚合生成 [`cn-ipv4.txt`](./cn-ipv4.txt) |
| [`scripts/12-regression.ps1`](./scripts/12-regression.ps1) | **v5.4 全量 22 项自动化回归套件**（`PASS` 后自动清理 8.7 MB WFP XML 与 `pktmon` ETL 临时文件，保留最近 10 份报告） |
| [`scripts/13-harden-acl.ps1`](./scripts/13-harden-acl.ps1) | **O1/O2 一键落地**：备份原 ACL → 所有者改 Administrators → DACL 收紧为 Admin/SYSTEM=F、Users=RX → 校验无非管理员写权限 → 以子进程跑 `07-mode.ps1`（完成 v5.4 热迁移）与 `12-regression.ps1` 并核对迁移结果；`-Undo` 恢复继承；`-SyncWorkspace` 从 Git 克隆目录热同步 `*.ps1` 到生产目录 |
| [`scripts/14-apply-policy.ps1`](./scripts/14-apply-policy.ps1) | 声明式策略编排器：读取 `backup\guard-policy.json` 对本表 16 项特性做增量幂等应用 |
| [`scripts/15-webrtc-browser-shield.ps1`](./scripts/15-webrtc-browser-shield.ps1) | 浏览器级 WebRTC 出口封锁：按 `Program` 维度在物理网卡上封锁全部出站 UDP（覆盖 443 与任意 TURN 端口），只作用于浏览器进程；**并对代理核心 `xray` / `sing-box` / `mihomo` 封锁 STUN/TURN 端口（3478/3479/5349/5350/19302-19309，UDP+TCP）**——TUN 模式下真正从物理网卡出网的是核心，境内 STUN 经 `geoip:cn → direct` 会让 STUN 服务器看到真实 ISP 地址；同时修复原 4 条 WebRTC 规则的 interface / LocalAddress 漂移，`LocalAddress` 改按网段写入 |
| [`scripts/16-browser-residue.ps1`](./scripts/16-browser-residue.ps1) | 已卸载浏览器残留清理（DCBrowser / Firefox）：注册键 + `RegisteredApplications` 值 + 孤儿 `%APPDATA%\Mozilla`，写 JSON 备份后可 `-Restore` 回滚；刻意不动属其它软件的 `MozillaPlugins` / `NativeMessagingHosts` |
| [`scripts/17-autorepair-task.ps1`](./scripts/17-autorepair-task.ps1) | 自愈计划任务管理器：`-Status` 只读体检（状态 / 触发器 / 上次结果 / 下次运行），`-Install` 复用 `07-mode.ps1 -InstallTasks` 注册事件任务与 60 分钟兜底并回读校验，`-Install -SelfTest` 事件任务实跑两次（首次修复 / 二次稳态）+ 兜底任务实跑一次，三条退出码全为 0 才算通过，`-Remove` 清空 `AI-Guard-Mode-*`；未提权时 exit 1 而非静默成功 |
| [`scripts/18-route-stun-guard.ps1`](./scripts/18-route-stun-guard.ps1) | **路由层 STUN/TURN 封锁（WebRTC 防泄露的兜底层）**：实测证明防火墙挡不住核心重发的那一跳（TUN 提供方在 `ALE_AUTH_CONNECT` 用 callout PERMIT 终结分类，防火墙 Block 过滤器不被求值），故改在 xray 路由表顶部插入 `port=3478,3479,5349,5350,19302-19309 → block`（UDP+TCP），照抄 v2rayN 自身「阻断udp443」手法；`-Verify` 只读、`-Apply` 先备份 `guiNDB.db` 再写入、`-Restore` 回滚；v2rayN 运行中拒绝执行（内存副本会覆盖 DB） |
| [`scripts/watchdog.ps1`](./scripts/watchdog.ps1) | 可选的 CLR 事件驱动常驻监听脚本（默认不启用，已支持多内核 TUN 识别与 PS7 伪接口过滤） |
| [`scripts/align-xray-egress.ps1`](./scripts/align-xray-egress.ps1) | 物理出口 socket 对齐工具：消除 `sing-box` TUN 与 Xray 内核之间的内部二跳中继 |
| [`scripts/lib-foreign-block.ps1`](./scripts/lib-foreign-block.ps1) | 共享助手（被 `02` / `07` / `10` / `14` dot-source）：显式物理网卡境外 IPv4 阻断规则的 IP 归一化与增删，用于压制第三方 WFP callout 驱动的 soft-permit |
| [`scripts/verify-leak-test.ps1`](./scripts/verify-leak-test.ps1) | 轻量泄漏与连通性自检四项：越权全放行规则、TUN 适配器状态、物理网卡真实境外探测（`13.107.246.51:443`）、代理/TUN 连通性 |
| [`scripts/disable-telemetry.ps1`](./scripts/disable-telemetry.ps1) | Windows 11 遥测与隐私加固：停用并禁用 `DiagTrack` / `dmwappushservice` 及关联计划任务与策略 |
| [`scripts/restore-telemetry.ps1`](./scripts/restore-telemetry.ps1) | 遥测还原：把服务启动类型与组策略恢复为系统默认，供 `disable-telemetry` 回滚 |

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
| R21 | 本机 v2rayN `guiNConfig.json` 将 `Hysteria2`（`ConfigType=7`）映射到 `sing-box.exe`（`CoreType=24`），原规则与解析器仅兼容 `xray.exe` / `xray_tun` | **v5.4**：[`scripts/07-mode.ps1`](./scripts/07-mode.ps1) 与 [`scripts/10-sync-node-rule.ps1`](./scripts/10-sync-node-rule.ps1) 同时兼容解析 Xray 与 `sing-box`（含 Hysteria2 端口跳跃 `server_ports`）配置，自动切换绑定活跃内核路径（`xray.exe` / `sing-box.exe` / `mihomo.exe`）并动态放行异构 TUN 接口（`AI-Guard-Allow-TUN-Alt`） |
| R22 | 安装目录继承 `Authenticated Users:(M)`，且部分文件所有者为普通用户（所有者隐含 `WRITE_DAC`，可自行改回权限）；SYSTEM 任务执行其中脚本并读取 `cn-ipv4.txt` 构建白名单 | **v5.4**：新增 [`scripts/13-harden-acl.ps1`](./scripts/13-harden-acl.ps1)（用 SID 调用 `icacls`，兼容中文系统组名）；`07-mode.ps1 -Status` 新增 `install ACL` 行，回归套件新增「安装目录已锁定」断言（使用 .NET ACL API，不依赖可能无法自动加载的 `Get-Acl`） |
| R23 | `Show-Status` 用 `@(...)` 包裹 `return ,$array` 型函数，结果 `Count` 恒为 1：**TUN 关闭时仍显示 `Up`**，内核停止时仍判定为运行中，导致「死代理」红色告警永远不会出现 | **v5.4**：改为直接赋值（已用模拟 TUN 关闭验证：`Count 1 -> 0`）；新函数统一不带逗号返回 |
| R24 | O2 首次提权运行捕获：PowerShell 注册表提供程序中对已存在的键执行 `New-Item -Path $polKey -Force` 会**重建该键并清空同键下的既有值**，导致写入 `DisableSmartNameResolution=1` 时把同键的 `EnableMulticast=0`（禁 LLMNR）抹除 | **v5.4**：[`scripts/07-mode.ps1`](./scripts/07-mode.ps1) 与 [`scripts/01-dns-hardening.ps1`](./scripts/01-dns-hardening.ps1) 中所有注册表建键统一加 `if (-not (Test-Path -LiteralPath ...))` 保护，并在 `Set-SmhnrHardening` / `Ensure-Guard` 中同时守护自愈 `EnableMulticast=0` 与 `DisableSmartNameResolution=1` |
| R25 | Windows 11 24H2 下 Wintun 未分配单播 IPv6 地址时，调用底层 `SetInterfaceDnsSettings` 触发系统 Win32 错误码 `5` (`Access is denied`) 导致 Xray 原生单核心 TUN 崩溃回滚 | **v5.7**：在 Xray 源码引入无侵入精准前置守卫：以协议族是否拥有合法单播 IP 作为下发 DNS 的绝对凭据，完美兼容纯 IPv4/IPv6、双栈与空 DNS 清空语义；输出产物已在生产环境稳定运行 |
| R26 | 原防漂移逻辑盲目信任以 `AI-Guard-*` 开头的规则名，导致第三方或历史运维脚本注入的无约束全放行规则（如 `netsh ... interfacetype=any`）绕过隔离，架空默认 Block 策略 | **v5.7**：[`scripts/07-mode.ps1`](./scripts/07-mode.ps1) 强化防冒名与 Blanket Allow 识别：凡是出站 Allow 规则缺少 `RA4/RA6`（远程 IP）、`IF`（网卡接口）与 `App`（进程）三重限定的，一律判定为高危违规并自动隔离入 `backup\auto-disabled-outbound-allow.json` |
| R27 | `Get-NetFirewallInterfaceFilter.InterfaceAlias` 从系统读回网卡 GUID 列表，与传入的别名 `$activeTun = 'xray_tun'` 发生比对歧义，导致每次网络事件唤醒均判定未授权而重复写入 `AI-Guard-Allow-TUN-Alt` 并堆积过期 GUID 和 `'0'` | **v5.7**：新增 [`Test-FirewallRuleHasTun`](./scripts/07-mode.ps1) 辅助函数，实现别名与适配器底层 GUID 双向解析比对，彻底消除冗余写入、日志刷屏与 `'0'` 占位符残留 |
| R28 | `07-mode.ps1 -Status` 因前置管理员提权断言，导致非管理员终端（普通 CMD、PowerShell、VSCode/Cursor 内置终端）无法直接执行轻量级状态查看 | **v5.7**：优化提权分支：非管理员请求 `-Status` 时进入 `$script:ReadOnlyStatusMode` 快检通道，免提权展示当前 15 项防护状态看板 |
| R29 | 全链路回归体检第 4 项检测 Xray TUN 防泄漏 WFP 规则时使用 `'block DNS'` 严格字面量，无法匹配 Xray 官方创建的 `block the DNS Client service` 与 `block udp/53` 规则导致误报 `count=0` | **v5.7.2**：[`scripts/12-regression.ps1`](./scripts/12-regression.ps1) 与 [`scripts/04-wfp-audit.ps1`](./scripts/04-wfp-audit.ps1) 升级为正则 `'block (?:the )?DNS|block (?:tcp|udp)/(?:53|853)'`，准确匹配 18 条活跃防泄漏底层规则，24 项体检满分 PASS |
| R30 | TUN 代理模式下开启系统代理引发 WinINET HTTP 代理与虚拟网卡抢占、端口不匹配（10808/10809）以及常驻死代理风险 | **v5.7.2**：确立官方推荐系统代理模式为清除（`ProxyEnable = 0`），所有出站流量经由 `xray_tun` 虚拟网卡由内核捕获分流，免 WinINET 冲突；[`scripts/14-apply-policy.ps1`](./scripts/14-apply-policy.ps1) 自动保障纯净推荐状态，GUI 动态呈现推荐状态并支持与 v2rayN 协同切换 |
| R31 | 原生 GUI 桌面端仅提供中文界面，无法满足海外及多语言开发者使用需求 | **v5.7.2**：新增原生 [`LocalizationService`](./gui/Services/LocalizationService.cs)，右上角集成 `🌐 English` / `🌐 中文` 即时无缝双语切换，覆盖 15 项策略卡片、方案预设、遥测指标与交互弹窗，语言偏好自动持久化 |

---

## 5. 日常维护与配合说明

1. **v2rayN 系统代理建议**：若希望**仅凭开关 TUN 就 100% 控制浏览器能否访问境外 AI**，请在 v2rayN 主界面底部将系统代理设为**「清除系统代理」**（否则只关 TUN 而不退出 v2rayN 时，浏览器仍会走 `127.0.0.1:10808 -> xray.exe` 出站）。
2. **v5.4 热同步自迁移机制**：所有 v5.4 脚本已热同步至 `C:\AI-Net-Guard\`。当你下次开关 TUN/Wi-Fi、睡眠唤醒、到达每小时巡检点，或手动执行一次 `.\scripts\07-mode.ps1` 时，`SYSTEM` 会自动执行一次性 `v54-migrated.flag` 热迁移（写入 `DisableSmartNameResolution=1` 并为计划任务加上睡眠唤醒触发器）。

```powershell
# 管理员 PowerShell 常用命令（平时零维护，按需查看）
cd C:\AI-Net-Guard
.\scripts\07-mode.ps1                    # （可选）立即触发一次自检与 v5.4 注册表/睡眠唤醒任务热迁移，并打印状态
.\scripts\07-mode.ps1 -Status            # 只读查看 v5.4 状态（含 core、auto-sync=on、LLMNR/SMHNR、越权 Allow=0、0 常驻进程）
.\scripts\12-regression.ps1              # 运行 v5.4 全量 22 项回归测试（PASS 后自动清理临时抓包文件）
.\scripts\10-sync-node-rule.ps1 -WhatIfOnly  # 免提权预览当前 Xray / sing-box 节点与端口解析结果
.\scripts\09-rollback.ps1                # 彻底回滚到安装前原始基线状态
.\scripts\13-harden-acl.ps1              # 锁定安装目录权限 + 跑一次 v5.4 提权自检与回归（-Undo 可撤销）
```

3. **ACL 锁定后的更新方式**：`C:\AI-Net-Guard` 锁定后仅管理员可写，以后若工作区有更新，只需在**管理员终端**执行短命令 `.\scripts\13-harden-acl.ps1 -SyncWorkspace`（会自动同步文件、重新校验/锁定 ACL 并完成自检），无需再手敲长路径 `Copy-Item`。

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
- [x] **锁定 `C:\AI-Net-Guard` 目录与所有者 ACL（O1）** + **R24 注册表建键保护与 `24/24 PASS` 闭环确认（O2）**；
- [ ] （可选）在 v2rayN 底部状态栏将系统代理设为**「清除系统代理」**，实现纯 TUN 单开关总控；
- [ ] （可选）**重启演练**：`.\scripts\06-boot-guard.ps1 -Arm -WindowMinutes 30 -WaitMinutes 10` → 重启系统 → 验证不开代理国内正常/境外阻断、开 TUN 后国外恢复且后台无常驻 `powershell.exe` → `.\scripts\06-boot-guard.ps1 -Remove`。

## 7. 安全审查结论（v5.4）

**结论：功能与权限面已收敛，冻结在 v5.4。**

| # | 事项 | 严重度 | 状态 |
|---|------|--------|------|
| O1 | `C:\AI-Net-Guard` 默认继承 C 盘根目录的 `Authenticated Users:(M)`，而 `AI-Guard-Mode-Event` / `-Fallback` 以 **SYSTEM** 运行其中的 `07-mode.ps1`。若不锁权，非管理员进程可改写脚本以提权或静默拆除防护。 | **高** | **已解决（[`scripts/13-harden-acl.ps1`](./scripts/13-harden-acl.ps1)）** |
| O2 | v5.4 提权自迁移与全量回归验证（`v54-migrated.flag`、`SMHNR=off` `phys_attempts=0`、睡眠唤醒触发器 XML、R24 注册表同键保留修复）。 | 中 | **已解决（`24/24 PASS`）** |
| O3 | 用户态安装的 `<v2rayN>\bin\xray\xray.exe` 与 `geoip*.dat` 通常为普通用户可写，而 `AI-Guard-Allow-Node-TCP` / `DoH-Ali` 按程序路径放行。 | 低 | 设计取舍（若锁死 v2rayN 目录会破坏客户端自动更新内核与 GeoIP；高安全场景可将 v2rayN 迁入 `C:\Program Files\v2rayN`） |

O1 + O2 一键执行（管理员 PowerShell）：

```powershell
cd C:\AI-Net-Guard
.\scripts\13-harden-acl.ps1
```

> [!NOTE]
> Windows 中对象所有者（Owner）隐含 `WRITE_DAC` 权限，若不把所有者一并改为 `Administrators`，原普通用户所有者仍可把写权限重新赋回给自己。[`scripts/13-harden-acl.ps1`](./scripts/13-harden-acl.ps1) 会同时执行 `/setowner *S-1-5-32-544 /T` 并使用 `.NET` ACL API 逐项校验。

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
   - 引入 [`scripts/14-apply-policy.ps1`](./scripts/14-apply-policy.ps1) 幂等编排引擎：不仅首次部署全自动完成基线备份、规则建立、连通性快速探测与提交，且在已部署状态下修改任意单项开关时，支持秒级增量切换而绝不污染原始基线；
   - [`scripts/07-mode.ps1`](./scripts/07-mode.ps1) 与 [`scripts/12-regression.ps1`](./scripts/12-regression.ps1) 严格读取并遵循用户在 GUI 中配置的策略，确保后台自愈与体检断言与用户意图 100% 一致。
3. **桌面一键运维与安全防篡改**：
   - 顶部提供 `v2rayN` 路径自动探测与配置校验徽章；
   - 自动检测并提供 **「一键关闭系统代理」**（`HKCU` WinINET `ProxyEnable=0` + `InternetSetOption` 实时刷新），实现仅通过 `v2rayN` 的「启用 Tun」单开关控制全局分流；
   - 底部集成 **「一键部署」**、**「一键 24 项健康体检」**、**「一键完整卸载回滚」** 及可折叠的实时流式输出控制台。

---

## 9. v5.7 升级：Win11 24H2 原生 Xray TUN 适配、防冒名全放行隔离与智能网卡治理

v5.7 针对近期在 Windows 11 24H2 实测与代码深度审查中捕获的关键痛点进行了架构级升级：

1. **Win11 24H2 下 Xray 原生 TUN `SetDNS: Access is denied` 根因定位与修复**：
   - **根因剖析**：Windows 11 24H2 对未配置单播 IPv6 地址的 Wintun 虚拟接口调用 `SetInterfaceDnsSettings` 时严格校验并返回错误码 `5`。原版 Xray 依赖 `ERROR_NOT_FOUND` 作为跳过条件，但 Win11 24H2 下该 API 穿透返回 `nil`，导致强行设置空 IPv6 DNS 触发致命崩溃。
   - **工程修复**：引入以单播 IP 存在性为守卫的最小补丁，杜绝假成功，确保纯 IPv4、纯 IPv6 及双栈环境均能稳定运行原生单核心 TUN。
2. **防冒名伪装与高危无约束出站 Allow 规则反穿透 (R26)**：
   - 重构了 `Get-FirewallRuleAnalysis` 引擎，引入严密特征识别：任何缺少远端目标 IP (`RA4/RA6`)、作用网卡 (`IF`) 与进程签名 (`App`) 的全放行出站规则，即使名字前缀带有 `AI-Guard-*`，也会被视作伪装/非法规则并自动移入隔离区，彻底杜绝运维误操作或恶意进程架空默认阻断策略。
3. **异构 TUN 规则动态挂载 GUID / 别名智能映射 (R27)**：
   - 引入 [`Test-FirewallRuleHasTun`](./scripts/07-mode.ps1) 机制，双向识别网卡友好别名与底层 InterfaceGuid，杜绝因比对失败导致的每次网络事件重复刷新，清除历史残留的 `'0'` 占位符与废弃 Wintun GUID。
4. **免提权只读状态看板与生态协同 (R28)**：
   - `07-mode.ps1 -Status` 支持非提权普通终端即开即查，日常在 VSCode/Cursor 终端中无需 UAC 弹窗即可实时核验 15 项防护状态。
   - 提供了专用的连通性与防泄漏自动化探测脚本，一键验证物理网卡直连阻断与 TUN 代理链路健康。

---

## 10. v5.7.2 小版本升级：官方推荐系统代理模式（ProxyEnable=0 纯 TUN 模式）与 GUI 中英双语切换

v5.7.2 是在 v5.7 基础上的精细化小版本演进，重点强化了系统代理规范性、体检准确性与多语言体验：

1. **确立官方推荐系统代理模式（`ProxyEnable = 0` 纯 TUN 模式）**：
   - **架构设计**：在开启 TUN 虚拟网卡（如 `xray_tun`）后，所有三层 IP 数据包已在 Windows 内核网络协议栈被虚拟网卡全量捕获与路由分流。若同时开启 Windows 系统代理（`ProxyEnable = 1`），WinINET 及其支持的浏览器和应用会尝试连接 `127.0.0.1:10809` 本地端口，一旦代理客户端未开启 HTTP 监听（仅开 10808 SOCKS5）或异常退出，就会出现浏览器死代理报错。
   - **官方推荐准则**：AI-Net-Guard 明确将系统代理清除（`ProxyEnable = 0`）作为官方推荐的纯净状态。在策略应用脚本 [`scripts/14-apply-policy.ps1`](./scripts/14-apply-policy.ps1) 及 GUI 推荐预设中默认确保该纯净状态，并提供动态双向切换机制。
2. **全链路回归体检 WFP DNS 封锁规则识别修正 (R29)**：
   - 修正了 Xray TUN 防泄漏规则检查的匹配正则，完美覆盖 `block the DNS Client service`、`block udp/53`、`block tcp/53` 等全部 18 条驱动层拦截规则，杜绝误报。
3. **原生 GUI 桌面端中英双语即时切换 (R31)**：
   - 新增原生轻量多语言服务，支持界面实时中英文热切换，无需重启应用程序，偏好自动保存至 `backup/gui-settings.json`。

---

## 11. v5.7.3 小版本升级：Fluent 纯矢量微图标系统、0 截断弹性状态药丸与全链路浅色微光美化

v5.7.3 针对原生桌面 GUI 客户端进行了全链路深度美化与人机工学交互重构，全面对标 Windows 11 Fluent 与 macOS 现代工业级软件质感：

1. **工业级 Fluent / Lucide 纯矢量几何图标系统（`StreamGeometry`）**：
   - **告别卡通 Emoji**：全面移除界面中容易因平台字体差异产生黑边、比例失调的系统 Emoji（如 `🚇` 地铁车厢、`🛡️` 盾牌、`🌐` 地球、`🔒` 门锁、`🛟` 救生圈、`⚡` 闪电、`🔍` 放大镜）；
   - **硬件加速矢量路径**：引入 13 组标准化 24x24 矢量微图标（`IconShieldCheck`、`IconNetwork`、`IconGlobe`、`IconLock`、`IconCheckCircle`、`IconAlertTriangle`、`IconZap`、`IconSearchCheck`、`IconLifebuoy`、`IconFolder`、`IconRefresh`、`IconTrash`、`IconLanguages`），具备统一的 `1.8px` 细致线宽、圆角线帽与完美适配的高 DPI 缩放表现；
   - **TUN 拓扑重绘**：将误导性的地铁车厢替换为高科技感的双向网络节点总线网关图标（`IconNetwork`），准确传达内核驱动与网络拓扑意象。
2. **底部状态提示栏 0 截断弹性药丸架构**：
   - 底部按钮横向紧凑化，节省出 150px 宝贵呼吸空间；
   - 底部状态提示重构为弹性圆角状态药丸（`SetFooterStatusPill`），支持绿（成功防护）、黄（待同步）、红（异常阻断）、蓝（部署忙碌）状态指示灯，无论窗口缩放至何种尺寸均保持绝对 0 截断，鼠标悬停即时展示详细 ToolTip。
3. **系统代理微光卡片美化**：
   - 移除了原先突兀的深蓝纯黑大色块（`#182234`），采用 Fluent 浅色软强调微光卡片（`#F0FDF4` / `#86EFAC`）；
   - 根据代理模式动态切换官方推荐状态（`ProxyEnable = 0`，绿圆环对勾）与临时开启警告状态（`ProxyEnable = 1`，暖黄警告三角）。
4. **特性分类微胶囊徽章与数量统计**：
   - 4 大特性分类标题增加独立色彩的微胶囊矢量徽章；
   - 动态计算并展示分类下特性数量胶囊（`[ 4 项特性 ]` / `[ 3 项特性 ]`）。

---
## 12. v5.7.4 修复版本：更换失效的默认 NTP 服务器，并实测系统时钟偏差

问题：默认 NTP 列表中的 `www.time.ac.cn` 已不再响应 NTP 请求（`w32tm` 返回 `0x800705B4` 超时）。当它是唯一的 NTP 服务器时，Windows 时间服务开机后从未成功同步，时钟最多慢了 27 分钟，导致 VMess（允许的最大时间差为 120 秒）连接失败。旧的检查只匹配 `.cn` 后缀，因此一直把它判定为正常。

1. **新的默认 NTP 列表**：`ntp.aliyun.com`（首选）、`ntp.tencent.com`、`ntp.ntsc.ac.cn`（国家授时中心）。按实测稳定性排序：阿里云每次都能响应，国家授时中心偶尔超时。
2. **新的判定规则**：列表中至少有一个已知可用的国内服务器（`ntsc.ac.cn` / `aliyun` / `tencent` / `203.107.6.88`），并且不能包含 `www.time.ac.cn`。仍带有旧列表的安装会被自动迁移。`07-mode.ps1`、`14-apply-policy.ps1`、`01-dns-hardening.ps1` 与 GUI 状态探测使用同一条规则。
3. **立即同步**：修改 NTP 列表后执行 `w32tm /resync /nowait`。
4. **新增验证项**：`03-verify.ps1` 新增「system clock offset vs domestic NTP」，实测本机与国内 NTP 的时间差，超过 60 秒判为失败。

---
## 13. v5.7.5 修复版本：WebRTC STUN/TURN 物理网卡旁路泄漏双层防护 (`BlockWebRtcLeak`)

1. **根因实测**：
   - 在 Windows TUN 模式下，无论使用 `sing-box`（如 Hysteria2 节点）还是 `Xray`（如 VLESS 节点），物理网卡默认路由仍与虚拟 TUN 网卡并存。
   - 当浏览器 WebRTC ICE 显式将 UDP Socket 绑定至物理网卡本地 IP（如 `192.168.1.165`）向公网 STUN 服务器（如 `74.125.250.129:19302`）发包时，即使 `Xray` 开启了 `autoSystemWfpBlockLeak=["dns","misconfigtun"]`，该机制仅覆盖 53 端口及 `0.0.0.0` 未绑定流，仍无法拦截绑定物理网卡 IP 的 STUN 出站包，导致 STUN 响应直接暴露真实运营商公网 IP。
2. **双层防御实现**：
   - **内核/防火墙层 (`AI-Guard-Block-WebRTC-UDP/TCP` & `AI-Guard-Block-WebRTC-LocalIP-UDP/TCP` & `AI-Guard-Allow-TUN` 源 IP 隔离)**：
     - 除物理网卡别名与物理源 IP 的 STUN/TURN 显式阻断规则（`3478, 3479, 5349, 5350, 19302-19309`）外，还将 `AI-Guard-Allow-TUN` 与 `AI-Guard-Allow-TUN-Alt` 的 `LocalAddress` 收窄为实际 TUN 地址与私网 TUN 网段（排除任何物理网卡子网），从根源彻底阻断“绑定物理 IP 借道 `0.0.0.0/0` TUN 规则绕过 `DefaultOutboundAction=Block`”的任意端口直连旁路泄漏（含 `13.107.246.51:443` 探针与 TURN-over-TLS/443）。
   - **另附发现并修复验证假阴性**：`03-verify.ps1` 与 `12-regression.ps1` 原先的物理网卡绑定直连探针存在 `try { throw 'leak detected' } catch { return 'blocked' }` 的异常自吞 bug，本次一并修复为在 `finally` 之后再判定抛出。
   - **浏览器策略层**：写入 Chrome / Edge 组策略 `WebRtcIPHandlingPolicy = disable_non_proxied_udp`（及 Edge `WebRtcLocalhostIpHandling = disable_non_proxied_udp`），并在安装前捕获原始注册表值到 DNS 备份 JSON（v5.5 格式），`09-rollback.ps1` 或关闭开关时完整恢复。
3. **全链路集成与验证**：
   - 新增策略开关 `BlockWebRtcLeak`（第 16 项策略，默认开启），同步集成于 `01-dns-hardening.ps1`、`02-killswitch.ps1`、`07-mode.ps1`（0-CIM 快路径审计与新接入物理网卡自动纳管）、`09-rollback.ps1`、`14-apply-policy.ps1` 及 WPF GUI（`GuardPolicy.cs`、`MainWindow.xaml.cs`）。
   - `03-verify.ps1`、`12-regression.ps1`、`verify-leak-test.ps1` 均新增规则/策略检查及物理网卡绑定真实 STUN UDP（`74.125.250.129:19302`）阻断实测探针。

---
## 14. v5.7.6 升级版本：显式物理境外阻断 (`AI-Guard-Block-Foreign-Physical`) 与 Hysteria2/VLESS 多核深化优化

1. **第三方 WFP 软放行与物理网卡旁路彻底封堵**：
   - 在同时安装第三方安全/流控 WFP 驱动（如 `hrwfpdrv` 火绒、`idmwfp` IDM、`nfwfp` NetFilter）的环境下，其 `Flow Established Callout` 等软放行优先级高于 Windows 防火墙底层的 `DefaultOutboundAction = Block`，导致仅依赖默认拒绝时，显式绑定物理 IP（如 `192.168.1.165`）的非 CN 请求仍可能出站。
   - **核心修复**：
     - 新增共享模块 [`scripts/lib-foreign-block.ps1`](./scripts/lib-foreign-block.ps1)，基于 `[0, 2^32-1]` IPv4 区间扫面算法精准计算 `cn-ipv4.txt` + 私网/LAN + NCSI(`13.107.4.52`) + 阿里 DoH(`223.5.5.5/223.6.6.6`) + 落地节点 IP 之外的全部补集网段，在物理网卡接口写入显式 `Action=Block` 规则 **`AI-Guard-Block-Foreign-Physical`**，跨子层一票否决任何第三方 WFP 软放行与 `Xray TUN` 软放行。
     - 同步收窄 `AI-Guard-Allow-TUN` / `AI-Guard-Allow-TUN-Alt` 的 `LocalAddress` 为 TUN 地址及非重叠私网 TUN 网段，并维护 `AI-Guard-Block-PhysicalIP-On-TUN` 显式阻断。
2. **Hysteria2 (`hy2`) + `sing-box` + 双核心稳定性优化**：
   - **多出站 & 端口跳跃 (`server_ports`) 完备支持**：`02-killswitch.ps1`、`07-mode.ps1`、`10-sync-node-rule.ps1` 全面支持扫描 `sing-box` 多代理出站及 `configTest*.json` 中的 `server_ports`（自动将 `:` 转为防火墙范围 `-`），并在 `07-mode.ps1` 快路径比对 `AI-Guard-Allow-Node-UDP` 的具体 IP 与端口，同时自动清理不再使用 UDP 时的陈旧 `AI-Guard-Allow-Core-*-UDP` 规则。
   - **双核心阿里 DoH 伴生放行 (`AI-Guard-Allow-Core-*-DoH`)**：为所有已安装代理核心（`xray.exe`、`sing-box.exe`、`v2rayN.exe`）各自维护 `223.5.5.5/223.6.6.6:443` 放行规则，切换协议或双核协同不互抢。
   - **域名节点 15 分钟周期重解析 & 旧 `/32` 路由清理**：CDN/DDNS 域名落地节点自动定期刷新 IP，切换节点时清理旧 `/32` 物理主机路由。
   - **`03-verify.ps1` 与 `04-wfp-audit.ps1` 完善**：节点校验同时观测 `sing-box` UDP 套接字与物理 `/32` 路由对齐；WFP 审计器支持输出非 `AI-Guard` 的 `ALE_AUTH_CONNECT_V4` `FWP_ACTION_PERMIT` / `FWP_ACTION_CALLOUT_TERMINATING` 过滤器。

---
## 15. v5.7.7 升级版本：浏览器内置 DoH 防泄漏锁定与 Windows mDNS 禁用

1. **禁止 Chrome / Edge 内置 DoH 旁路国内 DNS (`DnsOverHttpsMode = "off"`)**：
   - 当物理网卡 DNS 锁定为 `223.5.5.5` 时，浏览器若默认开启“安全 DNS 自动模式”可能直接升级为阿里云 `dns.alidns.com` DoH，绕过 `xray_tun` 的国外 DoH 分流模块（`dns-module`）并将境外域名泄漏给国内 DNS。
   - 归属于 `LockPhysicalDns`（及 `StrictNrptDoh`）：在 [`scripts/01-dns-hardening.ps1`](./scripts/01-dns-hardening.ps1)、[`scripts/14-apply-policy.ps1`](./scripts/14-apply-policy.ps1) 与 [`scripts/07-mode.ps1`](./scripts/07-mode.ps1)（`Set-BrowserDohPolicy`）中统一写入 Chrome / Edge 组策略 `DnsOverHttpsMode = "off"`，使浏览器域名请求统一进入 `xray_tun` / 系统解析路径分流；并在 `dns-*.json`（`ChromeDohMode`、`EdgeDohMode`）完整备份以便关闭或 [`scripts/09-rollback.ps1`](./scripts/09-rollback.ps1) 时原样恢复。
2. **显式禁用 Windows 系统级 mDNS (`EnableMDNS = 0`)**：
   - 归属于 `DisableLlmnrNetbios`：除 `DNSClient\EnableMulticast=0`（LLMNR）与 NetBIOS 外，同步在 `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` 写入 `EnableMDNS = 0`，并在 `dns-*.json`（`MdnsEnabled`）保存原始基线，关闭开关或完整回滚时无损还原。
   - [`scripts/03-verify.ps1`](./scripts/03-verify.ps1)、[`scripts/12-regression.ps1`](./scripts/12-regression.ps1) 与 [`scripts/verify-leak-test.ps1`](./scripts/verify-leak-test.ps1) 同步增加 `DnsOverHttpsMode=off` 与 `EnableMDNS=0` 校验。

---
## 16. v5.8.0 升级版本：路由层 STUN 封锁与自愈快路径重构

### 16.1 WebRTC 泄露的真实链路（推翻 v5.7.x 的结论）

v5.7.x 把"防火墙 Block 规则已启用"当成 WebRTC 已封堵的证据，实测不成立。用**不经浏览器**的裸 UDP STUN 客户端（`System.Net.Sockets.UdpClient` 直接发 Binding Request）测量：

| 目标 | 结果 | 判定 |
| --- | --- | --- |
| `stun.miwifi.com:3478`（111.206.174.x） | `mapped=183.188.38.12` | **泄露真实宽带 IP** |
| `stun.chat.bilibili.com:3478`（106.12.x） | `mapped=183.188.38.12` | **泄露** |
| `stun.l.google.com:19302` | `mapped=20.89.232.246` | 走代理，正常 |

当时 8 条 `AI-Guard-Block-WebRTC-*` 全部 `Active=TRUE`，`xray.exe` 程序路径、12 个 STUN 端口、网卡 GUID 全部正确。真实链路是：

```
任意进程 -> xray_tun（默认路由 metric 0）-> xray.exe 路由命中 geoip:cn -> direct
        -> xray.exe 从物理网卡重发，源 IP 192.168.1.165 -> NAT -> 183.188.38.12
```

根因不是"规则不够具体"。Windows 防火墙的仲裁是**显式 Block 一律压过 Allow**，与具体度无关。真正原因是 TUN 提供方在 `ALE_AUTH_CONNECT` 层对核心自身的出站安装 callout 并 **PERMIT + 终结分类**，防火墙的 Block 过滤器根本没有被求值。旁证：同一个探针若显式绑定物理地址（`verify-leak-test.ps1` 第 3 段即如此）规则一定生效，失效的只是"核心自己发包"这一跳。**任何防火墙规则都堵不住这一跳**。

### 16.2 `18-route-stun-guard.ps1`：在核心路由表里丢弃 STUN/TURN

唯一能在重发前看到包的层次是核心自己的路由表。v2rayN 本身就用这个手法阻断 QUIC（生成的 `config.json` 里带 `{"port":"135,137-139,5353","network":"udp","outboundTag":"block"}`），因此沿用同一形状，在当前生效路由集**顶部**插入两条：

```json
{"Port":"3478,3479,5349,5350,19302,19303,19304,19305,19306,19307,19308,19309","Network":"udp","OutboundTag":"block","Remarks":"STUN-GUARD: ..."}
{"Port":"... 同上 ...","Network":"tcp","OutboundTag":"block","Remarks":"STUN-GUARD: ..."}
```

- **国内直连规则一行不动**，`geoip:cn` / `geosite:cn` 位置与语义不变，代理流量零增加，配额不受影响。
- **确定性**：包在核心内被丢弃，不产生任何出站，不依赖 WFP 仲裁与第三方驱动行为。
- **安全性**：`-Verify`（默认）只读；`-Apply` 先把 `guiNDB.db` 备份到 `backup\v2rayn-routing\<时间戳>\` 再写；`-Restore` 一键回滚且恢复前先快照当前库；**v2rayN 运行中拒绝执行**（其内存副本会在退出时覆盖数据库）；以 `STUN-GUARD:` 前缀做幂等剥离，重复执行不会叠加规则；写入后回读校验，读不到即视为失败（exit 3）。
- **代价**：网页版 WebRTC 通话彻底拿不到 `srflx` 候选，可能只能走 TURN 中转或直接建连失败。这是"宁可不通也不泄露"的显式取舍，可随时 `-Restore` 撤销。

### 16.3 `verify-leak-test.ps1` 第 9 段：从"数规则"改为"测行为"

新增活体 STUN 探针（`stun.miwifi.com` / `stun.chat.bilibili.com` / `stun.qq.com` + `stun.l.google.com` / `stun.cloudflare.com` 对照）。判定标准改为行为，且**与 B1 语义严格一致：任何应答都算失败，境内境外同等对待**——B1 只匹配目的端口、不看目标地址，境外能应答就说明这条端口没有被丢弃，不存在"境外应答属正常"这一说。探针错误按 `SocketErrorCode` 分类（`TimedOut` / `ConnectionRefused` / `ConnectionReset` / `HostUnreachable` / `NetworkUnreachable` / `HostNotFound`），不依赖会被本地化的异常文本；其中只有 `TimedOut` 可以配合配置检查算"已丢弃"，其余一律 INCONCLUSIVE。详见 16.7。

### 16.4 `07-mode.ps1` 自愈快路径：5.8 s → 2.1 s

| 缺陷 | 机制 | 修法 |
| --- | --- | --- |
| `Test-ShieldDriftFast` 用 `IF=\{GUID\}` 匹配，而 `NetworkInterface.Id` 自带花括号，拼成双层 `IF=\{\{...}}` 永不匹配 | 每轮自检都判"漂移"，每次都拉起 `15-webrtc-browser-shield.ps1` 子进程（约 3.5 s） | 统一为带花括号形式后逐字比较；门控两向验证（注入幻影网卡 GUID 立刻跳回 5.6 s，证明修复路径没有被关掉） |
| `backup\foreign-block.meta` 用 `-Encoding ASCII` 写签名，而签名含网卡别名（`以太网`） | 别名被写成 `???`，签名永远不等 → 只要以太网 Up 就 `Remove-` + `New-NetFirewallRule` 整条重建上千条 `RemoteAddress` 的 `AI-Guard-Block-Foreign-Physical`，且**删除到重建之间存在无显式 BLOCK 的 fail-open 窗口** | meta 改 UTF-8；已有规则改用 `Set-NetFirewallRule -RemoteAddress` 原地更新，空窗消失 |

实测（非提权、同机、各 3 次取最小值）：`5789 / 6310 / 6012 ms` → `2113 / 2210 / 2168 ms`。剩余 2.1 s 中约 1.33 s 是 PowerShell 进程启动 + 148 KB 脚本解析，已到地板。

### 16.5 规则集缓存层（`07` / `15` 各自独立实现）

`Get-NetFirewallRule` 单次约 1233 ms（加不加 `-Name` 都一样，模块先做全量 CIM 往返再客户端过滤），每个 `Get-NetFirewall*Filter` 约 290~337 ms。新增 `RuleIndex`（Name / DisplayName 双键）+ `RuleFilterCache`（`Kind|Key`）两层缓存，并提供 `Reset-RuleCache`：**任何 `Set-/New-/Remove-/Disable-/Enable-NetFirewallRule` 之后必须失效缓存**，否则会拿陈旧对象去"修复"它刚修好的漂移。

对健康路径收益接近零（健康路径本就不怎么调这些命令），但对 `15` 自身显著：`-Verify` 45.1 s → 11.9 s，`-Apply` 12.4 s → 6.6 s，`-DryRun` 32.4 s → 7.8 s。

### 16.6 提权实测与 `17 -SelfTest` 补齐兜底腿（v5.8.1）

在真实 SYSTEM 上下文（提权终端跑 `17-autorepair-task.ps1 -Install -SelfTest`）实测：**run 1 = 5.09 s / run 2 = 5.17 s，result 均为 0**，较改前的 20.69 s / 21.18 s 缩短约 4 倍。剩余的 5 s 构成为：任务计划程序启动 + SYSTEM 冷进程 ~2 s、`-OnNetworkEvent` 的 350 ms 预延时与 800 ms 后置复核、以及脚本自身约 2.1 s（其中 1.33 s 是 PowerShell 启动 + 解析）。

同时修掉两处会误导的表述：

1. `-Status` 的 `cost` 行原本硬编码「fallback ~17 s, event repair ~21 s per fire」，优化后已失真。**静态耗时数字写进输出必然会腐烂**，改为只描述触发模型，耗时一律以 `-Install -SelfTest` 实测为准。
2. `-Install -SelfTest` 原本只验证事件任务（跑两次），**兜底任务在全新安装上永远是 `last run: never / result: 267011`**，等于从没被证明过能用。现在追加一次兜底任务实跑（`-Mode Auto -Quiet`，与定时器触发完全同一路径），三条退出码全为 0 才判定通过。

### 16.7 外部审查后的修正（v5.8.2）

v5.8.1 的两个脚本经过一次逐行审查，暴露出 7 个问题，其中 2 个会造成**假阳性**（报告防护有效而实际无效）。以下按优先级记录结论，不接受"看起来没问题"作为证据。

**P0 —— 第 9 段把境外 STUN 应答判成 PASS（最严重）**

旧逻辑是 `if ($isCn) { FAIL } else { WARN }`，汇总时只统计 `$stunLeaks`（境内应答数）。B1 是纯端口匹配、不看目标，境外应答恰恰证明端口没被丢弃；旧逻辑却把唯一能证伪的情况降级成一条 WARN，然后照样打印 PASS。实测现场就能复现：`stun.l.google.com:19302` 返回 `20.89.232.246`（机场落地 IP），旧代码判 PASS。

现在判定收敛为三态，且**失败优先级最高**：

| 探针结果 | 判定 |
| --- | --- |
| 任一目标有应答（境内或境外） | `FAIL` |
| 目标静默 + 两条规则已完整加载 + TUN 在线 | `PASS` |
| 静默但配置未加载 / 无 TUN / 拒绝 / 重置 / 不可达 / DNS 失败 | `INCONCLUSIVE` |

**静默本身不是证据**：被丢弃的端口和断掉的网络对 UDP socket 完全一样，所以 PASS 必须同时满足"配置检查通过"，否则只能说 INCONCLUSIVE。汇总规则是 `FAIL > INCONCLUSIVE > PASS`，且不允许多数掩盖少数——1 个应答就是 FAIL。

**P1 —— `-Verify` 的配置检查太弱，会把"部分配置"报成 B1 ACTIVE**

旧实现只找"`outboundTag=block` 且 `port` 含 `3478`"的第一条规则。这意味着：只有 UDP 一条、或端口列表只写了 `3478,3479`、或 TCP/UDP 顺序颠倒，都会被判成已生效。现在要求**相邻的 udp 规则紧跟 tcp 规则、两条都携带完整 11 个端口**；不满足时输出 `PARTIAL` 并列出缺哪些端口，绝不输出 ACTIVE。`18` 侧同一套检查（`Get-CoreGuardState`）共用同样判据，并额外校验两条规则的固定 `Id`。

**P1 —— 固定规则 `Id` 可能与既有规则冲突**

两条守卫规则复用固定 `Id`（`8800000000000000001/2`）以实现幂等替换。若用户自己的某条规则恰好占用同一 `Id`，v2rayN 会把两条当成同一条，可能丢弃或覆盖对方。现在 `apply` 前先扫描非守卫规则，命中即 `exit 4` 并打印冲突规则的 JSON 摘要，库一个字节都不写。（实测真库 9 条规则的 `Id` 均为 19 位随机数字，当前无冲突。）

**P1 —— `-Restore` 没有恢复前快照**

`-Restore` 直接覆盖当前库。如果恢复后才发现选错了备份，恢复前那份状态就再也没有了。现在先把当前库复制到 `backup\v2rayn-restore-pre\<时间戳>\guiNDB.db`，并单独放一棵目录树——否则这个快照会被 `-Restore` 自己"取最新干净备份"的逻辑挑中，造成"回滚到回滚前"的循环。

**P2 —— 注释声称的 `PRAGMA quick_check` 并不存在**

原注释写了 quick_check，Python 里只是打开库、读表、解析 JSON。现在 `open_db()` 真的执行 `PRAGMA quick_check`，要求恰好返回一行 `ok`，否则抛错并以 `DB_UNUSABLE` / `BACKUP_UNUSABLE` 退出（exit 3）。用被抹掉 200 字节的副本验证过：`-Restore` 拒绝执行，真库不动。

**P2 —— WAL 检查的位置本身就是错的（这条是演练才发现的）**

最初把 `-wal` 检查放在 apply 段，位于读库之后。实测发现：**只要 sqlite 打开过 `guiNDB.db`，残留的 `-wal` 就会被删掉**——所以那个检查永远看到"没有 WAL"，是彻底的死代码。现在检查前移到任何 sqlite 连接之前，并且覆盖 `-Verify` / `-Apply` / `-Restore` 全部分支。`guiNDB.db` 本身是 `journal_mode=delete`，这条警报正常情况不会触发，它针对的是"v2rayN 没干净退出"。

**P2 —— 补 `stun.cloudflare.com` 探针**

境外端点从 1 个增到 2 个，避免单一端点被墙/被机场特殊处理时误判。

**顺带修掉的两个自身缺陷（演练抓出，非审查提出）**

1. ID 冲突分支写成 `Say '...' + $bkDir 'Yellow'`，PowerShell 按 4 个位置参数绑定而抛终止性错误——正好发生在需要给人看提示的那条路径上。
2. Windows 对 UDP 收到的 ICMP port-unreachable 报的是 `ConnectionReset`（10054）而不是 `ConnectionRefused`，未分类时会落到 `error`。现在归入"包已离开主机"，与 refused 同等处理。

**验收方式**：沙箱副本 + 假 v2rayN 根目录，11 个场景 35 条断言全绿（WAL 拒绝、进程拒绝、apply、配置四态、幂等、restore、ID 冲突、损坏备份），全过程 **真库 `guiNDB.db` 的 SHA-256 与规则数（9 条、guard=0）未被改动**。


