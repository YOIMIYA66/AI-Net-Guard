using System;
using System.Collections.Generic;
using System.IO;

namespace AiNetGuard.Gui.Services
{
    public enum AppLanguage
    {
        Zh,
        En
    }

    public static class LocalizationService
    {
        private static AppLanguage _currentLanguage = AppLanguage.Zh;
        public static event Action LanguageChanged;

        public static AppLanguage CurrentLanguage
        {
            get => _currentLanguage;
            set
            {
                if (_currentLanguage != value)
                {
                    _currentLanguage = value;
                    LanguageChanged?.Invoke();
                }
            }
        }

        public static bool IsEnglish => _currentLanguage == AppLanguage.En;

        public static void ToggleLanguage(string rootDir = null)
        {
            CurrentLanguage = _currentLanguage == AppLanguage.Zh ? AppLanguage.En : AppLanguage.Zh;
            if (!string.IsNullOrEmpty(rootDir))
            {
                SaveLanguagePreference(rootDir, _currentLanguage);
            }
        }

        public static void LoadLanguagePreference(string rootDir)
        {
            try
            {
                string settingsFile = Path.Combine(rootDir, "backup", "gui-settings.json");
                if (File.Exists(settingsFile))
                {
                    string content = File.ReadAllText(settingsFile);
                    if (content.IndexOf("\"Language\": \"en\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        content.IndexOf("\"Language\":\"en\"", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _currentLanguage = AppLanguage.En;
                        return;
                    }
                    if (content.IndexOf("\"Language\": \"zh\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        content.IndexOf("\"Language\":\"zh\"", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _currentLanguage = AppLanguage.Zh;
                        return;
                    }
                }
            }
            catch { }
            _currentLanguage = AppLanguage.Zh;
        }

        public static void SaveLanguagePreference(string rootDir, AppLanguage lang)
        {
            try
            {
                string backupDir = Path.Combine(rootDir, "backup");
                if (!Directory.Exists(backupDir))
                {
                    Directory.CreateDirectory(backupDir);
                }
                string settingsFile = Path.Combine(backupDir, "gui-settings.json");
                string langStr = lang == AppLanguage.En ? "en" : "zh";
                string json = "{\n  \"Language\": \"" + langStr + "\",\n  \"UpdatedAt\": \"" + DateTime.Now.ToString("o") + "\"\n}";
                File.WriteAllText(settingsFile, json);
            }
            catch { }
        }

        private static readonly Dictionary<string, string> StringsZh = new Dictionary<string, string>
        {
            ["AppTitle"] = "AI-Net-Guard v5.7.3 — Windows 内核级防泄漏与智能分流配置中心",
            ["HeaderVersionBadge"] = "v5.7.3 原生桌面版",
            ["HeaderSubtitle"] = "Windows 内核级 WFP 失败关闭防泄漏 · 国内直连白名单 · 零内存事件自愈配置中心",
            ["RescueBtn"] = "应急脱困",
            ["RescueBtnToolTip"] = "若遇网络异常或急需上网，一键秒级重置 Windows 原生网络并解除所有内核拦截",
            ["OpenDirBtn"] = "打开安装目录",
            ["RefreshBtn"] = "刷新状态",
            ["LangSwitchBtn"] = "English",
            ["LangSwitchBtnToolTip"] = "切换为英文界面 (Switch to English)",

            // Status Badges
            ["StatusReading"] = "正在读取系统状态...",
            ["StatusStrictActive"] = "严格全局铁桶锁已激活 (零直连)",
            ["StatusTestingPeriod"] = "防护运行中 (测试保护期)",
            ["StatusRunning"] = "内核静态防护运行中",
            ["StatusNotDeployed"] = "尚未部署 (系统原始状态)",

            // Cards
            ["CardFirewallTitle"] = "内核防火墙与防漂移",
            ["CardFirewallBlock"] = "默认出站拦截 (Block)",
            ["CardFirewallAllow"] = "系统默认放行 (未接管)",
            ["CardFirewallCnPrefixes"] = "大陆白名单 {0} 段",
            ["CardFirewallCnActive"] = "大陆白名单已启用",
            ["CardFirewallCnOff"] = "大陆直连已关闭",
            ["CardFirewallCnNone"] = "未安装白名单",
            ["CardFirewallRogue"] = "外部放行 {0} 条",

            ["CardTunTitle"] = "TUN 虚拟网卡与核心",
            ["CardTunOnline"] = "隧道在线 ({0})",
            ["CardTunOffline"] = "TUN 未开启",
            ["CardTunCoreOnline"] = "内核: {0} (在线)",
            ["CardTunCoreOffline"] = "内核: 未运行",

            ["CardNodeTitle"] = "当前放行节点",
            ["SyncNow"] = "同步",
            ["CardNodeNone"] = "未检测到放行节点",
            ["CardNodeRuleValid"] = "规则有效 · 允许出站",
            ["CardNodeRuleMissing"] = "规则缺失或未放行",
            ["CardNodeMaskTip"] = "点击切换隐藏/显示完整节点 IP",

            ["CardDnsTitle"] = "DNS 防泄漏与后台",
            ["CardDnsNrpt"] = "严格 NRPT (1.1.1.1)",
            ["CardDnsSummary"] = "DNS: {0}",
            ["CardDnsSmhnrOff"] = "SMHNR已禁",
            ["CardDnsSmhnrOn"] = "SMHNR默认",
            ["CardDnsZeroResidentReady"] = "0 MB 事件自愈",
            ["CardDnsZeroResidentNone"] = "无后台任务",
            ["CardDnsAclLocked"] = "目录 ACL 已防篡改锁定",
            ["CardDnsAclUnlocked"] = "目录 ACL 未锁定",
            ["CardDnsAclNotice"] = "部署时自动绑定节点并锁定 ACL",

            // v2rayN Row
            ["V2rayNPathLabel"] = "v2rayN 目录：",
            ["BrowseBtn"] = "浏览选择...",
            ["V2rayNValid"] = "已识别配置",
            ["V2rayNInvalid"] = "未找到配置",

            // System Proxy Banner
            ["SystemProxyOn"] = "Windows 系统代理：已开启为 {0}（WinINET 代理生效中，若已开 TUN 建议清除）",
            ["SystemProxyOff"] = "Windows 系统代理：已清除 (ProxyEnable=0 · 官方推荐 TUN 纯净状态，全量流量无感走虚拟网卡，免 WinINET 冲突)",
            ["ClearSysProxyBtnOff"] = "恢复为官方推荐状态 (清除代理)",
            ["ClearSysProxyBtnOn"] = "临时开启系统代理",

            // Presets
            ["PresetsTitle"] = "防护方案预设",
            ["ResetRecommendedBtn"] = "恢复默认推荐设置",
            ["Preset1Title"] = "推荐日常防泄漏",
            ["Preset1Badge"] = "强烈推荐",
            ["Preset2Title"] = "严格全局铁桶",
            ["Preset2Badge"] = "零直连",
            ["Preset3Title"] = "开发者 / 兼容模式",
            ["Preset3Badge"] = "保留 IPv6",
            ["PresetDescRecommended"] = "推荐日常防泄漏模式：开启全部 14 项推荐防护。国内满速直连、海外 100% 强制走 TUN 防泄漏、切节点自动放行、后台 0 MB 内存事件自愈。",
            ["PresetDescStrict"] = "严格全局铁桶锁模式：关闭大陆直连白名单与 NCSI 探测。只要 TUN 隧道断开或代理节点故障，全网（含国内网站）100% 物理熔断阻断，绝无任何裸连泄漏窗口。",
            ["PresetDescCompatible"] = "开发者兼容模式：在推荐防护基础上保留物理网卡 IPv6，适合局域网 IPv6 直连开发测试等特殊场景（注意：若运营商原生 IPv6 未接管可能存在泄漏）。",
            ["PresetDescCustom"] = "自定义方案：当前配置与标准预设不同（包含手动微调项）。点击右侧「恢复默认推荐设置」可一键重置。",

            // Foundation Banner
            ["FoundationTitle"] = "内核静态防护底座（部署期间恒定生效）：",
            ["FoundationText"] = "Windows 防火墙三配置默认出站拦截 (DefaultOutbound=Block) + TUN 隧道网卡放行 + 授权代理节点 / 阿里 DoH / DHCP 基础放行。代理进程退出也是 0 毫秒内核拦截，绝无裸连泄漏窗口。如需彻底关闭防护底座，请点击左下角「一键完整卸载」。",

            // Console
            ["ToggleConsoleExpand"] = "▶ 实时执行输出控制台（部署 / 体检 / 卸载时自动展开）",
            ["ToggleConsoleCollapse"] = "▼ 实时执行输出控制台（点击折叠）",
            ["CopyLogBtn"] = "复制日志",
            ["ClearLogBtn"] = "清空",

            // Bottom Actions
            ["UninstallBtn"] = "一键完整卸载",
            ["UninstallBtnToolTip"] = "完整还原 Windows 原始防火墙、DNS、IPv6 及系统计划任务",
            ["RegressionBtn"] = "24项全量回归",
            ["RegressionBtnToolTip"] = "运行 24 项全链路自动化防泄漏回归测试，含 10 秒实机网络抓包",
            ["LeakCheckBtn"] = "极速体检 (5s)",
            ["LeakCheckBtnToolTip"] = "5秒极速检测：底层物理网卡 Socket 强绑定直接出站拦截、活跃 TUN 网卡与海外连通性",
            ["FooterHintReady"] = "就绪",
            ["ApplyBtn"] = "一键部署 / 应用当前配置",

            // Modals & Messages
            ["Confirm"] = "确定",
            ["Cancel"] = "取消",
            ["ConfirmModalSubtitle"] = "AI-Net-Guard 原生操作确认",
            ["DeployConfirmTitle"] = "确认部署防护方案",
            ["DeployConfirmMsg"] = "即将将当前安全策略写入 Windows 内核 WFP 防火墙与系统网络栈。\n\n部署过程耗时约 3~5 秒，期间将自动同步代理节点放行规则并刷新 DNS 缓存。\n\n是否立即开始？",
            ["UninstallConfirmTitle"] = "高风险操作 — 确认完整卸载",
            ["UninstallConfirmMsg"] = "此操作将执行完整的安全回滚：\n\n1. 恢复 Windows 防火墙默认出站允许 (DefaultOutbound=Allow)\n2. 删除所有 AI-Guard-* 放行及阻断规则\n3. 恢复物理网卡原始 DNS 与 IPv6 绑定\n4. 删除计划任务与目录 ACL 锁定\n\n确定要彻底卸载并恢复系统出厂状态吗？",
            ["RescueConfirmTitle"] = "应急脱困确认",
            ["RescueConfirmMsg"] = "应急脱困将立即强制解除 Windows 防火墙所有拦截策略并恢复 DHCP DNS 自动获取，用于在网络异常阻断时秒级恢复联网。\n\n是否立即执行脱困？",
            ["StrictNrptConfirmTitle"] = "高级功能确认 — 严格全局 NRPT DoH",
            ["StrictNrptConfirmMsg"] = "开启「严格系统级全局 DoH (NRPT 1.1.1.1)」后：\n\n• 全系统 DNS 将强制仅走 1.1.1.1 加密通道且禁止回退；\n• 若代理未开启 TUN 虚拟网卡，国内国外域名都将完全无法解析；\n• 仅推荐海外常驻或 24 小时常开 TUN 的深度用户使用。\n\n确定要开启吗？",
            ["V2rayNNoticeTitle"] = "提示：v2rayN 正在运行",
            ["V2rayNNoticeMsg"] = "Windows 系统级 WinINET 代理注册表已更新完毕。\n\n由于 v2rayN 运行期间界面状态由内存常驻维护，不会自动重读磁盘文件，若需 v2rayN 托盘与底栏状态完全同步，请在 v2rayN 底栏手动将系统代理切换为「{0}」，或直接重启 v2rayN。"
        };

        private static readonly Dictionary<string, string> StringsEn = new Dictionary<string, string>
        {
            ["AppTitle"] = "AI-Net-Guard v5.7.3 — Windows Kernel Leak Shield & Smart Split-Tunneling",
            ["HeaderVersionBadge"] = "v5.7.3 Native Desktop",
            ["HeaderSubtitle"] = "Windows Kernel WFP Fail-Closed Leak Shield · Domestic Direct Whitelist · Zero-RAM Event-Triggered Center",
            ["RescueBtn"] = "Rescue",
            ["RescueBtnToolTip"] = "Instantly reset Windows native networking and release all kernel intercepts in an emergency",
            ["OpenDirBtn"] = "Open Folder",
            ["RefreshBtn"] = "Refresh",
            ["LangSwitchBtn"] = "中文",
            ["LangSwitchBtnToolTip"] = "Switch to Chinese interface (切换为中文界面)",

            // Status Badges
            ["StatusReading"] = "Reading system status...",
            ["StatusStrictActive"] = "Strict Global Lock Active (Zero Direct)",
            ["StatusTestingPeriod"] = "Guard Running (Testing Period)",
            ["StatusRunning"] = "Kernel Static Guard Active",
            ["StatusNotDeployed"] = "Not Deployed (Original System State)",

            // Cards
            ["CardFirewallTitle"] = "Kernel Firewall & Anti-Drift",
            ["CardFirewallBlock"] = "Default Outbound Block (Active)",
            ["CardFirewallAllow"] = "Default Outbound Allow (Unmanaged)",
            ["CardFirewallCnPrefixes"] = "CN Whitelist ({0} prefixes)",
            ["CardFirewallCnActive"] = "CN Whitelist Active",
            ["CardFirewallCnOff"] = "CN Direct Disabled",
            ["CardFirewallCnNone"] = "Whitelist Not Installed",
            ["CardFirewallRogue"] = "{0} Rogue Allows",

            ["CardTunTitle"] = "TUN Adapter & Core",
            ["CardTunOnline"] = "Tunnel Online ({0})",
            ["CardTunOffline"] = "TUN Inactive",
            ["CardTunCoreOnline"] = "Core: {0} (Online)",
            ["CardTunCoreOffline"] = "Core: Stopped",

            ["CardNodeTitle"] = "Active Proxy Node",
            ["SyncNow"] = "Sync",
            ["CardNodeNone"] = "No Allowed Node Detected",
            ["CardNodeRuleValid"] = "Rule Valid · Outbound Allowed",
            ["CardNodeRuleMissing"] = "Rule Missing or Disabled",
            ["CardNodeMaskTip"] = "Click to toggle mask/unmask node IP",

            ["CardDnsTitle"] = "DNS Shield & Zero-RAM",
            ["CardDnsNrpt"] = "Strict NRPT (1.1.1.1)",
            ["CardDnsSummary"] = "DNS: {0}",
            ["CardDnsSmhnrOff"] = "SMHNR Disabled",
            ["CardDnsSmhnrOn"] = "SMHNR Default",
            ["CardDnsZeroResidentReady"] = "0 MB Event-Triggered",
            ["CardDnsZeroResidentNone"] = "No Background Task",
            ["CardDnsAclLocked"] = "Install ACL Tamper-Locked",
            ["CardDnsAclUnlocked"] = "Install ACL Not Locked",
            ["CardDnsAclNotice"] = "Auto-bind node and lock ACL on deploy",

            // v2rayN Row
            ["V2rayNPathLabel"] = "v2rayN Path:",
            ["BrowseBtn"] = "Browse...",
            ["V2rayNValid"] = "Config Detected",
            ["V2rayNInvalid"] = "Config Not Found",

            // System Proxy Banner
            ["SystemProxyOn"] = "Windows System Proxy: Enabled at {0} (WinINET proxy active, clearing is recommended if TUN is ON)",
            ["SystemProxyOff"] = "Windows System Proxy: Cleared (ProxyEnable=0 · Official Recommended Pure State, TUN Kernel Routing, 0 WinINET Conflicts)",
            ["ClearSysProxyBtnOff"] = "Restore to Official Recommended (Clear Proxy)",
            ["ClearSysProxyBtnOn"] = "Temporarily Enable System Proxy",

            // Presets
            ["PresetsTitle"] = "Security Presets",
            ["ResetRecommendedBtn"] = "Restore Recommended Defaults",
            ["Preset1Title"] = "Recommended Daily Guard",
            ["Preset1Badge"] = "Recommended",
            ["Preset2Title"] = "Strict Global Lock",
            ["Preset2Badge"] = "Zero Direct",
            ["Preset3Title"] = "Developer / Compatible",
            ["Preset3Badge"] = "Keep IPv6",
            ["PresetDescRecommended"] = "Recommended Daily Guard Mode: Enables all 14 recommended hardening features. Domestic traffic connects directly at full speed, overseas traffic is strictly forced through TUN, node switching is auto-synced, and 0 MB RAM footprint with event self-healing.",
            ["PresetDescStrict"] = "Strict Global Lock Mode: Disables CN direct whitelist and NCSI probe. If TUN disconnects or proxy node fails, all traffic (including domestic sites) is 100% physically blocked with zero leak window.",
            ["PresetDescCompatible"] = "Developer Compatible Mode: Keeps physical NIC IPv6 enabled on top of recommended features. Suitable for local IPv6 dev/test environments (Note: may leak if ISP IPv6 is unrouted).",
            ["PresetDescCustom"] = "Custom Configuration: Current options differ from standard presets (contains manual tweaks). Click 'Restore Recommended Defaults' to reset.",

            // Foundation Banner
            ["FoundationTitle"] = "Kernel Static Guard Baseline (Permanently active during deployment):",
            ["FoundationText"] = "Windows Firewall DefaultOutbound=Block across all 3 profiles + TUN adapter allow + Authorized proxy node / AliDNS DoH / DHCP allow rules. Even if proxy process crashes, kernel intercepts in 0 ms with zero leak window. To completely remove the baseline, click 'Full Uninstall' at bottom-left.",

            // Console
            ["ToggleConsoleExpand"] = "▶ Live Execution Console (Auto-expands on Deploy / Test / Uninstall)",
            ["ToggleConsoleCollapse"] = "▼ Live Execution Console (Click to collapse)",
            ["CopyLogBtn"] = "Copy Log",
            ["ClearLogBtn"] = "Clear",

            // Bottom Actions
            ["UninstallBtn"] = "Full Uninstall",
            ["UninstallBtnToolTip"] = "Reversibly restores original Windows firewall, DNS, IPv6, and scheduled tasks",
            ["RegressionBtn"] = "Full Regression (24)",
            ["RegressionBtnToolTip"] = "Run 24-check full regression suite with live 10-second packet capture",
            ["LeakCheckBtn"] = "Quick Check (5s)",
            ["LeakCheckBtnToolTip"] = "5-second quick check: physical NIC raw socket direct outbound block, active TUN adapter, and overseas connectivity",
            ["FooterHintReady"] = "Ready",
            ["ApplyBtn"] = "Deploy / Apply Configuration",

            // Modals & Messages
            ["Confirm"] = "Confirm",
            ["Cancel"] = "Cancel",
            ["ConfirmModalSubtitle"] = "AI-Net-Guard Native Confirmation",
            ["DeployConfirmTitle"] = "Confirm Guard Deployment",
            ["DeployConfirmMsg"] = "About to apply the current security policy to Windows kernel WFP firewall and network stack.\n\nDeployment takes ~3-5 seconds and will auto-sync proxy node rules and flush DNS cache.\n\nProceed now?",
            ["UninstallConfirmTitle"] = "High Risk Action — Confirm Full Uninstall",
            ["UninstallConfirmMsg"] = "This operation performs a complete security rollback:\n\n1. Restores Windows Firewall DefaultOutbound=Allow\n2. Deletes all AI-Guard-* rules\n3. Restores physical NIC original DNS and IPv6 bindings\n4. Removes scheduled tasks and install directory ACL lock\n\nAre you sure you want to fully uninstall?",
            ["RescueConfirmTitle"] = "Confirm Emergency Rescue",
            ["RescueConfirmMsg"] = "Emergency rescue will immediately reset all Windows firewall blocks and restore DHCP DNS auto-acquire to recover connectivity in an emergency.\n\nExecute emergency rescue now?",
            ["StrictNrptConfirmTitle"] = "Advanced Feature Confirmation — Strict Global NRPT DoH",
            ["StrictNrptConfirmMsg"] = "After enabling Strict Global NRPT DoH (1.1.1.1):\n\n• All system DNS will strictly use encrypted 1.1.1.1 without UDP fallback;\n• If the proxy TUN adapter is not running, domestic and foreign domains cannot be resolved;\n• Recommended only for users running TUN 24/7.\n\nDo you want to proceed?",
            ["V2rayNNoticeTitle"] = "Notice: v2rayN is Running",
            ["V2rayNNoticeMsg"] = "Windows system proxy registry settings have been updated.\n\nNote that v2rayN manages its bottom toolbar state in-memory while running and does not reload disk files dynamically. To synchronize v2rayN's UI, please manually set its bottom proxy dropdown to '{0}', or restart v2rayN."
        };

        public static string T(string key, params object[] args)
        {
            var dict = _currentLanguage == AppLanguage.En ? StringsEn : StringsZh;
            if (!dict.TryGetValue(key, out string val))
            {
                if (!StringsZh.TryGetValue(key, out val))
                {
                    val = key;
                }
            }
            if (args != null && args.Length > 0)
            {
                try
                {
                    return string.Format(val, args);
                }
                catch
                {
                    return val;
                }
            }
            return val;
        }
    }
}
