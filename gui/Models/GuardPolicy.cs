using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Xml;

namespace AiNetGuard.Gui.Models
{
    [DataContract]
    public sealed class GuardPolicy : INotifyPropertyChanged
    {
        private string _version = "5.5";
        private string _preset = "Recommended";
        private string _dnsServer = "223.5.5.5";
        private string _v2rayNRoot = "";
        private string _updatedAt = "";

        private bool _allowCnDirect = true;
        private bool _allowLan = true;
        private bool _allowNcsi = true;
        private bool _quarantineRogueAllow = true;
        private bool _lockPhysicalDns = true;
        private bool _disableSmhnr = true;
        private bool _disableLlmnrNetbios = true;
        private bool _strictNrptDoh = false;
        private bool _disablePhysicalIpv6 = true;
        private bool _preferIpv4Prefix = true;
        private bool _zeroResidentMonitor = true;
        private bool _autoNodeSync = true;
        private bool _autoHealStaleProxy = true;
        private bool _domesticNtp = true;
        private bool _hardenInstallAcl = true;

        public event PropertyChangedEventHandler PropertyChanged;

        [DataMember(Name = "Version", Order = 1)]
        public string Version { get => _version; set => SetField(ref _version, value); }

        [DataMember(Name = "Preset", Order = 2)]
        public string Preset { get => _preset; set => SetField(ref _preset, value); }

        [DataMember(Name = "DnsServer", Order = 3)]
        public string DnsServer { get => _dnsServer; set => SetField(ref _dnsServer, value); }

        [DataMember(Name = "V2rayNRoot", Order = 4)]
        public string V2rayNRoot { get => _v2rayNRoot; set => SetField(ref _v2rayNRoot, value); }

        [DataMember(Name = "AllowCnDirect", Order = 10)]
        public bool AllowCnDirect { get => _allowCnDirect; set => SetToggle(ref _allowCnDirect, value); }

        [DataMember(Name = "AllowLan", Order = 11)]
        public bool AllowLan { get => _allowLan; set => SetToggle(ref _allowLan, value); }

        [DataMember(Name = "AllowNcsi", Order = 12)]
        public bool AllowNcsi { get => _allowNcsi; set => SetToggle(ref _allowNcsi, value); }

        [DataMember(Name = "QuarantineRogueAllow", Order = 13)]
        public bool QuarantineRogueAllow { get => _quarantineRogueAllow; set => SetToggle(ref _quarantineRogueAllow, value); }

        [DataMember(Name = "LockPhysicalDns", Order = 20)]
        public bool LockPhysicalDns { get => _lockPhysicalDns; set => SetToggle(ref _lockPhysicalDns, value); }

        [DataMember(Name = "DisableSmhnr", Order = 21)]
        public bool DisableSmhnr { get => _disableSmhnr; set => SetToggle(ref _disableSmhnr, value); }

        [DataMember(Name = "DisableLlmnrNetbios", Order = 22)]
        public bool DisableLlmnrNetbios { get => _disableLlmnrNetbios; set => SetToggle(ref _disableLlmnrNetbios, value); }

        [DataMember(Name = "StrictNrptDoh", Order = 23)]
        public bool StrictNrptDoh
        {
            get => _strictNrptDoh;
            set
            {
                if (SetToggle(ref _strictNrptDoh, value) && value && !_lockPhysicalDns)
                {
                    LockPhysicalDns = true;
                }
            }
        }

        [DataMember(Name = "DisablePhysicalIpv6", Order = 30)]
        public bool DisablePhysicalIpv6 { get => _disablePhysicalIpv6; set => SetToggle(ref _disablePhysicalIpv6, value); }

        [DataMember(Name = "PreferIpv4Prefix", Order = 31)]
        public bool PreferIpv4Prefix { get => _preferIpv4Prefix; set => SetToggle(ref _preferIpv4Prefix, value); }

        [DataMember(Name = "ZeroResidentMonitor", Order = 40)]
        public bool ZeroResidentMonitor { get => _zeroResidentMonitor; set => SetToggle(ref _zeroResidentMonitor, value); }

        [DataMember(Name = "AutoNodeSync", Order = 41)]
        public bool AutoNodeSync { get => _autoNodeSync; set => SetToggle(ref _autoNodeSync, value); }

        [DataMember(Name = "AutoHealStaleProxy", Order = 42)]
        public bool AutoHealStaleProxy { get => _autoHealStaleProxy; set => SetToggle(ref _autoHealStaleProxy, value); }

        [DataMember(Name = "DomesticNtp", Order = 43)]
        public bool DomesticNtp { get => _domesticNtp; set => SetToggle(ref _domesticNtp, value); }

        [DataMember(Name = "HardenInstallAcl", Order = 44)]
        public bool HardenInstallAcl { get => _hardenInstallAcl; set => SetToggle(ref _hardenInstallAcl, value); }

        [DataMember(Name = "UpdatedAt", Order = 50)]
        public string UpdatedAt { get => _updatedAt; set => SetField(ref _updatedAt, value); }

        public static GuardPolicy CreateDisabled(string v2rayNRoot = "")
        {
            return new GuardPolicy
            {
                Version = "5.5",
                Preset = "None",
                DnsServer = "223.5.5.5",
                V2rayNRoot = v2rayNRoot ?? "",
                AllowCnDirect = false,
                AllowLan = false,
                AllowNcsi = false,
                QuarantineRogueAllow = false,
                LockPhysicalDns = false,
                DisableSmhnr = false,
                DisableLlmnrNetbios = false,
                StrictNrptDoh = false,
                DisablePhysicalIpv6 = false,
                PreferIpv4Prefix = false,
                ZeroResidentMonitor = false,
                AutoNodeSync = false,
                AutoHealStaleProxy = false,
                DomesticNtp = false,
                HardenInstallAcl = false,
                UpdatedAt = DateTime.Now.ToString("o")
            };
        }

        public static GuardPolicy CreateRecommended(string v2rayNRoot = "")
        {
            return new GuardPolicy
            {
                Version = "5.5",
                Preset = "Recommended",
                DnsServer = "223.5.5.5",
                V2rayNRoot = v2rayNRoot ?? "",
                AllowCnDirect = true,
                AllowLan = true,
                AllowNcsi = true,
                QuarantineRogueAllow = true,
                LockPhysicalDns = true,
                DisableSmhnr = true,
                DisableLlmnrNetbios = true,
                StrictNrptDoh = false,
                DisablePhysicalIpv6 = true,
                PreferIpv4Prefix = true,
                ZeroResidentMonitor = true,
                AutoNodeSync = true,
                AutoHealStaleProxy = true,
                DomesticNtp = true,
                HardenInstallAcl = true,
                UpdatedAt = DateTime.Now.ToString("o")
            };
        }

        public void DisableAll()
        {
            AllowCnDirect = false;
            AllowLan = false;
            AllowNcsi = false;
            QuarantineRogueAllow = false;
            LockPhysicalDns = false;
            DisableSmhnr = false;
            DisableLlmnrNetbios = false;
            StrictNrptDoh = false;
            DisablePhysicalIpv6 = false;
            PreferIpv4Prefix = false;
            ZeroResidentMonitor = false;
            AutoNodeSync = false;
            AutoHealStaleProxy = false;
            DomesticNtp = false;
            HardenInstallAcl = false;
            Preset = "None";
            UpdatedAt = DateTime.Now.ToString("o");
        }

        public void ApplyPreset(string presetKey)
        {
            if (string.Equals(presetKey, "StrictLock", StringComparison.OrdinalIgnoreCase))
            {
                AllowCnDirect = false;
                AllowLan = true;
                AllowNcsi = false;
                QuarantineRogueAllow = true;
                LockPhysicalDns = true;
                DisableSmhnr = true;
                DisableLlmnrNetbios = true;
                StrictNrptDoh = false;
                DisablePhysicalIpv6 = true;
                PreferIpv4Prefix = true;
                ZeroResidentMonitor = true;
                AutoNodeSync = true;
                AutoHealStaleProxy = true;
                DomesticNtp = true;
                HardenInstallAcl = true;
                Preset = "StrictLock";
            }
            else if (string.Equals(presetKey, "Compatible", StringComparison.OrdinalIgnoreCase))
            {
                AllowCnDirect = true;
                AllowLan = true;
                AllowNcsi = true;
                QuarantineRogueAllow = true;
                LockPhysicalDns = true;
                DisableSmhnr = true;
                DisableLlmnrNetbios = false;
                StrictNrptDoh = false;
                DisablePhysicalIpv6 = false;
                PreferIpv4Prefix = true;
                ZeroResidentMonitor = true;
                AutoNodeSync = true;
                AutoHealStaleProxy = true;
                DomesticNtp = true;
                HardenInstallAcl = true;
                Preset = "Compatible";
            }
            else
            {
                AllowCnDirect = true;
                AllowLan = true;
                AllowNcsi = true;
                QuarantineRogueAllow = true;
                LockPhysicalDns = true;
                DisableSmhnr = true;
                DisableLlmnrNetbios = true;
                StrictNrptDoh = false;
                DisablePhysicalIpv6 = true;
                PreferIpv4Prefix = true;
                ZeroResidentMonitor = true;
                AutoNodeSync = true;
                AutoHealStaleProxy = true;
                DomesticNtp = true;
                HardenInstallAcl = true;
                Preset = "Recommended";
            }
        }

        public string ComputePresetKey()
        {
            if (AllowCnDirect && AllowLan && AllowNcsi && QuarantineRogueAllow &&
                LockPhysicalDns && DisableSmhnr && DisableLlmnrNetbios && !StrictNrptDoh &&
                DisablePhysicalIpv6 && PreferIpv4Prefix && ZeroResidentMonitor &&
                AutoNodeSync && AutoHealStaleProxy && DomesticNtp && HardenInstallAcl)
            {
                return "Recommended";
            }

            if (!AllowCnDirect && AllowLan && !AllowNcsi && QuarantineRogueAllow &&
                LockPhysicalDns && DisableSmhnr && DisableLlmnrNetbios &&
                DisablePhysicalIpv6 && PreferIpv4Prefix && ZeroResidentMonitor &&
                AutoNodeSync && AutoHealStaleProxy && DomesticNtp && HardenInstallAcl)
            {
                return "StrictLock";
            }

            if (AllowCnDirect && AllowLan && AllowNcsi && QuarantineRogueAllow &&
                LockPhysicalDns && DisableSmhnr && !DisableLlmnrNetbios && !StrictNrptDoh &&
                !DisablePhysicalIpv6 && PreferIpv4Prefix && ZeroResidentMonitor &&
                AutoNodeSync && AutoHealStaleProxy && DomesticNtp && HardenInstallAcl)
            {
                return "Compatible";
            }

            return "Custom";
        }

        public GuardPolicy Clone()
        {
            return new GuardPolicy
            {
                Version = Version,
                Preset = Preset,
                DnsServer = DnsServer,
                V2rayNRoot = V2rayNRoot,
                AllowCnDirect = AllowCnDirect,
                AllowLan = AllowLan,
                AllowNcsi = AllowNcsi,
                QuarantineRogueAllow = QuarantineRogueAllow,
                LockPhysicalDns = LockPhysicalDns,
                DisableSmhnr = DisableSmhnr,
                DisableLlmnrNetbios = DisableLlmnrNetbios,
                StrictNrptDoh = StrictNrptDoh,
                DisablePhysicalIpv6 = DisablePhysicalIpv6,
                PreferIpv4Prefix = PreferIpv4Prefix,
                ZeroResidentMonitor = ZeroResidentMonitor,
                AutoNodeSync = AutoNodeSync,
                AutoHealStaleProxy = AutoHealStaleProxy,
                DomesticNtp = DomesticNtp,
                HardenInstallAcl = HardenInstallAcl,
                UpdatedAt = UpdatedAt
            };
        }

        public int CountDifferences(GuardPolicy other)
        {
            if (other == null) return 15;
            int diffs = 0;
            if (AllowCnDirect != other.AllowCnDirect) diffs++;
            if (AllowLan != other.AllowLan) diffs++;
            if (AllowNcsi != other.AllowNcsi) diffs++;
            if (QuarantineRogueAllow != other.QuarantineRogueAllow) diffs++;
            if (LockPhysicalDns != other.LockPhysicalDns) diffs++;
            if (DisableSmhnr != other.DisableSmhnr) diffs++;
            if (DisableLlmnrNetbios != other.DisableLlmnrNetbios) diffs++;
            if (StrictNrptDoh != other.StrictNrptDoh) diffs++;
            if (DisablePhysicalIpv6 != other.DisablePhysicalIpv6) diffs++;
            if (PreferIpv4Prefix != other.PreferIpv4Prefix) diffs++;
            if (ZeroResidentMonitor != other.ZeroResidentMonitor) diffs++;
            if (AutoNodeSync != other.AutoNodeSync) diffs++;
            if (AutoHealStaleProxy != other.AutoHealStaleProxy) diffs++;
            if (DomesticNtp != other.DomesticNtp) diffs++;
            if (HardenInstallAcl != other.HardenInstallAcl) diffs++;
            if (!string.Equals((V2rayNRoot ?? "").TrimEnd('\\'), (other.V2rayNRoot ?? "").TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) diffs++;
            return diffs;
        }

        public bool GetFlag(string key)
        {
            switch (key)
            {
                case "AllowCnDirect": return AllowCnDirect;
                case "AllowLan": return AllowLan;
                case "AllowNcsi": return AllowNcsi;
                case "QuarantineRogueAllow": return QuarantineRogueAllow;
                case "LockPhysicalDns": return LockPhysicalDns;
                case "DisableSmhnr": return DisableSmhnr;
                case "DisableLlmnrNetbios": return DisableLlmnrNetbios;
                case "StrictNrptDoh": return StrictNrptDoh;
                case "DisablePhysicalIpv6": return DisablePhysicalIpv6;
                case "PreferIpv4Prefix": return PreferIpv4Prefix;
                case "ZeroResidentMonitor": return ZeroResidentMonitor;
                case "AutoNodeSync": return AutoNodeSync;
                case "AutoHealStaleProxy": return AutoHealStaleProxy;
                case "DomesticNtp": return DomesticNtp;
                case "HardenInstallAcl": return HardenInstallAcl;
                default: return false;
            }
        }

        public void SetFlag(string key, bool value)
        {
            switch (key)
            {
                case "AllowCnDirect": AllowCnDirect = value; break;
                case "AllowLan": AllowLan = value; break;
                case "AllowNcsi": AllowNcsi = value; break;
                case "QuarantineRogueAllow": QuarantineRogueAllow = value; break;
                case "LockPhysicalDns": LockPhysicalDns = value; break;
                case "DisableSmhnr": DisableSmhnr = value; break;
                case "DisableLlmnrNetbios": DisableLlmnrNetbios = value; break;
                case "StrictNrptDoh": StrictNrptDoh = value; break;
                case "DisablePhysicalIpv6": DisablePhysicalIpv6 = value; break;
                case "PreferIpv4Prefix": PreferIpv4Prefix = value; break;
                case "ZeroResidentMonitor": ZeroResidentMonitor = value; break;
                case "AutoNodeSync": AutoNodeSync = value; break;
                case "AutoHealStaleProxy": AutoHealStaleProxy = value; break;
                case "DomesticNtp": DomesticNtp = value; break;
                case "HardenInstallAcl": HardenInstallAcl = value; break;
            }
        }

        public string ToJson()
        {
            Version = "5.5";
            Preset = ComputePresetKey();
            UpdatedAt = DateTime.Now.ToString("o");
            var serializer = new DataContractJsonSerializer(typeof(GuardPolicy));
            using (var ms = new MemoryStream())
            {
                using (XmlDictionaryWriter writer = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, false, true, "  "))
                {
                    serializer.WriteObject(writer, this);
                    writer.Flush();
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public void SaveToFile(string filePath)
        {
            string dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(filePath, ToJson(), new UTF8Encoding(false));
        }

        public static GuardPolicy LoadFromFileOrNull(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;
            try
            {
                byte[] bytes = File.ReadAllBytes(filePath);
                // Strip UTF-8 BOM if present
                int offset = (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) ? 3 : 0;
                var serializer = new DataContractJsonSerializer(typeof(GuardPolicy));
                using (var ms = new MemoryStream(bytes, offset, bytes.Length - offset))
                {
                    var loaded = serializer.ReadObject(ms) as GuardPolicy;
                    if (loaded != null)
                    {
                        if (string.IsNullOrEmpty(loaded.DnsServer)) loaded.DnsServer = "223.5.5.5";
                        if (string.IsNullOrEmpty(loaded.Version)) loaded.Version = "5.5";
                        loaded.Preset = loaded.ComputePresetKey();
                    }
                    return loaded;
                }
            }
            catch
            {
                return null;
            }
        }

        private bool SetField<T>(ref T field, T value, [CallerMemberName] string propName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
            return true;
        }

        private bool SetToggle(ref bool field, bool value, [CallerMemberName] string propName = null)
        {
            if (field == value) return false;
            field = value;
            _preset = ComputePresetKey();
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Preset)));
            return true;
        }
    }

    public sealed class FeatureToggleItem
    {
        public string Category { get; set; }
        public string Key { get; set; }
        public string Title { get; set; }
        public string BadgeText { get; set; }
        public bool IsRecommended { get; set; }
        public string Summary { get; set; }
    }

    public static class FeatureCatalog
    {
        public static IReadOnlyList<FeatureToggleItem> All { get; } = new List<FeatureToggleItem>
        {
            new FeatureToggleItem
            {
                Category = "一、流量分流与防火墙边界 (Traffic & Firewall Boundary)",
                Key = "AllowCnDirect",
                Title = "中国大陆 IPv4 直连白名单 (AI-Guard-Allow-CN)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "国内网站、微信、游戏免代理满速直连，仅严防海外流量明文泄漏；若关闭此项则进入“严格全局铁桶锁”（关闭 TUN 时国内网也会一并阻断）。"
            },
            new FeatureToggleItem
            {
                Category = "一、流量分流与防火墙边界 (Traffic & Firewall Boundary)",
                Key = "AllowLan",
                Title = "局域网设备互访 (LAN / LocalSubnet)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "允许访问同一路由器下的 NAS、局域网打印机、无线投屏与路由器管理后台（192.168.x.x）；在机场或咖啡厅公共 Wi-Fi 下可关闭以彻底隔离内网。"
            },
            new FeatureToggleItem
            {
                Category = "一、流量分流与防火墙边界 (Traffic & Firewall Boundary)",
                Key = "AllowNcsi",
                Title = "Windows 联网状态图标探测放行 (NCSI)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "仅精准放行微软联网检测探针（13.107.4.52:80），避免关闭代理时任务栏右下角误报“无 Internet 小地球”导致 Office 与微软商店拒绝联网。"
            },
            new FeatureToggleItem
            {
                Category = "一、流量分流与防火墙边界 (Traffic & Firewall Boundary)",
                Key = "QuarantineRogueAllow",
                Title = "自动隔离第三方软件私自添加的出站放行规则 (防规则漂移)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "Windows 防火墙中任何第三方出站 Allow 规则都会架空默认拦截；开启后自动冻结其他软件静默植入的出站放行规则（关闭或卸载时原样恢复）。"
            },

            new FeatureToggleItem
            {
                Category = "二、DNS 防污染与防泄漏护盾 (DNS & Leak-Shield Hardening)",
                Key = "LockPhysicalDns",
                Title = "锁定物理网卡安全静态 DNS (223.5.5.5)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "防止路由器 DHCP 下发运营商劫持 DNS；开启代理时 53 端口自动被 TUN 接管走加密 DoH，关闭代理时也能在大陆白名单内安全解析国内域名。"
            },
            new FeatureToggleItem
            {
                Category = "二、DNS 防污染与防泄漏护盾 (DNS & Leak-Shield Hardening)",
                Key = "DisableSmhnr",
                Title = "禁用 Windows 智能多宿主并行 DNS 抢答 (SMHNR)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "阻止 Windows 11 在开启代理时同时向物理网卡和 TUN 虚拟网卡并发喷射 DNS 查询，将物理网卡明文 53 端口尝试次数彻底压降至 0。"
            },
            new FeatureToggleItem
            {
                Category = "二、DNS 防污染与防泄漏护盾 (DNS & Leak-Shield Hardening)",
                Key = "DisableLlmnrNetbios",
                Title = "禁用局域网多播与广播名称解析 (LLMNR & NetBIOS)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "关闭陈旧的局域网广播域名解析协议，既防止未命中域名泄漏到局域网，也能免疫局域网内常见的 LLMNR / NBT-NS 欺骗劫持攻击。"
            },
            new FeatureToggleItem
            {
                Category = "二、DNS 防污染与防泄漏护盾 (DNS & Leak-Shield Hardening)",
                Key = "StrictNrptDoh",
                Title = "严格系统级全局 DoH 强制加密 (NRPT 1.1.1.1 · 禁 UDP 回退)",
                BadgeText = "高级可选 · 默认关闭",
                IsRecommended = false,
                Summary = "强制全系统所有域名仅通过 1.1.1.1 DoH 解析；注意：开启后一旦关闭 TUN 代理，国内网页也将无法解析域名（仅建议 24 小时常开 TUN 的用户开启）。"
            },

            new FeatureToggleItem
            {
                Category = "三、IPv6 防绕过与双栈连接加速 (IPv6 & Dual-Stack Speed)",
                Key = "DisablePhysicalIpv6",
                Title = "禁用物理网卡 IPv6 协议栈绑定 (ms_tcpip6)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "彻底堵死浏览器或应用通过运营商原生 IPv6 绕过 IPv4 TUN 隧道直连海外的严重泄漏隐患（含手机 USB 共享网络等热插拔网卡自动防护）。"
            },
            new FeatureToggleItem
            {
                Category = "三、IPv6 防绕过与双栈连接加速 (IPv6 & Dual-Stack Speed)",
                Key = "PreferIpv4Prefix",
                Title = "提升 IPv4 双栈寻址优先级高于 IPv6 (::ffff:0:0/96 > ::/0)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "让系统及 Python / Git / Node 等命令行开发工具优先请求 IPv4，彻底消除因等待 IPv6 AAAA 超时导致的每次联网前卡顿 2~5 秒问题。"
            },

            new FeatureToggleItem
            {
                Category = "四、零驻留自愈、多核联动与防篡改加固 (Automation & Tamper-Lock)",
                Key = "ZeroResidentMonitor",
                Title = "零内存事件触发与合盖睡眠唤醒自愈 (0 MB 后台常驻)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "平时后台 0 进程、0 MB 内存占用；仅在网络切换、开机、笔记本睡眠唤醒时由系统事件毫秒级唤醒自检并刷新污染 DNS 缓存。"
            },
            new FeatureToggleItem
            {
                Category = "四、零驻留自愈、多核联动与防篡改加固 (Automation & Tamper-Lock)",
                Key = "AutoNodeSync",
                Title = "多内核代理节点与端口自动热同步 (Xray / sing-box / Hysteria2)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "在 v2rayN 中切换节点、更换协议（如 VLESS 切 Hysteria2 端口跳跃）或切换代理内核时，自动识别并更新防火墙放行节点 IP 与端口。"
            },
            new FeatureToggleItem
            {
                Category = "四、零驻留自愈、多核联动与防篡改加固 (Automation & Tamper-Lock)",
                Key = "AutoHealStaleProxy",
                Title = "代理异常退出/断电后残留死系统代理自动修复",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "当代理软件崩溃或关机未正常退出导致系统残留失效的 127.0.0.1 本地代理（引发开机后浏览器全部报错打不开网页）时自动清理恢复。"
            },
            new FeatureToggleItem
            {
                Category = "四、零驻留自愈、多核联动与防篡改加固 (Automation & Tamper-Lock)",
                Key = "DomesticNtp",
                Title = "国内高可用时间同步加固 (阿里云/腾讯云/中科院授时)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "解决默认 time.windows.com 在未开代理时被拦截，导致电脑睡眠后时钟偏差超过 90 秒、引发 VLESS+REALITY 节点握手死锁连不上的痛点。"
            },
            new FeatureToggleItem
            {
                Category = "四、零驻留自愈、多核联动与防篡改加固 (Automation & Tamper-Lock)",
                Key = "HardenInstallAcl",
                Title = "安装目录防篡改权限锁定 (C:\\AI-Net-Guard 管理员只写 ACL)",
                BadgeText = "推荐开启",
                IsRecommended = true,
                Summary = "将防护安装目录锁定为仅系统管理员 (Administrators/SYSTEM) 可修改，防止普通权限恶意程序篡改白名单规则或借系统计划任务提权。"
            }
        };
    }
}
