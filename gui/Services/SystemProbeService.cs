using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using AiNetGuard.Gui.Models;
using Microsoft.Win32;

namespace AiNetGuard.Gui.Services
{
    public sealed class LiveSystemSnapshot
    {
        public bool IsAdmin { get; set; }
        public string InstallRoot { get; set; }
        public bool InstallScriptsPresent { get; set; }
        public bool BaselineExists { get; set; }
        public bool IsDeployed { get; set; }
        public bool ProfilesAllBlock { get; set; }

        public bool TunUp { get; set; }
        public string ActiveTunName { get; set; } = "";
        public string RunningCoreSummary { get; set; } = "未运行";

        public bool CnRuleActive { get; set; }
        public int CnPrefixCount { get; set; }
        public bool TunRuleActive { get; set; }
        public bool NodeRuleActive { get; set; }
        public bool LanRuleActive { get; set; }
        public bool NcsiRuleActive { get; set; }
        public string NodeSummary { get; set; } = "尚未绑定节点";
        public int RogueAllowCount { get; set; }

        public string PhysicalNicName { get; set; } = "未连接";
        public string PhysicalDnsSummary { get; set; } = "-";
        public bool PhysicalDnsLocked { get; set; }
        public bool PhysicalIpv6Disabled { get; set; }

        public bool LlmnrDisabled { get; set; }
        public bool SmhnrDisabled { get; set; }
        public bool NrptActive { get; set; }
        public bool PreferIpv4Active { get; set; }
        public bool DomesticNtpActive { get; set; }

        public bool ZeroResidentTaskReady { get; set; }
        public bool PendingTestRollbackTask { get; set; }
        public bool AclLocked { get; set; }

        public bool SystemProxyEnabled { get; set; }
        public string SystemProxyServer { get; set; } = "";

        public string DetectedV2rayNRoot { get; set; } = "";
        public bool V2rayNConfigExists { get; set; }
        public bool AnyTunAdapterCreated { get; set; }
    }

    public static class SystemProbeService
    {
        private static readonly string[] KnownTunNames = { "xray_tun", "singbox_tun", "mihomo_tun", "Meta", "Mihomo" };
        private static readonly string[] CoreProcessNames = { "xray", "sing-box", "mihomo", "mihomo-windows-amd64-v1" };
        private static readonly HashSet<string> TrustedSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-5-32-544", // BUILTIN\Administrators
            "S-1-5-18",     // NT AUTHORITY\SYSTEM
            "S-1-3-0",      // CREATOR OWNER
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
        };

        public static bool IsCurrentProcessAdmin()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(id);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        public static string DiscoverV2rayNRoot(string preferredPath = "")
        {
            if (!string.IsNullOrWhiteSpace(preferredPath) && IsValidV2rayNDir(preferredPath))
            {
                return preferredPath.TrimEnd('\\');
            }

            string envRoot = Environment.GetEnvironmentVariable("V2RAYN_ROOT");
            if (!string.IsNullOrWhiteSpace(envRoot) && IsValidV2rayNDir(envRoot))
            {
                return envRoot.TrimEnd('\\');
            }

            try
            {
                foreach (Process p in Process.GetProcessesByName("v2rayN"))
                {
                    try
                    {
                        string exe = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exe))
                        {
                            string dir = Path.GetDirectoryName(exe);
                            if (IsValidV2rayNDir(dir)) return dir;
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var candidates = new List<string>
            {
                @"C:\v2rayN-windows-64",
                @"D:\v2rayN-windows-64",
                @"E:\v2rayN-windows-64",
                @"C:\v2rayN",
                @"D:\v2rayN",
                @"E:\v2rayN",
                Path.Combine(localAppData, "v2rayN"),
                @"C:\Program Files\v2rayN"
            };

            foreach (string cand in candidates)
            {
                if (IsValidV2rayNDir(cand)) return cand;
            }

            return !string.IsNullOrWhiteSpace(preferredPath) ? preferredPath.TrimEnd('\\') : @"C:\v2rayN-windows-64";
        }

        public static bool IsValidV2rayNDir(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return false;
            return File.Exists(Path.Combine(dir, "v2rayN.exe")) ||
                   Directory.Exists(Path.Combine(dir, "binConfigs"));
        }

        public static LiveSystemSnapshot Probe(string installRoot = @"C:\AI-Net-Guard", string preferredV2rayNRoot = "")
        {
            var snap = new LiveSystemSnapshot
            {
                IsAdmin = IsCurrentProcessAdmin(),
                InstallRoot = installRoot
            };

            snap.InstallScriptsPresent = File.Exists(Path.Combine(installRoot, "07-mode.ps1"));
            snap.BaselineExists = File.Exists(Path.Combine(installRoot, @"backup\baseline.json"));

            // 1. Discover v2rayN
            string savedPolicyV2 = "";
            var savedPol = GuardPolicy.LoadFromFileOrNull(Path.Combine(installRoot, @"backup\guard-policy.json"));
            if (savedPol != null && !string.IsNullOrWhiteSpace(savedPol.V2rayNRoot))
            {
                savedPolicyV2 = savedPol.V2rayNRoot;
            }
            snap.DetectedV2rayNRoot = DiscoverV2rayNRoot(!string.IsNullOrWhiteSpace(preferredV2rayNRoot) ? preferredV2rayNRoot : savedPolicyV2);
            snap.V2rayNConfigExists = File.Exists(Path.Combine(snap.DetectedV2rayNRoot, @"binConfigs\config.json"));

            // 2. Firewall profiles & rules (fast pure registry pass)
            snap.ProfilesAllBlock = CheckFirewallProfilesAllBlock();
            ProbeFirewallRulesRegistry(installRoot, snap);

            // CN prefix count from cn-rule.sig
            try
            {
                string sigPath = Path.Combine(installRoot, @"backup\cn-rule.sig");
                if (File.Exists(sigPath))
                {
                    string sigText = File.ReadAllText(sigPath).Trim();
                    int colon = sigText.IndexOf(':');
                    if (colon > 0 && int.TryParse(sigText.Substring(0, colon), out int cnt))
                    {
                        snap.CnPrefixCount = cnt;
                    }
                }
            }
            catch { }

            snap.IsDeployed = snap.BaselineExists && (snap.ProfilesAllBlock || snap.TunRuleActive);

            // 3. Running core processes
            var coreList = new List<string>();
            foreach (string pn in CoreProcessNames)
            {
                try
                {
                    foreach (Process p in Process.GetProcessesByName(pn))
                    {
                        coreList.Add($"{p.ProcessName}:{p.Id}");
                        p.Dispose();
                    }
                }
                catch { }
            }
            snap.RunningCoreSummary = coreList.Count > 0 ? string.Join(", ", coreList) : "未运行";

            // 4. Network interfaces (TUN & Physical NICs; filter out NDIS filter pseudo-interfaces)
            ProbeNetworkInterfaces(snap);

            // 5. DNS policy (LLMNR, SMHNR, NRPT), IPv4 precedence, NTP
            ProbeRegistryPolicies(snap);

            // 6. Scheduled tasks (fast System32\Tasks check with fallback)
            string sysTasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            snap.ZeroResidentTaskReady =
                File.Exists(Path.Combine(sysTasksDir, "AI-Guard-Mode-Event")) ||
                File.Exists(Path.Combine(sysTasksDir, "AI-Guard-Mode-Watcher"));
            snap.PendingTestRollbackTask = File.Exists(Path.Combine(sysTasksDir, "AI-Guard-Test-Rollback"));

            // 7. Install directory ACL check
            snap.AclLocked = Directory.Exists(installRoot) && CheckInstallDirectoryLocked(installRoot);

            // 8. HKCU WinINET system proxy check
            try
            {
                using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false))
                {
                    if (rk != null)
                    {
                        object pe = rk.GetValue("ProxyEnable");
                        snap.SystemProxyEnabled = pe != null && Convert.ToInt32(pe) == 1;
                        snap.SystemProxyServer = Convert.ToString(rk.GetValue("ProxyServer") ?? "");
                    }
                }
            }
            catch { }

            return snap;
        }

        public static GuardPolicy LoadOrInferPolicy(string installRoot, LiveSystemSnapshot snap)
        {
            // If system is not currently deployed (e.g. after uninstall / rollback), show all switches as OFF
            if (snap != null && !snap.IsDeployed)
            {
                string stalePolicyPath = Path.Combine(installRoot, @"backup\guard-policy.json");
                if (File.Exists(stalePolicyPath))
                {
                    try { File.Delete(stalePolicyPath); } catch { }
                }
                return GuardPolicy.CreateDisabled(snap.DetectedV2rayNRoot ?? "");
            }

            string policyPath = Path.Combine(installRoot, @"backup\guard-policy.json");
            GuardPolicy existing = GuardPolicy.LoadFromFileOrNull(policyPath);
            if (existing != null)
            {
                if (string.IsNullOrWhiteSpace(existing.V2rayNRoot))
                {
                    existing.V2rayNRoot = snap.DetectedV2rayNRoot;
                }
                return existing;
            }

            if (snap != null && snap.IsDeployed)
            {
                var inferred = new GuardPolicy
                {
                    Version = "5.5",
                    DnsServer = snap.NrptActive ? "1.1.1.1" : "223.5.5.5",
                    V2rayNRoot = snap.DetectedV2rayNRoot,
                    AllowCnDirect = snap.CnRuleActive,
                    AllowLan = snap.LanRuleActive,
                    AllowNcsi = snap.NcsiRuleActive,
                    QuarantineRogueAllow = snap.RogueAllowCount == 0,
                    LockPhysicalDns = snap.PhysicalDnsLocked || snap.NrptActive,
                    DisableSmhnr = snap.SmhnrDisabled,
                    DisableLlmnrNetbios = snap.LlmnrDisabled,
                    StrictNrptDoh = snap.NrptActive,
                    DisablePhysicalIpv6 = snap.PhysicalIpv6Disabled,
                    PreferIpv4Prefix = snap.PreferIpv4Active,
                    ZeroResidentMonitor = snap.ZeroResidentTaskReady,
                    AutoNodeSync = true,
                    AutoHealStaleProxy = true,
                    DomesticNtp = snap.DomesticNtpActive,
                    HardenInstallAcl = snap.AclLocked
                };
                inferred.Preset = inferred.ComputePresetKey();
                return inferred;
            }

            return GuardPolicy.CreateDisabled(snap?.DetectedV2rayNRoot ?? "");
        }

        private static bool CheckFirewallProfilesAllBlock()
        {
            try
            {
                string[] profiles = { "DomainProfile", "StandardProfile", "PublicProfile" };
                foreach (string sub in profiles)
                {
                    using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{sub}", false))
                    {
                        if (rk == null) return false;
                        int enabled = Convert.ToInt32(rk.GetValue("EnableFirewall") ?? 0);
                        int outbound = Convert.ToInt32(rk.GetValue("DefaultOutboundAction") ?? 0);
                        if (enabled != 1 || outbound != 1) return false;
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void ProbeFirewallRulesRegistry(string installRoot, LiveSystemSnapshot snap)
        {
            var exceptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string exFile = Path.Combine(installRoot, @"backup\allowed-outbound-rules.json");
                if (File.Exists(exFile))
                {
                    foreach (Match m in Regex.Matches(File.ReadAllText(exFile), "\"([^\"]+)\""))
                    {
                        exceptions.Add(m.Groups[1].Value);
                    }
                }
            }
            catch { }

            try
            {
                using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", false))
                {
                    if (rk == null) return;
                    int rogues = 0;
                    foreach (string valName in rk.GetValueNames())
                    {
                        string v = rk.GetValue(valName) as string;
                        if (string.IsNullOrEmpty(v)) continue;

                        bool active = v.IndexOf("Active=TRUE", StringComparison.OrdinalIgnoreCase) >= 0;
                        string displayName = ExtractRuleField(v, "Name");
                        bool isAiGuard = valName.StartsWith("AI-Guard-", StringComparison.OrdinalIgnoreCase) ||
                                         displayName.StartsWith("AI-Guard-", StringComparison.OrdinalIgnoreCase);

                        if (isAiGuard)
                        {
                            string ruleId = !string.IsNullOrEmpty(displayName) ? displayName : valName;
                            if (string.Equals(ruleId, "AI-Guard-Allow-CN", StringComparison.OrdinalIgnoreCase) && active)
                                snap.CnRuleActive = true;
                            else if (string.Equals(ruleId, "AI-Guard-Allow-TUN", StringComparison.OrdinalIgnoreCase) && active)
                                snap.TunRuleActive = true;
                            else if (string.Equals(ruleId, "AI-Guard-Allow-LAN", StringComparison.OrdinalIgnoreCase) && active)
                                snap.LanRuleActive = true;
                            else if (string.Equals(ruleId, "AI-Guard-Allow-NCSI", StringComparison.OrdinalIgnoreCase) && active)
                                snap.NcsiRuleActive = true;
                            else if (string.Equals(ruleId, "AI-Guard-Allow-Node-TCP", StringComparison.OrdinalIgnoreCase) && active)
                            {
                                snap.NodeRuleActive = true;
                                snap.NodeSummary = FormatNodeSummaryFromRaw(v);
                            }
                        }
                        else if (active &&
                                 v.IndexOf("Dir=Out", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                 v.IndexOf("Action=Allow", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            if (!exceptions.Contains(valName) && (string.IsNullOrEmpty(displayName) || !exceptions.Contains(displayName)))
                            {
                                rogues++;
                            }
                        }
                    }
                    snap.RogueAllowCount = rogues;
                }
            }
            catch { }
        }

        private static string ExtractRuleField(string raw, string key)
        {
            string prefix = "|" + key + "=";
            int idx = raw.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                if (raw.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase)) idx = 0;
                else return "";
            }
            else
            {
                idx += 1; // skip '|'
            }
            int valStart = idx + key.Length + 1;
            int end = raw.IndexOf('|', valStart);
            return end >= 0 ? raw.Substring(valStart, end - valStart) : raw.Substring(valStart);
        }

        private static string FormatNodeSummaryFromRaw(string raw)
        {
            var ips = new List<string>();
            var ports = new List<string>();
            string app = "";
            foreach (string token in raw.Split('|'))
            {
                if (token.StartsWith("RA4=", StringComparison.OrdinalIgnoreCase))
                    ips.Add(token.Substring(4));
                else if (token.StartsWith("RPort=", StringComparison.OrdinalIgnoreCase))
                    ports.Add(token.Substring(6));
                else if (token.StartsWith("App=", StringComparison.OrdinalIgnoreCase))
                    app = Path.GetFileName(token.Substring(4));
            }
            if (ips.Count == 0) return "已激活";
            string ipDisplay = ips.Count == 1 ? ips[0] : $"{ips[0]} (+{ips.Count - 1})";
            string portDisplay = ports.Count > 0 ? ":" + string.Join(",", ports) : "";
            string coreDisplay = !string.IsNullOrEmpty(app) ? $" [{app}]" : "";
            return ipDisplay + portDisplay + coreDisplay;
        }

        private static void ProbeNetworkInterfaces(LiveSystemSnapshot snap)
        {
            try
            {
                var activeTuns = new List<string>();
                var physNames = new List<string>();
                var physDns = new List<string>();
                bool anyPhysHasIpv6 = false;
                bool allPhysApprovedDns = true;
                int physCount = 0;

                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    bool hasIpComponent = ni.Supports(NetworkInterfaceComponent.IPv4) || ni.Supports(NetworkInterfaceComponent.IPv6);
                    string desc = ni.Description ?? "";
                    bool isTun = KnownTunNames.Contains(ni.Name, StringComparer.OrdinalIgnoreCase) ||
                                 Regex.IsMatch(desc, "(?i)Wintun|sing-tun|Mihomo");

                    if (isTun)
                    {
                        snap.AnyTunAdapterCreated = true;
                        if (hasIpComponent && ni.OperationalStatus == OperationalStatus.Up)
                        {
                            activeTuns.Add(ni.Name);
                        }
                        continue;
                    }

                    if (!hasIpComponent || ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        Regex.IsMatch(desc, "(?i)Loopback|WAN Miniport")) continue;

                    physCount++;
                    physNames.Add(ni.Name);
                    if (ni.Supports(NetworkInterfaceComponent.IPv6))
                    {
                        anyPhysHasIpv6 = true;
                    }

                    if (ni.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        var v4Dns = ni.GetIPProperties().DnsAddresses
                            .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                            .Select(a => a.ToString())
                            .ToList();
                        if (v4Dns.Count > 0)
                        {
                            foreach (string d in v4Dns)
                            {
                                if (!physDns.Contains(d)) physDns.Add(d);
                                if (d != "223.5.5.5" && d != "223.6.6.6" && d != "1.1.1.1")
                                {
                                    allPhysApprovedDns = false;
                                }
                            }
                        }
                        else
                        {
                            allPhysApprovedDns = false;
                        }
                    }
                }

                snap.TunUp = activeTuns.Count > 0;
                snap.ActiveTunName = activeTuns.Count > 0 ? string.Join(", ", activeTuns) : "未开启";
                snap.PhysicalNicName = physNames.Count > 0 ? string.Join(", ", physNames) : "未连接";
                snap.PhysicalDnsSummary = physDns.Count > 0 ? string.Join(", ", physDns) : "DHCP";
                snap.PhysicalDnsLocked = physCount > 0 && allPhysApprovedDns;
                snap.PhysicalIpv6Disabled = physCount > 0 && !anyPhysHasIpv6;
            }
            catch { }
        }

        private static void ProbeRegistryPolicies(LiveSystemSnapshot snap)
        {
            try
            {
                using (RegistryKey rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", false))
                {
                    if (rk != null)
                    {
                        object em = rk.GetValue("EnableMulticast");
                        object sm = rk.GetValue("DisableSmartNameResolution");
                        snap.LlmnrDisabled = em != null && Convert.ToInt32(em) == 0;
                        snap.SmhnrDisabled = sm != null && Convert.ToInt32(sm) == 1;
                    }
                }
            }
            catch { }

            foreach (string nrptBase in new[]
            {
                @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig",
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"
            })
            {
                try
                {
                    using (RegistryKey bk = Registry.LocalMachine.OpenSubKey(nrptBase, false))
                    {
                        if (bk == null) continue;
                        foreach (string sub in bk.GetSubKeyNames())
                        {
                            using (RegistryKey sk = bk.OpenSubKey(sub, false))
                            {
                                string comment = Convert.ToString(sk?.GetValue("Comment") ?? "");
                                if (comment.StartsWith("AI-Guard", StringComparison.OrdinalIgnoreCase))
                                {
                                    snap.NrptActive = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            try
            {
                using (RegistryKey tk = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", false))
                {
                    object dc = tk?.GetValue("DisabledComponents");
                    snap.PreferIpv4Active = dc != null && (Convert.ToInt32(dc) & 0x20) != 0;
                }
            }
            catch { }

            try
            {
                using (RegistryKey wk = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", false))
                {
                    string ntp = Convert.ToString(wk?.GetValue("NtpServer") ?? "");
                    snap.DomesticNtpActive = Regex.IsMatch(ntp, @"(?i)(\.cn\b|aliyun|tencent|ntsc|203\.107\.6\.88)");
                }
            }
            catch { }
        }

        private static bool CheckInstallDirectoryLocked(string installRoot)
        {
            try
            {
                const int writeMask = 0x500D0156;
                DirectorySecurity acl = Directory.GetAccessControl(installRoot, AccessControlSections.Owner | AccessControlSections.Access);
                string ownerSid = acl.GetOwner(typeof(SecurityIdentifier))?.Value ?? "";
                if (!TrustedSids.Contains(ownerSid)) return false;

                foreach (FileSystemAccessRule ace in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (ace.AccessControlType != AccessControlType.Allow) continue;
                    string sid = ace.IdentityReference.Value;
                    if (TrustedSids.Contains(sid)) continue;
                    if (((int)ace.FileSystemRights & writeMask) != 0) return false;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
