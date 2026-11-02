# AI-Net-Guard (v5.4)

**Zero-Resident Windows 11 Kernel WFP Static Guard & DNS Leak Shield for AI Coding Tools & TUN Proxies**

> **0 MB background RAM · 0 ms TUN switch latency · Default-Deny Outbound + Mainland-China Direct Allowlist · Multi-Core Auto-Sync (`Xray` / `sing-box` / `Hysteria2` / `Mihomo`) · Reversible One-Command Rollback**

---

## Why AI-Net-Guard?

When using AI coding assistants and CLI agents (`Claude Code`, `Codex`, `Cursor`, `Gemini CLI`, `Python` SDKs, browsers) alongside a Windows TUN proxy (`v2rayN` with `Xray` or `sing-box`), three failure modes routinely leak your real IP or plaintext DNS:

1. **TUN crash / node switch fallback**: Windows keeps the physical default route (`0.0.0.0/0` on Wi-Fi/Ethernet) alive beneath the TUN split routes. The millisecond `xray.exe` / `sing-box.exe` restarts or TUN drops, connections silently fall back to your ISP IP.
2. **Parallel Multi-Homed DNS (`SMHNR`) & Plaintext Resolvers**: By default, Windows `Dnscache` broadcasts DNS queries across **all** active interfaces simultaneously and falls back to LLMNR / NetBIOS / IPv6 AAAA when TUN transitions.
3. **Default-Allow Windows Firewall + Third-Party Rule Drift**: Simply setting `DefaultOutboundAction = Block` does **not** override Windows' ~180 built-in `Outbound Allow` rules—nor new `Outbound Allow` rules silently added later by third-party app installers.

**AI-Net-Guard v5.4** solves all three directly inside the Windows kernel (`tcpip.sys` / WFP) with **zero resident background scripts**:

- **TUN ON**: Traffic routes through `xray_tun` / `singbox_tun`; foreign AI traffic exits exclusively via your proxy node while domestic traffic routes directly according to your core rules.
- **TUN OFF (or core crashed)**: **0 ms kernel fail-closed switch**—mainland-China IPv4 traffic (`cn-ipv4.txt`, ~6,516 collapsed prefixes), LAN, and DHCP continue working normally at line rate, while **all foreign/AI direct egress is dropped by the kernel firewall**.

---

## Key Features (v5.4)

- **100% Static Kernel Datapath (`0 ms` switch, `~0%` CPU overhead)**:
  - Stateful WFP ALE flow cache evaluates the 6,516-prefix `AI-Guard-Allow-CN` rule only on the first SYN/handshake packet (`< 0.01 ms`), forwarding established flows in `O(1)`.
  - Toggling TUN ON/OFF requires **zero firewall rule mutations**. Protection holds even if zero PowerShell processes ever run.
- **Zero-Resident Event Architecture (`0 MB` idle RAM)**:
  - No `while ($true)` polling daemon. `AI-Guard-Mode-Event` wakes via native Windows Event Log subscriptions on `NetworkProfile` (`10000/10001`), system boot, and **S3 Sleep / Hibernate / Modern Standby (`S0ix`) resume** (`Power-Troubleshooter 1`, `Kernel-Power 107/507`), runs in ~90 ms (zero CIM/WMI loaded on healthy fast path), and exits immediately.
  - `AI-Guard-Mode-Fallback` performs a 60-minute zero-CIM anti-drift check (~90 ms).
- **Hands-Free Multi-Core Node Auto-Sync (`Xray` + `sing-box` / `Hysteria2` + `Mihomo`)**:
  - Automatically detects `v2rayN` installation paths (or `$env:V2RAYN_ROOT` / `-V2rayNRoot`) and parses both **Xray** (`outbounds[].protocol`, `vnext`, `servers`, `peers`) and **sing-box** (`outbounds[].type`, `server`, `server_port`, and Hysteria2 port-hopping ranges `"20000:30000"` -> `"20000-30000"`).
  - Dynamically binds `-Program` to the active core executable (`xray.exe` / `sing-box.exe` / `mihomo.exe`), authorizes alternate TUN adapters (`AI-Guard-Allow-TUN-Alt`), and resolves domain-based nodes over encrypted `https://223.5.5.5/resolve` (`Proxy=$null`) first.
- **Complete DNS & IPv6 Leak Shield**:
  - Disables physical NIC IPv6 bindings (`ms_tcpip6`) including hot-plugged USB/tethering NICs, elevates IPv4 prefix precedence (`::ffff:0:0/96 = 50 > ::/0 = 40` + `DisabledComponents |= 0x20` to eliminate Python/CLI AAAA stalls), disables **LLMNR**, **NetBIOS**, and **Windows Smart Multi-Homed Name Resolution (`SMHNR`, `DisableSmartNameResolution = 1`)**, and ensures domestic-capable NTP (`ntp.aliyun.com`) to prevent VLESS+REALITY clock-skew deadlocks after sleep.
- **Zero-Cost Anti-Drift & Dead Loopback Proxy Auto-Heal**:
  - Single-pass registry audit (`~80 ms`) automatically quarantines unapproved `Outbound Allow` rules added by third-party installers (recording them for clean rollback) and clears stale `127.0.0.1:<port>` system proxy settings across user hives if the proxy app exited abnormally.
- **Privilege-Escalation Hardening & 23-Check Automated Regression Suite**:
  - [`13-harden-acl.ps1`](./13-harden-acl.ps1) locks `C:\AI-Net-Guard` ownership and DACL (`owner=Administrators`, `Administrators/SYSTEM=Full`, `Users=Read+Execute`) so unelevated processes cannot tamper with `SYSTEM`-scheduled scripts.
  - [`12-regression.ps1`](./12-regression.ps1) verifies 23 end-to-end invariants including live `pktmon` port-53 packet capture (`phys_attempts=0, escaped=0`), WFP filter inspection, `Proxy=$null` direct socket probes, and corrupt `geoip.dat` rejection drills—automatically cleaning up temporary XML/ETL dumps on `PASS`.

---

## Architecture

```text
Application Socket (Browser / Claude Code / Codex / Cursor / Python / Node)
  │  (IPv4 preferred ::ffff:0:0/96=50>40; SMHNR=off -> zero parallel DNS spray on physical NIC)
  │
  ├── [TUN ON] 0.0.0.0/0 split routes -> TUN (xray_tun / singbox_tun) -> Proxy Core
  │     ├─ Foreign / AI domains -> Encrypted DoH via Proxy Node (e.g. 203.0.113.10:443)
  │     └─ Domestic domains     -> Direct / Domestic DoH per core routing rules
  │     (Background Event Task: flushes stale DNS cache on TUN-up, auto-syncs node IP:port & core exe, exits)
  │
  └── [TUN OFF / Core Stopped] Hits Windows Kernel Firewall (WFP, 100% static, 0 scripts needed)
        ├─ Mainland China IPv4 (6,516 prefixes) / 223.5.5.5 / Domestic NTP -> AI-Guard-Allow-CN (ALLOW)
        ├─ LocalSubnet / DHCP / Windows NCSI (13.107.4.52:80)             -> Companion Rules   (ALLOW)
        └─ ALL Foreign & AI Destinations                                  -> Default Outbound  (BLOCK)
```

> **Why not enable Windows 11 OS-level DoH directly on the physical Wi-Fi/Ethernet adapter?**
> If OS-level DoH is enabled on the physical NIC for `223.5.5.5`, Windows `Dnscache` wraps all DNS queries inside TLS `:443` packets to `223.5.5.5`. When TUN is ON, the proxy core's port-53 DNS hijack rule cannot intercept `:443` traffic and routes `223.5.5.5:443` directly as a domestic IP—leaking every foreign/AI domain lookup to domestic DoH! Keeping NIC DNS on standard `223.5.5.5` (intercepted by TUN on port 53 when TUN is ON; allowed by `AI-Guard-Allow-CN` when TUN is OFF) + `SMHNR=off` + automatic DNS cache flush on TUN-up avoids both leaks and domestic CDN slowdowns.

---

## Requirements

- **OS**: Windows 11 (22H2 / 23H2 / 24H2+) or Windows 10 22H2
- **Shell**: Windows PowerShell `5.1` or PowerShell `7.x` (all 15 `.ps1` scripts are 100% pure ASCII and dual-engine tested)
- **Proxy Client**: `v2rayN` (7.x+) with `Xray`, `sing-box`, or `Mihomo` TUN mode enabled
  - *Tip*: If you want toggling the **Enable Tun** switch alone to block/unblock browser access to foreign AI sites without exiting `v2rayN`, set v2rayN's bottom system proxy mode to **Clear System Proxy** (`清除系统代理`).

---

## Quick Start (Safe Deployment with 45-Minute Auto-Rollback Net)

1. **Copy to `C:\AI-Net-Guard`** and open an **elevated PowerShell** (`Win + X` -> *Terminal (Admin)*):

   ```powershell
   Copy-Item -Path .\AI-Net-Guard -Destination C:\AI-Net-Guard -Recurse -Force
   cd C:\AI-Net-Guard
   ```

2. **Start `v2rayN` with TUN enabled**, then run the read-only pre-flight audit (optional):

   ```powershell
   .\00-audit.ps1
   .\04-wfp-audit.ps1
   ```

3. **Step 1 — DNS, IPv6, Prefix Policy, SMHNR & NTP Hardening** (records original baseline in `backup\baseline.json`):

   ```powershell
   .\01-dns-hardening.ps1
   ```

4. **Step 2 — Install Static Kernel Firewall & Arm 45-Minute Rollback Safety Net**:

   ```powershell
   .\02-killswitch.ps1 -RollbackMinutes 45
   ```

5. **Step 3 — Verify & Commit** (cancels the 45-minute auto-rollback timer once invariants pass and registers the zero-resident event tasks):

   ```powershell
   .\03-verify.ps1 -WfpCheck
   .\08-commit.ps1
   ```

6. **Step 4 — Lock Install Directory ACL & Run Full 23-Check Regression Suite**:

   ```powershell
   .\13-harden-acl.ps1
   ```

---

## Daily Usage & Maintenance Commands

Once installed and committed, **daily operation is completely hands-free**—switching proxy nodes, switching between `Xray` (VLESS/VMess/Trojan) and `sing-box` (Hysteria2/TUIC), plugging in USB/phone-tethering NICs, and waking from Modern Standby are all handled automatically.

```powershell
# Run in Elevated PowerShell (C:\AI-Net-Guard)
.\07-mode.ps1 -Status                # Read-only status dashboard (TUN, core, rules, ACL, DNS shield, 0 MB footprint)
.\07-mode.ps1                        # Run an immediate zero-CIM health check / self-heal
.\12-regression.ps1                  # Run the full 23-check end-to-end regression suite (auto-cleans temp captures)
.\10-sync-node-rule.ps1 -WhatIfOnly  # Preview parsed node IP/ports/core from v2rayN config.json (works non-elevated)
.\13-harden-acl.ps1 -SyncWorkspace   # Pull script updates from a git clone directory & re-lock ACLs
.\09-rollback.ps1                    # Completely uninstall & restore original firewall, DNS, IPv6, prefix policy & tasks
```

### Custom `v2rayN` Path

All scripts auto-detect `v2rayN` across `C:\v2rayN-windows-64`, `D:\v2rayN-windows-64`, `C:\v2rayN`, `D:\v2rayN`, `%LOCALAPPDATA%\v2rayN`, `C:\Program Files\v2rayN`, and any running `v2rayN.exe` process. For a custom path, set `$env:V2RAYN_ROOT` or pass `-V2rayNRoot "E:\Path\To\v2rayN"`.

### Allowing Specific Third-Party Outbound Firewall Rules

To exempt specific third-party firewall rule names from automatic anti-drift quarantine, create `C:\AI-Net-Guard\backup\allowed-outbound-rules.json` containing a JSON string array of rule `Name` or `DisplayName` values:

```json
[
  "My-Approved-App-Rule"
]
```

---

## Repository Script Reference

| Script | Purpose |
| --- | --- |
| [`00-audit.ps1`](./00-audit.ps1) | Read-only system snapshot (NICs, routes, DNS, IPv6 prefix policy, NTP, firewall profiles/rules, proxy config) |
| [`01-dns-hardening.ps1`](./01-dns-hardening.ps1) | Sets static `223.5.5.5` physical DNS, disables physical IPv6, prefers IPv4 over IPv6, disables LLMNR/NetBIOS/SMHNR, ensures domestic NTP |
| [`02-killswitch.ps1`](./02-killswitch.ps1) | Backs up `.wfw` & active outbound Allow rules, installs `AI-Guard-*` static ruleset, enables `DefaultOutboundAction=Block`, arms 45-min rollback timer |
| [`03-verify.ps1`](./03-verify.ps1) | Configuration & datapath verification (`Proxy=$null` direct kernel probes, `-WfpCheck`, interactive `-FailClosedTest`) |
| [`04-wfp-audit.ps1`](./04-wfp-audit.ps1) | Exports WFP filters to inspect Xray's dynamic `permit Xray` / `block DNS` filters + optional `pktmon` port-53 capture |
| [`05-xray-direct-test.ps1`](./05-xray-direct-test.ps1) | Behavioral proof of Xray's `ALE_AUTH_CONNECT` WFP hard permit under `geosite:cn -> direct` routing |
| [`06-boot-guard.ps1`](./06-boot-guard.ps1) | Cross-reboot safety net (`-Arm` before reboot drill, `-Remove` after verifying persistence) |
| [`07-mode.ps1`](./07-mode.ps1) | **Core controller**: zero-resident guard check, multi-core auto node sync, rogue Allow quarantine, SMHNR/LLMNR heal, dead proxy cleanup, `-Status` |
| [`08-commit.ps1`](./08-commit.ps1) | Verifies invariants, removes `AI-Guard-Test-Rollback`, and registers `AI-Guard-Mode-Event` + `AI-Guard-Mode-Fallback` |
| [`09-rollback.ps1`](./09-rollback.ps1) | Full baseline restoration with postcondition assertions (tasks, `.wfw`, quarantined rules, DNS, IPv6, prefix policy, NTP, LLMNR, SMHNR) |
| [`10-sync-node-rule.ps1`](./10-sync-node-rule.ps1) | Manual / preview (`-WhatIfOnly`) multi-core node & port rule synchronizer |
| [`11-geo-cn.ps1`](./11-geo-cn.ps1) | Zero-allocation protobuf parser for `geoip-only-cn-private.dat` / `geoip.dat` -> CIDR normalization & lossless aggregation into [`cn-ipv4.txt`](./cn-ipv4.txt) |
| [`12-regression.ps1`](./12-regression.ps1) | **23-check automated regression suite** (static state, ACL lock, 0-MB footprint, TUN on/off datapath, WFP, 10s `pktmon` DNS capture, corrupt GeoIP drill) |
| [`13-harden-acl.ps1`](./13-harden-acl.ps1) | Locks `C:\AI-Net-Guard` owner & DACL against non-admin tampering, runs elevated migration + regression (`-Undo` and `-SyncWorkspace` supported) |
| [`watchdog.ps1`](./watchdog.ps1) | Optional CLR `NetworkChange` event-driven resident daemon (disabled by default in favor of 0-MB `AI-Guard-Mode-Event`) |

For deep architectural notes and the full `v5 -> v5.4` (`R1–R24`) engineering review log, see [`CURRENT-IMPLEMENTATION.md`](./CURRENT-IMPLEMENTATION.md).

---

## Known Security Boundaries

1. **All non-CN direct traffic is blocked when TUN is OFF**: GitHub, Google, Steam, and overseas CDNs are blocked alongside foreign AI endpoints whenever TUN is down (by design under `DefaultOutboundAction = Block` + `AI-Guard-Allow-CN`).
2. **Xray's Dynamic WFP Hard Permit (`permit Xray`)**: While `Xray` TUN is active with `autoSystemWfpBlockLeak`, Xray installs an `ALE_AUTH_CONNECT` filter with `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` for `xray.exe` itself. During TUN operation, Windows Firewall strictly governs **all non-Xray processes**, while `xray.exe`'s own direct vs. proxy split is governed by Xray's routing configuration (`sing-box` does not install this WFP override and is strictly bound by `AI-Guard-Allow-Node-*`). To constrain `xray.exe` externally even against a compromised config, enforce a router/gateway egress allowlist to your proxy node IP:port.
3. **Domestic-IP Relay Proxies**: Traffic sent to third-party API relays hosted on mainland-China IPv4 addresses matches `AI-Guard-Allow-CN` and is not blocked by GeoIP.
4. **Captive Portals**: Hotel/airport Wi-Fi portals using foreign public IPs or private hijacked DNS may require temporarily resetting NIC DNS or running `09-rollback.ps1` to complete portal login.

---

## License

Released under the [MIT License](./LICENSE).
