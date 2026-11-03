# Security Policy (安全策略)

## Supported Versions (支持版本)

AI-Net-Guard 专注于 Windows 10 与 Windows 11 下的内核级安全防御。我们始终建议用户使用最新发布的版本以获取最新的防护策略与漏洞修复：

| 版本系列 | 支持状态 | 修复支持 |
| :--- | :---: | :--- |
| `v5.6.x` | :white_check_mark: | 活跃维护与功能更新 |
| `v5.5.x` | :warning: | 仅安全补丁 |
| `< v5.5.0` | :x: | 已停止维护，建议升级 |

---

## Reporting a Vulnerability (漏洞提报)

如果您在 AI-Net-Guard 中发现了安全漏洞（例如：规则被未受限绕过、物理真实 IP 意外泄漏、DNS 境外明文逃逸或提权安全风险）：

1. **优先私密报告**：请优先通过 GitHub 的 [Private Vulnerability Reporting](https://github.com/YOIMIYA66/AI-Net-Guard/security/advisories/new) 功能提交安全通告草稿，避免在公共 Issue 中公开可利用的漏洞细节。
2. **复现指引**：提报时请尽可能提供：
   - 您的 Windows 版本与补丁号（如 Win11 24H2 Build 26100）
   - 所使用的代理客户端与 TUN 网卡模型
   - 能够证明流量泄漏的探测脚本、抓包文件（`.pcap` / `.etl`）或复现步骤
3. **响应承诺**：我们会在收到通告后 48 小时内确认问题，并在评估严重程度后尽快发布修复版本。
