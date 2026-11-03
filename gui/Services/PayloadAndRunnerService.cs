using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AiNetGuard.Gui.Services
{
    public static class PayloadAndRunnerService
    {
        public const string PayloadResourceName = "AiNetGuard.Payload.zip";

        public static bool HasEmbeddedPayload()
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResourceName))
            {
                return s != null && s.Length > 0;
            }
        }

        public static int ExtractEmbeddedPayload(string installRoot, Action<string> onLog = null)
        {
            if (string.IsNullOrWhiteSpace(installRoot))
                throw new ArgumentException("安装路径不能为空。", nameof(installRoot));

            Directory.CreateDirectory(installRoot);
            Directory.CreateDirectory(Path.Combine(installRoot, "backup"));
            Directory.CreateDirectory(Path.Combine(installRoot, "logs"));

            string fullRoot = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            int extractedCount = 0;

            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResourceName))
            {
                if (stream == null)
                {
                    // Fallback: if running directly from repo build folder without embedded resource
                    onLog?.Invoke("[提示] 未检测到内嵌载荷资源，保持现有目录脚本。");
                    return 0;
                }

                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false))
                {
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        if (string.IsNullOrEmpty(entry.Name)) continue;

                        string destPath = Path.GetFullPath(Path.Combine(installRoot, entry.FullName));
                        if (!destPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                        {
                            continue; // Prevent Zip-Slip
                        }

                        // Preserve newer user-refreshed cn-ipv4.txt if already healthy (>=50KB and newer than embedded entry)
                        if (string.Equals(entry.Name, "cn-ipv4.txt", StringComparison.OrdinalIgnoreCase) && File.Exists(destPath))
                        {
                            var fi = new FileInfo(destPath);
                            if (fi.Length >= 50000 && fi.LastWriteTimeUtc > entry.LastWriteTime.UtcDateTime)
                            {
                                continue;
                            }
                        }

                        string destDir = Path.GetDirectoryName(destPath);
                        if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                        {
                            Directory.CreateDirectory(destDir);
                        }

                        if (File.Exists(destPath))
                        {
                            FileAttributes attrs = File.GetAttributes(destPath);
                            if ((attrs & FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(destPath, attrs & ~FileAttributes.ReadOnly);
                            }
                        }

                        using (Stream entryStream = entry.Open())
                        using (var outStream = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                        {
                            entryStream.CopyTo(outStream);
                        }
                        extractedCount++;
                    }
                }
            }

            onLog?.Invoke($"[载荷引擎] 已同步释放 {extractedCount} 个核心防护组件至 {installRoot}");
            return extractedCount;
        }

        public static Task<int> RunPowerShellScriptAsync(
            string scriptPath,
            IReadOnlyList<string> scriptArgs,
            Action<string> onLine)
        {
            return Task.Run(() =>
            {
                if (!File.Exists(scriptPath))
                {
                    onLine?.Invoke($"[错误] 找不到核心脚本: {scriptPath}");
                    return 99;
                }

                string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string psExe = Path.Combine(sysRoot, @"System32\WindowsPowerShell\v1.0\powershell.exe");
                if (!File.Exists(psExe)) psExe = "powershell.exe";

                var sbCmd = new StringBuilder();
                sbCmd.Append("$ProgressPreference = 'SilentlyContinue'; ");
                sbCmd.Append("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ");
                sbCmd.Append("$OutputEncoding = [System.Text.Encoding]::UTF8; ");
                sbCmd.Append("& '").Append(EscapeSingleQuotes(scriptPath)).Append("'");

                if (scriptArgs != null)
                {
                    foreach (string arg in scriptArgs)
                    {
                        if (string.IsNullOrEmpty(arg)) continue;
                        if (arg.StartsWith("-", StringComparison.Ordinal))
                        {
                            sbCmd.Append(' ').Append(arg);
                        }
                        else
                        {
                            sbCmd.Append(" '").Append(EscapeSingleQuotes(arg)).Append("'");
                        }
                    }
                }
                sbCmd.Append("; exit $LASTEXITCODE");

                string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(sbCmd.ToString()));

                var psi = new ProcessStartInfo
                {
                    FileName = psExe,
                    Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded,
                    WorkingDirectory = Path.GetDirectoryName(scriptPath) ?? @"C:\",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                using (var proc = new Process { StartInfo = psi, EnableRaisingEvents = true })
                {
                    proc.OutputDataReceived += (_, e) =>
                    {
                        if (e.Data != null) onLine?.Invoke(FilterClixmlNoise(e.Data));
                    };
                    proc.ErrorDataReceived += (_, e) =>
                    {
                        if (!string.IsNullOrWhiteSpace(e.Data))
                        {
                            string cleaned = FilterClixmlNoise(e.Data);
                            if (!string.IsNullOrWhiteSpace(cleaned))
                            {
                                onLine?.Invoke("[STDERR] " + cleaned);
                            }
                        }
                    };

                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();
                    proc.WaitForExit();
                    return proc.ExitCode;
                }
            });
        }

        private static string EscapeSingleQuotes(string s)
        {
            return (s ?? "").Replace("'", "''");
        }

        private static string FilterClixmlNoise(string line)
        {
            if (string.IsNullOrEmpty(line)) return line;
            if (line.StartsWith("#< CLIXML", StringComparison.Ordinal) ||
                line.StartsWith("<Objs Version=", StringComparison.Ordinal))
            {
                return "";
            }
            return line;
        }
    }
}
