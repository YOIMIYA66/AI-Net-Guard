using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AiNetGuard.Gui.Services
{
    public static class PayloadAndRunnerService
    {
        public const string PayloadResourceName = "AiNetGuard.Payload.zip";
        private const string GlobalWriteLockName = @"Global\AI-Net-Guard-PolicyEngine";

        public static bool HasEmbeddedPayload()
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResourceName))
            {
                return s != null && s.Length > 0;
            }
        }

        private static Mutex AcquireGlobalWriteLock(int timeoutMs = 30000)
        {
            var identity = WindowsIdentity.GetCurrent();
            bool isAdmin = identity != null && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            var mtxSec = new MutexSecurity();
            mtxSec.AddAccessRule(new MutexAccessRule(new SecurityIdentifier("S-1-5-32-544"), MutexRights.FullControl, AccessControlType.Allow));
            mtxSec.AddAccessRule(new MutexAccessRule(new SecurityIdentifier("S-1-5-18"), MutexRights.FullControl, AccessControlType.Allow));
            if (!isAdmin && identity?.User != null)
            {
                mtxSec.AddAccessRule(new MutexAccessRule(identity.User, MutexRights.FullControl, AccessControlType.Allow));
            }

            bool createdNew;
            var mtx = new Mutex(false, GlobalWriteLockName, out createdNew, mtxSec);
            bool acquired = false;
            try
            {
                try
                {
                    acquired = mtx.WaitOne(timeoutMs);
                }
                catch (AbandonedMutexException)
                {
                    acquired = true;
                }
                if (!acquired)
                {
                    throw new TimeoutException($"等待全局写入锁超时 ({GlobalWriteLockName})");
                }
                return mtx;
            }
            catch
            {
                try { mtx.Dispose(); } catch { }
                throw;
            }
        }

        private static bool BytesSha256MatchFile(byte[] content, string existingPath)
        {
            if (!File.Exists(existingPath)) return false;
            byte[] existingBytes = File.ReadAllBytes(existingPath);
            if (existingBytes.Length != content.Length) return false;
            using (var sha = SHA256.Create())
            {
                byte[] h1 = sha.ComputeHash(content);
                byte[] h2 = sha.ComputeHash(existingBytes);
                for (int i = 0; i < h1.Length; i++)
                {
                    if (h1[i] != h2[i]) return false;
                }
                return true;
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
            int updatedCount = 0;
            int skippedCount = 0;

            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResourceName))
            {
                if (stream == null)
                {
                    // Fallback: if running directly from repo build folder without embedded resource
                    onLog?.Invoke("[提示] 未检测到内嵌载荷资源，保持现有目录脚本。");
                    return 0;
                }

                Mutex writeLock = AcquireGlobalWriteLock(30000);
                try
                {
                    int pid = Process.GetCurrentProcess().Id;
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
                                    skippedCount++;
                                    continue;
                                }
                            }

                            byte[] entryBytes;
                            using (Stream entryStream = entry.Open())
                            using (var ms = new MemoryStream())
                            {
                                entryStream.CopyTo(ms);
                                entryBytes = ms.ToArray();
                            }

                            if (BytesSha256MatchFile(entryBytes, destPath))
                            {
                                skippedCount++;
                                continue;
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

                            string tmpPath = destPath + ".tmp." + pid;
                            try
                            {
                                File.WriteAllBytes(tmpPath, entryBytes);
                                if (File.Exists(destPath))
                                {
                                    File.Replace(tmpPath, destPath, null);
                                }
                                else
                                {
                                    File.Move(tmpPath, destPath);
                                }
                            }
                            catch
                            {
                                try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                                throw;
                            }
                            updatedCount++;
                        }
                    }
                }
                finally
                {
                    try { writeLock.ReleaseMutex(); } catch { }
                    try { writeLock.Dispose(); } catch { }
                }
            }

            onLog?.Invoke($"[载荷引擎] 组件同步完成：更新 {updatedCount} 个，跳过未变更 {skippedCount} 个 ({installRoot})");
            return updatedCount + skippedCount;
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
