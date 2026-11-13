using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;

namespace AiNetGuard.Gui
{
    public partial class App : Application
    {
        private const string AppMutexName = "Local\\AI_Net_Guard_SingleInstance_App_Mutex";
        private const string WindowTitle = "AI-Net-Guard v5.7.4 — Windows 内核级防泄漏与智能分流配置中心";
        private const int SW_SHOW = 5;
        private const int SW_RESTORE = 9;

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

        private static Mutex _appMutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            string smokeOutDir = null;
            if (e.Args != null)
            {
                for (int i = 0; i < e.Args.Length; i++)
                {
                    if (string.Equals(e.Args[i], "--smoke-test", StringComparison.OrdinalIgnoreCase) && i + 1 < e.Args.Length)
                    {
                        smokeOutDir = e.Args[i + 1];
                        break;
                    }
                }
            }

            DispatcherUnhandledException += (_, args) =>
            {
                if (!string.IsNullOrEmpty(smokeOutDir))
                {
                    try { System.IO.File.WriteAllText(System.IO.Path.Combine(smokeOutDir, "smoke-error.txt"), args.Exception.ToString()); } catch { }
                    Shutdown(2);
                    return;
                }
                MessageBox.Show(
                    "界面运行发生未预期异常：\n\n" + args.Exception.Message,
                    "AI-Net-Guard 错误提示",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                args.Handled = true;
            };

            // Single-instance enforcement (bypassed in headless smoke test mode)
            if (string.IsNullOrEmpty(smokeOutDir))
            {
                _appMutex = new Mutex(true, AppMutexName, out bool createdNew);
                if (!createdNew)
                {
                    ActivateExistingInstance();
                    Shutdown(0);
                    return;
                }
            }

            var mainWindow = new MainWindow(smokeOutDir);
            MainWindow = mainWindow;
            mainWindow.Show();
        }

        private static void ActivateExistingInstance()
        {
            try
            {
                IntPtr targetHwnd = FindWindow(null, WindowTitle);
                if (targetHwnd == IntPtr.Zero)
                {
                    var curProc = Process.GetCurrentProcess();
                    foreach (var proc in Process.GetProcessesByName(curProc.ProcessName))
                    {
                        if (proc.Id != curProc.Id && proc.MainWindowHandle != IntPtr.Zero)
                        {
                            targetHwnd = proc.MainWindowHandle;
                            break;
                        }
                    }
                }

                if (targetHwnd != IntPtr.Zero)
                {
                    if (IsIconic(targetHwnd))
                    {
                        ShowWindow(targetHwnd, SW_RESTORE);
                    }
                    else
                    {
                        ShowWindow(targetHwnd, SW_SHOW);
                    }

                    IntPtr foreWnd = GetForegroundWindow();
                    uint foreThread = GetWindowThreadProcessId(foreWnd, out _);
                    uint targetThread = GetWindowThreadProcessId(targetHwnd, out _);

                    if (foreThread != targetThread && foreThread != 0 && targetThread != 0)
                    {
                        AttachThreadInput(foreThread, targetThread, true);
                        SetForegroundWindow(targetHwnd);
                        AttachThreadInput(foreThread, targetThread, false);
                    }
                    else
                    {
                        SetForegroundWindow(targetHwnd);
                    }
                }
            }
            catch
            {
                // Best-effort activation
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (_appMutex != null)
            {
                try { _appMutex.ReleaseMutex(); } catch { }
                _appMutex.Dispose();
                _appMutex = null;
            }
            base.OnExit(e);
        }
    }
}
