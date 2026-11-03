using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AiNetGuard.Gui.Models;
using AiNetGuard.Gui.Services;
using Forms = System.Windows.Forms;

namespace AiNetGuard.Gui
{
    public partial class MainWindow : Window
    {
        public const string DefaultInstallRoot = @"C:\AI-Net-Guard";

        private readonly string _smokeTestOutDir;
        private readonly Dictionary<string, CheckBox> _toggleBoxes = new Dictionary<string, CheckBox>(StringComparer.OrdinalIgnoreCase);
        private DispatcherTimer _autoTelemetryTimer;

        private LiveSystemSnapshot _snapshot;
        private GuardPolicy _appliedPolicy;
        private GuardPolicy _draftPolicy;
        private bool _suppressUiEvents;
        private bool _isBusy;
        private bool _revealFullNodeIp;

        public MainWindow(string smokeTestOutDir = null)
        {
            _smokeTestOutDir = smokeTestOutDir;
            InitializeComponent();
            BuildFeatureCategoryCards();

            Loaded += MainWindow_Loaded;
            ContentRendered += MainWindow_ContentRendered;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            RefreshDashboard(reloadPolicy: true);

            if (string.IsNullOrEmpty(_smokeTestOutDir))
            {
                _autoTelemetryTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(3.5)
                };
                _autoTelemetryTimer.Tick += AutoTelemetryTimer_Tick;
                _autoTelemetryTimer.Start();
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _autoTelemetryTimer?.Stop();
        }

        private async void MainWindow_ContentRendered(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(_smokeTestOutDir))
            {
                await RunAutomatedSmokeTestAsync(_smokeTestOutDir);
            }
        }

        private void BuildFeatureCategoryCards()
        {
            CategoriesContainer.Children.Clear();
            _toggleBoxes.Clear();

            var grouped = FeatureCatalog.All.GroupBy(f => f.Category);
            foreach (var group in grouped)
            {
                // Apple macOS Section Header (placed outside the grouped inset card)
                var sectionTitle = new TextBlock
                {
                    Text = group.Key,
                    FontSize = 12,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    Margin = new Thickness(4, 14, 4, 6)
                };
                CategoriesContainer.Children.Add(sectionTitle);

                var cardBorder = new Border
                {
                    Background = (Brush)FindResource("CardBgBrush"),
                    BorderBrush = (Brush)FindResource("CardBorderBrush"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(10),
                    Margin = new Thickness(0, 0, 0, 4),
                    ClipToBounds = true
                };

                var cardStack = new StackPanel();

                var items = group.ToList();
                for (int i = 0; i < items.Count; i++)
                {
                    FeatureToggleItem item = items[i];
                    var rowBorder = new Border
                    {
                        Padding = new Thickness(16, 11, 16, 11),
                        BorderBrush = (Brush)FindResource("DividerBrush"),
                        BorderThickness = new Thickness(0, 0, 0, i < items.Count - 1 ? 1 : 0)
                    };

                    var rowGrid = new Grid();
                    rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                    // Left: Title + Badge + Plain Summary
                    var textStack = new StackPanel { Margin = new Thickness(0, 0, 18, 0) };
                    var titleWrap = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };

                    titleWrap.Children.Add(new TextBlock
                    {
                        Text = item.Title,
                        FontSize = 13,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = (Brush)FindResource("TextPrimaryBrush"),
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(0, 0, 8, 0)
                    });

                    var badgeBorder = new Border
                    {
                        Background = item.IsRecommended
                            ? (Brush)FindResource("SuccessBgBrush")
                            : new SolidColorBrush(Color.FromRgb(245, 245, 247)),
                        BorderBrush = item.IsRecommended
                            ? (Brush)FindResource("SuccessBorderBrush")
                            : (Brush)FindResource("CardBorderBrush"),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(4),
                        Padding = new Thickness(6, 1.5, 6, 1.5),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    badgeBorder.Child = new TextBlock
                    {
                        Text = item.BadgeText,
                        FontSize = 10.5,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = item.IsRecommended
                            ? (Brush)FindResource("SuccessTextBrush")
                            : (Brush)FindResource("TextMutedBrush")
                    };
                    titleWrap.Children.Add(badgeBorder);

                    textStack.Children.Add(titleWrap);
                    textStack.Children.Add(new TextBlock
                    {
                        Text = item.Summary,
                        FontSize = 11.5,
                        Foreground = (Brush)FindResource("TextSecondaryBrush"),
                        TextWrapping = TextWrapping.Wrap,
                        LineHeight = 17,
                        Margin = new Thickness(0, 3, 0, 0)
                    });

                    Grid.SetColumn(textStack, 0);
                    rowGrid.Children.Add(textStack);

                    // Right: Fluent ToggleSwitch
                    var toggle = new CheckBox
                    {
                        Style = (Style)FindResource("FluentToggleSwitch"),
                        VerticalAlignment = VerticalAlignment.Center,
                        Tag = item.Key
                    };
                    toggle.Checked += FeatureToggle_Changed;
                    toggle.Unchecked += FeatureToggle_Changed;

                    Grid.SetColumn(toggle, 1);
                    rowGrid.Children.Add(toggle);

                    rowBorder.Child = rowGrid;
                    cardStack.Children.Add(rowBorder);
                    _toggleBoxes[item.Key] = toggle;
                }

                cardBorder.Child = cardStack;
                CategoriesContainer.Children.Add(cardBorder);
            }
        }

        private void RefreshDashboard(bool reloadPolicy)
        {
            string currentV2Input = V2rayNPathBox?.Text?.Trim() ?? "";
            _snapshot = SystemProbeService.Probe(DefaultInstallRoot, currentV2Input);

            if (reloadPolicy || _draftPolicy == null || _appliedPolicy == null || !_snapshot.IsDeployed)
            {
                GuardPolicy loaded = SystemProbeService.LoadOrInferPolicy(DefaultInstallRoot, _snapshot);
                _appliedPolicy = loaded.Clone();
                _draftPolicy = loaded.Clone();
            }

            SyncUiFromState();
        }

        private void UpdateHeroStatusBadge()
        {
            if (_snapshot == null) return;
            if (_snapshot.IsDeployed)
            {
                if (!_snapshot.CnRuleActive)
                {
                    GuardStatusBadge.Background = (Brush)FindResource("WarnBgBrush");
                    GuardStatusBadge.BorderBrush = (Brush)FindResource("WarnBorderBrush");
                    GuardStatusDot.Fill = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                    GuardStatusText.Foreground = (Brush)FindResource("WarnTextBrush");
                    GuardStatusText.Text = "严格全局铁桶锁已激活 (零直连)";
                }
                else
                {
                    GuardStatusBadge.Background = (Brush)FindResource("SuccessBgBrush");
                    GuardStatusBadge.BorderBrush = (Brush)FindResource("SuccessBorderBrush");
                    GuardStatusDot.Fill = (Brush)FindResource("SuccessBrush");
                    GuardStatusText.Foreground = (Brush)FindResource("SuccessTextBrush");
                    GuardStatusText.Text = _snapshot.PendingTestRollbackTask
                        ? "防护运行中 (测试保护期)"
                        : "内核静态防护运行中";
                }
            }
            else
            {
                GuardStatusBadge.Background = new SolidColorBrush(Color.FromRgb(245, 245, 247));
                GuardStatusBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(229, 229, 234));
                GuardStatusDot.Fill = new SolidColorBrush(Color.FromRgb(142, 142, 147));
                GuardStatusText.Foreground = (Brush)FindResource("TextSecondaryBrush");
                GuardStatusText.Text = "尚未部署 (系统原始状态)";
            }
        }

        private void UpdateTelemetryCards()
        {
            if (_snapshot == null) return;

            CardFirewallMain.Text = _snapshot.ProfilesAllBlock ? "默认出站拦截 (Block)" : "系统默认放行 (未接管)";
            CardFirewallMain.Foreground = _snapshot.ProfilesAllBlock
                ? (Brush)FindResource("SuccessTextBrush")
                : (Brush)FindResource("TextPrimaryBrush");
            string cnText = _snapshot.CnRuleActive
                ? (_snapshot.CnPrefixCount > 0 ? $"大陆白名单 {_snapshot.CnPrefixCount} 段" : "大陆白名单已启用")
                : (_snapshot.IsDeployed ? "大陆直连已关闭" : "未安装白名单");
            CardFirewallSub.Text = $"{cnText} · 外部放行 {_snapshot.RogueAllowCount} 条";

            CardTunMain.Text = _snapshot.TunUp ? $"隧道在线 ({_snapshot.ActiveTunName})" : "TUN 未开启";
            CardTunMain.Foreground = _snapshot.TunUp
                ? (Brush)FindResource("AccentBrush")
                : (Brush)FindResource("TextPrimaryBrush");
            CardTunSub.Text = $"内核: {_snapshot.RunningCoreSummary} · 网卡: {_snapshot.PhysicalNicName}";

            CardNodeMain.Text = FormatNodeDisplay(_snapshot.NodeSummary);
            CardNodeSub.Text = _snapshot.AclLocked
                ? "目录 ACL 已防篡改锁定"
                : (_snapshot.IsDeployed ? "目录 ACL 未锁定" : "部署时自动绑定节点并锁定 ACL");

            string dnsMode = _snapshot.NrptActive ? "严格 NRPT (1.1.1.1)" : $"DNS: {_snapshot.PhysicalDnsSummary}";
            CardDnsMain.Text = dnsMode;
            string smhnrTxt = _snapshot.SmhnrDisabled ? "SMHNR已禁" : "SMHNR默认";
            string ramTxt = _snapshot.ZeroResidentTaskReady ? "0 MB 事件自愈" : "无后台任务";
            CardDnsSub.Text = $"{smhnrTxt} · {ramTxt}";
        }

        private void UpdateSystemProxyBanner()
        {
            if (_snapshot == null || !string.IsNullOrEmpty(_smokeTestOutDir)) return;
            SystemProxyBanner.Visibility = Visibility.Visible;
            if (_snapshot.SystemProxyEnabled)
            {
                SystemProxyText.Text = $"系统代理已自动配置为 {_snapshot.SystemProxyServer}（Xray 原生协同，已正常接入）";
                ClearSysProxyBtn.Content = "刷新系统代理";
            }
            else
            {
                SystemProxyText.Text = "当前未开启系统代理（如果使用 Xray，建议点击右侧一键设为自动配置系统代理）";
                ClearSysProxyBtn.Content = "一键启用系统代理";
            }
        }

        private async void AutoTelemetryTimer_Tick(object sender, EventArgs e)
        {
            if (_isBusy || !string.IsNullOrEmpty(_smokeTestOutDir)) return;

            string currentV2Input = V2rayNPathBox?.Text?.Trim() ?? "";
            string root = DefaultInstallRoot;

            LiveSystemSnapshot freshSnap = null;
            try
            {
                freshSnap = await Task.Run(() => SystemProbeService.Probe(root, currentV2Input));
            }
            catch
            {
                return;
            }

            if (freshSnap == null || _isBusy) return;

            bool wasDeployed = _snapshot != null && _snapshot.IsDeployed;
            _snapshot = freshSnap;

            UpdateHeroStatusBadge();
            UpdateTelemetryCards();
            UpdateSystemProxyBanner();

            if (wasDeployed != _snapshot.IsDeployed)
            {
                UninstallBtn.IsEnabled = !_isBusy && (_snapshot.IsDeployed || _snapshot.BaselineExists);
                RegressionBtn.IsEnabled = !_isBusy && _snapshot.IsDeployed;
                UpdateFooterHintAndButtons();
            }
        }

        private void SyncUiFromState()
        {
            _suppressUiEvents = true;
            try
            {
                // 1. Hero Status Badge
                UpdateHeroStatusBadge();

                // 2. Telemetry 4 Cards
                UpdateTelemetryCards();

                // 3. v2rayN path & System proxy banner
                V2rayNPathBox.Text = _draftPolicy.V2rayNRoot ?? _snapshot.DetectedV2rayNRoot;
                UpdateV2rayNValidationBadge(V2rayNPathBox.Text);
                UpdateSystemProxyBanner();

                // 4. Sync all 15 CheckBoxes
                foreach (var kv in _toggleBoxes)
                {
                    kv.Value.IsChecked = _draftPolicy.GetFlag(kv.Key);
                }

                UpdatePresetCardsHighlight();
                UpdateFooterHintAndButtons();
            }
            finally
            {
                _suppressUiEvents = false;
            }
        }

        private string FormatNodeDisplay(string rawSummary)
        {
            if (string.IsNullOrEmpty(rawSummary)) return "尚未绑定节点";
            if (_revealFullNodeIp && string.IsNullOrEmpty(_smokeTestOutDir)) return rawSummary;

            // Mask middle two octets of public IPv4 addresses by default to protect screenshots
            return Regex.Replace(rawSummary, @"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", m =>
            {
                return $"{m.Groups[1].Value}.{m.Groups[2].Value}.*.*";
            });
        }

        private void CardNodeMain_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            _revealFullNodeIp = !_revealFullNodeIp;
            if (_snapshot != null)
            {
                CardNodeMain.Text = FormatNodeDisplay(_snapshot.NodeSummary);
            }
        }

        private void UpdateV2rayNValidationBadge(string path)
        {
            string trimmed = (path ?? "").Trim();
            bool hasCfg = !string.IsNullOrEmpty(trimmed) && File.Exists(Path.Combine(trimmed, @"binConfigs\config.json"));
            bool hasExe = !string.IsNullOrEmpty(trimmed) && File.Exists(Path.Combine(trimmed, "v2rayN.exe"));

            if (hasCfg)
            {
                V2rayNValidBadge.Background = (Brush)FindResource("SuccessBgBrush");
                V2rayNValidText.Foreground = (Brush)FindResource("SuccessTextBrush");
                V2rayNValidText.Text = "已就绪 (含 config.json)";
            }
            else if (hasExe)
            {
                V2rayNValidBadge.Background = (Brush)FindResource("WarnBgBrush");
                V2rayNValidText.Foreground = (Brush)FindResource("WarnTextBrush");
                V2rayNValidText.Text = "已识别程序 (请先启动一次 v2rayN)";
            }
            else
            {
                V2rayNValidBadge.Background = new SolidColorBrush(Color.FromRgb(254, 226, 226));
                V2rayNValidText.Foreground = (Brush)FindResource("DangerBrush");
                V2rayNValidText.Text = "未找到 v2rayN 目录";
            }
        }

        private void V2rayNPathBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_suppressUiEvents || _draftPolicy == null) return;
            _draftPolicy.V2rayNRoot = (V2rayNPathBox.Text ?? "").Trim();
            UpdateV2rayNValidationBadge(_draftPolicy.V2rayNRoot);
            UpdateFooterHintAndButtons();
        }

        private void BrowseV2rayNBtn_Click(object sender, RoutedEventArgs e)
        {
            using (var dlg = new Forms.FolderBrowserDialog
            {
                Description = "请选择 v2rayN 所在根目录（包含 v2rayN.exe 与 binConfigs 文件夹）",
                ShowNewFolderButton = false,
                SelectedPath = Directory.Exists(V2rayNPathBox.Text) ? V2rayNPathBox.Text : @"C:\"
            })
            {
                if (dlg.ShowDialog() == Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.SelectedPath))
                {
                    V2rayNPathBox.Text = dlg.SelectedPath;
                }
            }
        }

        private Action _pendingConfirmAction;
        private Action _pendingCancelAction;

        private void ShowNativeConfirmModal(
            string title,
            string message,
            Action onConfirm,
            Action onCancel = null,
            string okText = "确定",
            string cancelText = "取消",
            bool isDestructive = false,
            string subtitle = "AI-Net-Guard 原生操作确认",
            string icon = "⚠️")
        {
            ConfirmModalTitle.Text = title;
            ConfirmModalSubtitle.Text = subtitle;
            ConfirmModalMessage.Text = message;
            ConfirmModalIconText.Text = icon;
            ConfirmModalOkBtn.Content = okText;
            ConfirmModalCancelBtn.Content = cancelText;
            ConfirmModalCancelBtn.Visibility = Visibility.Visible;

            if (isDestructive)
            {
                ConfirmModalIconBorder.Background = (TryFindResource("DangerBgBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 241, 242));
                ConfirmModalIconBorder.BorderBrush = (TryFindResource("DangerBorderBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(254, 205, 211));
                ConfirmModalOkBtn.Background = new SolidColorBrush(Color.FromRgb(220, 38, 38));
                ConfirmModalOkBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            }
            else
            {
                ConfirmModalIconBorder.Background = (TryFindResource("WarnBgBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 248, 225));
                ConfirmModalIconBorder.BorderBrush = (TryFindResource("WarnBorderBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 224, 130));
                ConfirmModalOkBtn.Background = (TryFindResource("AccentBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(0, 113, 227));
                ConfirmModalOkBtn.BorderBrush = (TryFindResource("AccentBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(0, 113, 227));
            }

            _pendingConfirmAction = onConfirm;
            _pendingCancelAction = onCancel;
            ConfirmModalOverlay.Visibility = Visibility.Visible;
        }

        private void ShowNativeAlertModal(
            string title,
            string message,
            Action onOk = null,
            string okText = "我知道了",
            bool isSuccess = false,
            string subtitle = "AI-Net-Guard 状态提示")
        {
            ConfirmModalTitle.Text = title;
            ConfirmModalSubtitle.Text = subtitle;
            ConfirmModalMessage.Text = message;
            ConfirmModalOkBtn.Content = okText;
            ConfirmModalCancelBtn.Visibility = Visibility.Collapsed;

            if (isSuccess)
            {
                ConfirmModalIconBorder.Background = (TryFindResource("SuccessBgBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(234, 247, 238));
                ConfirmModalIconBorder.BorderBrush = (TryFindResource("SuccessBorderBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(210, 242, 218));
                ConfirmModalIconText.Text = "✅";
                ConfirmModalOkBtn.Background = new SolidColorBrush(Color.FromRgb(22, 163, 74));
                ConfirmModalOkBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(21, 128, 61));
            }
            else
            {
                ConfirmModalIconBorder.Background = (TryFindResource("WarnBgBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 248, 225));
                ConfirmModalIconBorder.BorderBrush = (TryFindResource("WarnBorderBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 224, 130));
                ConfirmModalIconText.Text = "ℹ️";
                ConfirmModalOkBtn.Background = (TryFindResource("AccentBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(0, 113, 227));
                ConfirmModalOkBtn.BorderBrush = (TryFindResource("AccentBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(0, 113, 227));
            }

            _pendingConfirmAction = onOk;
            _pendingCancelAction = null;
            ConfirmModalOverlay.Visibility = Visibility.Visible;
        }

        private Task<bool> ShowNativeConfirmAsync(
            string title,
            string message,
            string okText = "确定",
            string cancelText = "取消",
            bool isDestructive = false,
            string subtitle = "AI-Net-Guard 操作确认",
            string icon = "⚠️")
        {
            var tcs = new TaskCompletionSource<bool>();
            ShowNativeConfirmModal(title, message,
                () => tcs.TrySetResult(true),
                () => tcs.TrySetResult(false),
                okText, cancelText, isDestructive, subtitle, icon);
            return tcs.Task;
        }

        private Task ShowNativeAlertAsync(
            string title,
            string message,
            string okText = "我知道了",
            bool isSuccess = false,
            string subtitle = "AI-Net-Guard 状态提示")
        {
            var tcs = new TaskCompletionSource<bool>();
            ShowNativeAlertModal(title, message,
                () => tcs.TrySetResult(true),
                okText, isSuccess, subtitle);
            return tcs.Task;
        }

        private void ConfirmModalOk_Click(object sender, RoutedEventArgs e)
        {
            ConfirmModalOverlay.Visibility = Visibility.Collapsed;
            var action = _pendingConfirmAction;
            _pendingConfirmAction = null;
            _pendingCancelAction = null;
            action?.Invoke();
        }

        private void ConfirmModalCancel_Click(object sender, RoutedEventArgs e)
        {
            ConfirmModalOverlay.Visibility = Visibility.Collapsed;
            var action = _pendingCancelAction;
            _pendingConfirmAction = null;
            _pendingCancelAction = null;
            action?.Invoke();
        }

        private void FeatureToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_suppressUiEvents || _draftPolicy == null) return;
            if (!(sender is CheckBox cb) || !(cb.Tag is string key)) return;

            bool newVal = cb.IsChecked == true;

            // Rule coordination 1: StrictNrptDoh warning & automatic LockPhysicalDns coupling via Native Modal
            if (string.Equals(key, "StrictNrptDoh", StringComparison.OrdinalIgnoreCase) && newVal && string.IsNullOrEmpty(_smokeTestOutDir))
            {
                ShowNativeConfirmModal(
                    "高级功能确认 — 严格全局 NRPT DoH",
                    "开启「严格系统级全局 DoH (NRPT 1.1.1.1)」后：\n\n" +
                    "• 全系统 DNS 将强制仅走 1.1.1.1 加密通道且禁止回退；\n" +
                    "• 一旦你在 v2rayN 中关闭 TUN 开关，国内网站也将无法解析域名（且酒店/校园网认证页可能无法弹出）。\n\n" +
                    "日常分流场景更建议保持此项关闭（使用 223.5.5.5 静态 DNS + TUN 劫持已实现 0 物理明文泄漏）。\n\n" +
                    "确定仍要开启严格全局 NRPT DoH 吗？",
                    onConfirm: () =>
                    {
                        _draftPolicy.StrictNrptDoh = true;
                        _draftPolicy.LockPhysicalDns = true;
                        _suppressUiEvents = true;
                        cb.IsChecked = true;
                        if (_toggleBoxes.TryGetValue("LockPhysicalDns", out CheckBox lockDnsCb))
                        {
                            lockDnsCb.IsChecked = true;
                        }
                        _suppressUiEvents = false;
                        UpdatePresetCardsHighlight();
                        UpdateFooterHintAndButtons();
                    },
                    onCancel: () =>
                    {
                        _suppressUiEvents = true;
                        cb.IsChecked = false;
                        _suppressUiEvents = false;
                    });
                return;
            }

            // Rule coordination 2: Cannot turn off LockPhysicalDns while StrictNrptDoh is ON
            if (string.Equals(key, "LockPhysicalDns", StringComparison.OrdinalIgnoreCase) && !newVal && _draftPolicy.StrictNrptDoh)
            {
                _draftPolicy.StrictNrptDoh = false;
                _suppressUiEvents = true;
                if (_toggleBoxes.TryGetValue("StrictNrptDoh", out CheckBox nrptCb))
                {
                    nrptCb.IsChecked = false;
                }
                _suppressUiEvents = false;
            }

            _draftPolicy.SetFlag(key, newVal);
            UpdatePresetCardsHighlight();
            UpdateFooterHintAndButtons();
        }

        private void ApplyPresetInteractive(string presetKey)
        {
            if (_isBusy || _draftPolicy == null) return;
            _draftPolicy.ApplyPreset(presetKey);

            _suppressUiEvents = true;
            try
            {
                foreach (var kv in _toggleBoxes)
                {
                    kv.Value.IsChecked = _draftPolicy.GetFlag(kv.Key);
                }
            }
            finally
            {
                _suppressUiEvents = false;
            }

            UpdatePresetCardsHighlight();
            UpdateFooterHintAndButtons();
        }

        private void PresetRecommendedCard_Click(object sender, MouseButtonEventArgs e) => ApplyPresetInteractive("Recommended");
        private void PresetStrictCard_Click(object sender, MouseButtonEventArgs e) => ApplyPresetInteractive("StrictLock");
        private void PresetCompatibleCard_Click(object sender, MouseButtonEventArgs e) => ApplyPresetInteractive("Compatible");
        private void ResetRecommendedBtn_Click(object sender, RoutedEventArgs e) => ApplyPresetInteractive("Recommended");

        private void UpdatePresetCardsHighlight()
        {
            bool deployed = _snapshot != null && _snapshot.IsDeployed;
            string active = _draftPolicy?.ComputePresetKey() ?? "Recommended";

            HighlightCard(PresetRecommendedCard, deployed && active == "Recommended");
            HighlightCard(PresetStrictCard, deployed && active == "StrictLock");
            HighlightCard(PresetCompatibleCard, deployed && active == "Compatible");

            if (PresetDescriptionText != null)
            {
                if (!deployed)
                {
                    if (active == "Recommended")
                    {
                        PresetDescriptionText.Text = "已选择「推荐日常防泄漏」方案（14 项配置已勾选）。点击右侧【首次一键部署防护】即可写入内核。";
                    }
                    else if (active == "StrictLock")
                    {
                        PresetDescriptionText.Text = "已选择「严格全局铁桶锁」方案（关闭大陆直连白名单与 NCSI 探测）。点击右侧【首次一键部署防护】即可写入内核。";
                    }
                    else if (active == "Compatible")
                    {
                        PresetDescriptionText.Text = "已选择「兼容 / 开发者」方案（保留大陆白名单，放开 IPv6 与局域网）。点击右侧【首次一键部署防护】即可写入内核。";
                    }
                    else
                    {
                        PresetDescriptionText.Text = "当前未激活防护（所有防护功能已关闭，系统处于原始默认网络状态）。你可以点击上方任一预设一键勾选，或手动勾选开关后点击右下角【首次一键部署防护】。";
                    }
                }
                else
                {
                    if (active == "StrictLock")
                    {
                        PresetDescriptionText.Text = "严格全局铁桶模式运行中：关闭大陆直连白名单与 NCSI 探测。只要 TUN 代理未开启或意外断开，含国内在内的所有外网请求在内核层 100% 阻断，不留任何裸连缝隙。";
                    }
                    else if (active == "Compatible")
                    {
                        PresetDescriptionText.Text = "开发者 / 兼容模式运行中：保留核心防火墙拦截与大陆白名单，但允许物理网卡 IPv6 与局域网多播发现，兼顾校园网/教育网纯 IPv6 与局域网智能设备调试。";
                    }
                    else
                    {
                        PresetDescriptionText.Text = "推荐日常防泄漏模式运行中：全开 14 项推荐加固。国内直连白名单与 TUN 代理智能分流，节点自动热同步，后台 0 进程、0 MB 内存占用自愈。";
                    }
                }
            }
        }

        private static void HighlightCard(Border card, bool selected)
        {
            if (card == null) return;
            if (selected)
            {
                card.Background = Brushes.White;
                card.BorderThickness = new Thickness(0);
                card.Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    BlurRadius = 3,
                    ShadowDepth = 1,
                    Opacity = 0.12,
                    Color = Colors.Black
                };
            }
            else
            {
                card.Background = Brushes.Transparent;
                card.BorderThickness = new Thickness(0);
                card.Effect = null;
            }
        }

        private void UpdateFooterHintAndButtons()
        {
            if (_isBusy) return;

            bool deployed = _snapshot != null && _snapshot.IsDeployed;
            UninstallBtn.IsEnabled = true;
            RegressionBtn.IsEnabled = true;

            int diffs = _draftPolicy != null ? _draftPolicy.CountDifferences(_appliedPolicy) : 0;
            if (!deployed)
            {
                ApplyBtn.Content = diffs > 0 ? $"首次一键部署防护 ({diffs} 项)" : "首次一键部署防护";
                FooterHintText.Text = diffs > 0
                    ? $"已勾选 {diffs} 项防护，点击右侧按钮立即部署到 Windows 内核"
                    : "当前未部署防护（所有开关已关闭）· 可选择上方预设或勾选功能后部署";
                FooterHintText.Foreground = (Brush)FindResource("TextSecondaryBrush");
            }
            else if (diffs > 0)
            {
                ApplyBtn.Content = $"应用配置更改 ({diffs} 项)";
                FooterHintText.Text = $"已修改 {diffs} 项功能设置，点击右侧按钮立即同步到 Windows 内核与后台自愈策略";
                FooterHintText.Foreground = (Brush)FindResource("WarnTextBrush");
            }
            else
            {
                ApplyBtn.Content = "重新校验并应用配置";
                FooterHintText.Text = "当前系统已激活所选防护策略 (内核零泄漏保护中)";
                FooterHintText.Foreground = (Brush)FindResource("SuccessTextBrush");
            }
        }

        private bool EnsureAdminOrPromptElevate()
        {
            if (SystemProbeService.IsCurrentProcessAdmin()) return true;

            ShowNativeConfirmModal(
                "需要管理员权限 (UAC)",
                "修改 Windows 内核防火墙、DNS 与系统计划任务需要管理员权限。\n\n是否以管理员身份重新启动 AI-Net-Guard？",
                () =>
                {
                    try
                    {
                        string exePath = Process.GetCurrentProcess().MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exePath))
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = exePath,
                                UseShellExecute = true,
                                Verb = "runas"
                            });
                            Application.Current.Shutdown();
                        }
                    }
                    catch (Exception ex)
                    {
                        ShowNativeAlertModal("提示", "提升权限已取消: " + ex.Message);
                    }
                },
                null,
                okText: "立即提升权限",
                cancelText: "取消",
                icon: "🛡️");

            return false;
        }


        private void SetBusy(bool busy, string statusText = "")
        {
            _isBusy = busy;
            ApplyBtn.IsEnabled = !busy;
            UninstallBtn.IsEnabled = !busy && (_snapshot != null && (_snapshot.IsDeployed || _snapshot.BaselineExists));
            RegressionBtn.IsEnabled = !busy && (_snapshot != null && _snapshot.IsDeployed);
            RefreshBtn.IsEnabled = !busy;
            RescueBtn.IsEnabled = !busy;
            SyncNodeNowBtn.IsEnabled = !busy;
            ClearSysProxyBtn.IsEnabled = !busy;
            BrowseV2rayNBtn.IsEnabled = !busy;
            V2rayNPathBox.IsEnabled = !busy;
            ResetRecommendedBtn.IsEnabled = !busy;

            foreach (CheckBox cb in _toggleBoxes.Values)
            {
                cb.IsEnabled = !busy;
            }

            if (busy && !string.IsNullOrEmpty(statusText))
            {
                FooterHintText.Text = statusText;
                FooterHintText.Foreground = (Brush)FindResource("AccentBrush");
            }
            else if (!busy)
            {
                UpdateFooterHintAndButtons();
            }
        }

        private void ExpandConsole()
        {
            ConsoleBodyBorder.Visibility = Visibility.Visible;
            ToggleConsoleBtn.Content = "▼ 实时执行输出控制台（点击折叠）";
        }

        private void AppendLog(string line)
        {
            if (line == null) return;
            Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                if (LogTextBox.Text.Length > 0)
                {
                    LogTextBox.AppendText(Environment.NewLine);
                }
                LogTextBox.AppendText(line);
                LogTextBox.ScrollToEnd();
            }));
        }

        private async void ApplyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            string v2Root = (V2rayNPathBox.Text ?? "").Trim();
            bool isFresh = _snapshot == null || !_snapshot.BaselineExists;
            if (isFresh)
            {
                if (!File.Exists(Path.Combine(v2Root, @"binConfigs\config.json")))
                {
                    await ShowNativeAlertAsync(
                        "前置条件提示",
                        "未在所选目录找到 v2rayN 配置文件：\n" + Path.Combine(v2Root, @"binConfigs\config.json") + "\n\n" +
                        "请先选择正确的 v2rayN 目录，并在 v2rayN 中开启一次「启用 Tun」以生成虚拟网卡和节点配置。",
                        okText: "我知道了",
                        isSuccess: false,
                        subtitle: "缺少 v2rayN 运行配置");
                    return;
                }
            }

            ExpandConsole();
            SetBusy(true, "正在释放引擎组件并应用所选策略，请稍候...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 开始应用 AI-Net-Guard v5.5.1 防护配置 ==========");

            try
            {
                _draftPolicy.V2rayNRoot = v2Root;
                await Task.Run(() =>
                {
                    PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, AppendLog);
                    _draftPolicy.SaveToFile(Path.Combine(DefaultInstallRoot, @"backup\guard-policy.json"));
                });

                string applyScript = Path.Combine(DefaultInstallRoot, "14-apply-policy.ps1");
                var args = new List<string> { "-Root", DefaultInstallRoot };
                if (!string.IsNullOrWhiteSpace(v2Root))
                {
                    args.Add("-V2rayNRoot");
                    args.Add(v2Root);
                }

                int code = await PayloadAndRunnerService.RunPowerShellScriptAsync(applyScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: true);

                if (code == 0)
                {
                    AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 配置应用成功 (exit=0) ==========");
                    FooterHintText.Text = "配置已成功应用并写入系统内核与持久化策略！";
                    FooterHintText.Foreground = (Brush)FindResource("SuccessTextBrush");
                }
                else
                {
                    AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 执行结束 (exit={code}) ==========");
                    await ShowNativeAlertAsync(
                        "策略应用提示",
                        $"底层加固脚本返回了非零退出码 (exit={code})，请查看控制台日志了解具体执行细节。",
                        okText: "我知道了",
                        isSuccess: false,
                        subtitle: "应用执行报告");
                }
            }
            catch (Exception ex)
            {
                AppendLog("[异常] " + ex.Message);
                await ShowNativeAlertAsync(
                    "应用策略异常",
                    "应用策略时发生异常：\n" + ex.Message,
                    okText: "关闭",
                    isSuccess: false,
                    subtitle: "执行异常");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async void SyncNodeNowBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            ExpandConsole();
            SetBusy(true, "正在同步当前代理节点与端口...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 立即同步代理节点规则 ==========");

            try
            {
                string v2Root = (V2rayNPathBox.Text ?? "").Trim();
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string applyScript = Path.Combine(DefaultInstallRoot, "14-apply-policy.ps1");
                var args = new List<string> { "-Root", DefaultInstallRoot, "-SyncNodeOnly" };
                if (!string.IsNullOrWhiteSpace(v2Root))
                {
                    args.Add("-V2rayNRoot");
                    args.Add(v2Root);
                }

                int code = await PayloadAndRunnerService.RunPowerShellScriptAsync(applyScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: false);
                AppendLog($"========== 节点同步完成 (exit={code}) ==========");
            }
            catch (Exception ex)
            {
                AppendLog("[异常] " + ex.Message);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async void ClearSysProxyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            ExpandConsole();
            SetBusy(true, "正在关闭系统代理并刷新 WinINET...");
            try
            {
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string applyScript = Path.Combine(DefaultInstallRoot, "14-apply-policy.ps1");
                var args = new List<string> { "-Root", DefaultInstallRoot, "-ClearSystemProxy" };
                await PayloadAndRunnerService.RunPowerShellScriptAsync(applyScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: false);
            }
            catch (Exception ex)
            {
                AppendLog("[异常] " + ex.Message);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async void RegressionBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            ExpandConsole();
            SetBusy(true, "正在运行 23 项全链路内核回归体检（包含 10 秒网卡抓包防泄漏验证，约需 25 秒）...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 启动 23 项全链路防泄漏回归体检 ==========");

            try
            {
                string v2Root = (V2rayNPathBox.Text ?? "").Trim();
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string regScript = Path.Combine(DefaultInstallRoot, "12-regression.ps1");
                var args = new List<string> { "-Root", DefaultInstallRoot };
                if (!string.IsNullOrWhiteSpace(v2Root))
                {
                    args.Add("-V2rayNRoot");
                    args.Add(v2Root);
                }

                int code = await PayloadAndRunnerService.RunPowerShellScriptAsync(regScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: false);

                if (code == 0)
                {
                    FooterHintText.Text = "健康体检全部通过 (FAIL=0)！系统处于零泄漏健康状态";
                    FooterHintText.Foreground = (Brush)FindResource("SuccessTextBrush");
                    await ShowNativeAlertAsync(
                        "健康体检全部通过",
                        "23 项全链路内核防泄漏体检全部通过 (FAIL=0)！\n\nWindows 内核防火墙、WFP 过滤层、DNS 防泄漏与防篡改规则均处于健康状态。",
                        okText: "完成",
                        isSuccess: true,
                        subtitle: "零泄漏健康验证");
                }
                else
                {
                    FooterHintText.Text = $"健康体检发现未通过项 (exit={code})，请查看控制台输出";
                    FooterHintText.Foreground = (Brush)FindResource("DangerBrush");
                    await ShowNativeAlertAsync(
                        "健康体检报告",
                        $"23 项全链路体检检测到未通过项 (exit={code})。\n\n请在下方实时控制台中查看具体的未通过项目与诊断建议。",
                        okText: "查看日志",
                        isSuccess: false,
                        subtitle: "健康体检报告");
                }
            }
            catch (Exception ex)
            {
                AppendLog("[异常] " + ex.Message);
                await ShowNativeAlertAsync("体检执行异常", ex.Message, okText: "关闭", isSuccess: false, subtitle: "执行异常");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async void UninstallBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            if (_snapshot == null || (!_snapshot.IsDeployed && !_snapshot.BaselineExists))
            {
                await ShowNativeAlertAsync(
                    "系统已处于初始状态",
                    "当前系统未激活任何 AI-Net-Guard 防护规则与计划任务，网络已处于 Windows 初始状态，无需重复卸载。\n\n如需开启零泄漏安全防护，请勾选所需功能后点击右侧【首次一键部署防护】。",
                    okText: "我知道了",
                    isSuccess: true,
                    subtitle: "系统初始状态");
                return;
            }

            bool confirm = await ShowNativeConfirmAsync(
                "确认一键卸载 AI-Net-Guard",
                "此操作将执行底层安全回滚 (09-rollback.ps1)：\n\n" +
                "• 移除所有 AI-Guard-* 防火墙与底层计划任务\n" +
                "• 导入备份，恢复 Windows 原始防火墙出站放行策略 (所有备份规则完整恢复)\n" +
                "• 恢复原始 DHCP / DNS、IPv6 绑定、前缀优先级与 NTP 时间服务\n" +
                "• 恢复默认目录访问权限并重置防护状态\n\n" +
                "卸载后所有 14 项防护功能将全部关闭，界面按钮将同步切为关闭状态。",
                okText: "确认卸载并恢复",
                cancelText: "取消",
                isDestructive: true,
                subtitle: "系统回滚恢复确认",
                icon: "🗑️");

            if (!confirm) return;

            ExpandConsole();
            SetBusy(true, "正在回滚防火墙、DNS、IPv6、计划任务与目录权限...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 开始一键卸载恢复 (09-rollback.ps1) ==========");

            try
            {
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string rbScript = Path.Combine(DefaultInstallRoot, "09-rollback.ps1");
                int code = await PayloadAndRunnerService.RunPowerShellScriptAsync(
                    rbScript,
                    new[] { "-Root", DefaultInstallRoot },
                    AppendLog);

                RefreshDashboard(reloadPolicy: true);
                if (code == 0)
                {
                    AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 已成功恢复系统初始状态 ==========");
                    await ShowNativeAlertAsync(
                        "卸载恢复完成",
                        "已完整卸载 AI-Net-Guard 防护，所有 14 项防护功能已停用，系统已恢复初始网络与防火墙设置。",
                        okText: "完成",
                        isSuccess: true,
                        subtitle: "系统初始状态已还原");
                }
                else
                {
                    await ShowNativeAlertAsync(
                        "回滚过程提示",
                        $"回滚脚本返回非零退出码 (exit={code})，请查看控制台日志了解具体执行细节。",
                        okText: "我知道了",
                        isSuccess: false,
                        subtitle: "回滚状态提示");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] 卸载异常: {ex.Message}");
                await ShowNativeAlertAsync("卸载回滚异常", ex.Message, okText: "关闭", isSuccess: false, subtitle: "执行异常");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private async void RescueBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            if (!EnsureAdminOrPromptElevate()) return;

            bool confirm = await ShowNativeConfirmAsync(
                "确认执行【应急网络脱困】",
                "如果你遇到了无法正常上网、断网或急需恢复原生网络的情况：\n\n" +
                "• 立即将 Windows 防火墙重置为原生全放行 (Default Outbound: Allow)\n" +
                "• 强力清除所有 AI-Guard 防火墙拦截规则与 NRPT 规则\n" +
                "• 终止所有后台自愈守护与计划任务\n" +
                "• 恢复所有物理网卡 DNS 为自动获取 (DHCP) 并重新启用 IPv6\n" +
                "• 重置 Windows 代理设置 (ProxyEnable=0) 与 Winsock 协议栈\n\n" +
                "此操作秒级生效，无需重启电脑即可完全恢复正常上网。",
                okText: "立即脱困恢复",
                cancelText: "取消",
                isDestructive: true,
                subtitle: "极速网络急救",
                icon: "🛟");

            if (!confirm) return;

            ExpandConsole();
            SetBusy(true, "正在执行应急网络脱困与网络急救，请稍候...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 启动应急网络脱困 (Emergency Rescue) ==========");

            try
            {
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));

                string rescueBat = Path.Combine(DefaultInstallRoot, "Emergency-Rescue.bat");
                if (!File.Exists(rescueBat))
                {
                    string localBat = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Emergency-Rescue.bat");
                    if (File.Exists(localBat)) rescueBat = localBat;
                }

                int exitCode = -1;
                if (File.Exists(rescueBat))
                {
                    exitCode = await Task.Run(() =>
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c \"\"{rescueBat}\"\"",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            StandardOutputEncoding = System.Text.Encoding.GetEncoding(936),
                            StandardErrorEncoding = System.Text.Encoding.GetEncoding(936)
                        };
                        using (var proc = Process.Start(psi))
                        {
                            proc.OutputDataReceived += (s, ev) => { if (ev.Data != null) AppendLog(ev.Data); };
                            proc.ErrorDataReceived += (s, ev) => { if (ev.Data != null) AppendLog(ev.Data); };
                            proc.BeginOutputReadLine();
                            proc.BeginErrorReadLine();
                            proc.WaitForExit();
                            return proc.ExitCode;
                        }
                    });
                }
                else
                {
                    AppendLog("[WARN] 未找到 Emergency-Rescue.bat，执行内置指令快速脱困...");
                    await Task.Run(() =>
                    {
                        Process.Start(new ProcessStartInfo("netsh", "advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
                        Process.Start(new ProcessStartInfo("netsh", "winsock reset") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
                        Process.Start(new ProcessStartInfo("ipconfig", "/flushdns") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
                    });
                    exitCode = 0;
                }

                _draftPolicy?.DisableAll();
                RefreshDashboard(reloadPolicy: true);
                AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 应急网络脱困完成 (exit={exitCode}) ==========");

                await ShowNativeAlertAsync(
                    "应急脱困已完成",
                    "已强制解除所有内核出站拦截并刷新网络协议栈！\n\n系统已恢复为 Windows 默认全放行状态与 DHCP 解析，网络已正常连通。",
                    okText: "我知道了",
                    isSuccess: true,
                    subtitle: "网络急救成功");
            }
            catch (Exception ex)
            {
                AppendLog("[异常] " + ex.Message);
                await ShowNativeAlertAsync("脱困执行异常", ex.Message, okText: "确定", isSuccess: false, subtitle: "执行异常");
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;
            RefreshDashboard(reloadPolicy: false);
            FooterHintText.Text = $"已于 {DateTime.Now:HH:mm:ss} 刷新系统实时状态";
        }

        private void OpenDirBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string dir = Directory.Exists(DefaultInstallRoot) ? DefaultInstallRoot : AppDomain.CurrentDomain.BaseDirectory;
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = "\"" + dir + "\"",
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private void ToggleConsoleBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ConsoleBodyBorder.Visibility == Visibility.Visible)
            {
                ConsoleBodyBorder.Visibility = Visibility.Collapsed;
                ToggleConsoleBtn.Content = "▶ 实时执行输出控制台（点击展开）";
            }
            else
            {
                ExpandConsole();
            }
        }

        private void CopyLogBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(LogTextBox.Text))
                {
                    Clipboard.SetText(LogTextBox.Text);
                    FooterHintText.Text = "日志已复制到剪贴板";
                }
            }
            catch { }
        }

        private void ClearLogBtn_Click(object sender, RoutedEventArgs e)
        {
            LogTextBox.Clear();
        }

        private async Task RunAutomatedSmokeTestAsync(string outDir)
        {
            try
            {
                Directory.CreateDirectory(outDir);
                var report = new List<string>();

                // 1. Assert all 15 feature toggles rendered
                if (_toggleBoxes.Count != 15)
                    throw new InvalidOperationException($"Expected 15 toggle switches, got {_toggleBoxes.Count}");
                report.Add($"[PASS] 15 feature toggle controls instantiated across 4 categories");

                // 2. Assert embedded payload presence
                bool hasPayload = PayloadAndRunnerService.HasEmbeddedPayload();
                if (!hasPayload)
                    throw new InvalidOperationException("Embedded payload resource AiNetGuard.Payload.zip is missing");
                report.Add("[PASS] Embedded payload AiNetGuard.Payload.zip verified inside executable");

                // 3. Exercise preset transitions & JSON roundtrip
                ApplyPresetInteractive("StrictLock");
                if (_draftPolicy.AllowCnDirect || _draftPolicy.AllowNcsi || _draftPolicy.ComputePresetKey() != "StrictLock")
                    throw new InvalidOperationException("StrictLock preset state mismatch");
                report.Add("[PASS] StrictLock preset transition verified");

                ApplyPresetInteractive("Compatible");
                if (_draftPolicy.DisablePhysicalIpv6 || _draftPolicy.DisableLlmnrNetbios || _draftPolicy.ComputePresetKey() != "Compatible")
                    throw new InvalidOperationException("Compatible preset state mismatch");
                report.Add("[PASS] Compatible preset transition verified");

                ApplyPresetInteractive("Recommended");
                if (!_draftPolicy.AllowCnDirect || !_draftPolicy.DisablePhysicalIpv6 || _draftPolicy.StrictNrptDoh || _draftPolicy.ComputePresetKey() != "Recommended")
                    throw new InvalidOperationException("Recommended preset state mismatch");
                report.Add("[PASS] Recommended preset transition verified");

                string tempJson = Path.Combine(outDir, "test-guard-policy.json");
                _draftPolicy.SaveToFile(tempJson);
                GuardPolicy reloaded = GuardPolicy.LoadFromFileOrNull(tempJson);
                if (reloaded == null || _draftPolicy.CountDifferences(reloaded) != 0)
                    throw new InvalidOperationException("GuardPolicy JSON round-trip mismatch");
                report.Add("[PASS] GuardPolicy UTF-8 JSON round-trip verified (0 diffs)");

                // Sanitize path box for clean preview screenshot
                _suppressUiEvents = true;
                V2rayNPathBox.Text = @"C:\v2rayN-windows-64";
                UpdateV2rayNValidationBadge(V2rayNPathBox.Text);
                _suppressUiEvents = false;

                await Task.Delay(180);
                UpdateLayout();

                // 4. Capture visual PNG screenshot of rendered WPF client content
                if (Content is FrameworkElement rootVisual && rootVisual.ActualWidth > 100 && rootVisual.ActualHeight > 100)
                {
                    int pxW = (int)Math.Ceiling(rootVisual.ActualWidth * 1.25);
                    int pxH = (int)Math.Ceiling(rootVisual.ActualHeight * 1.25);
                    var rtb = new RenderTargetBitmap(pxW, pxH, 120, 120, PixelFormats.Pbgra32);
                    rtb.Render(rootVisual);

                    var encoder = new PngBitmapEncoder();
                    encoder.Frames.Add(BitmapFrame.Create(rtb));
                    string pngPath = Path.Combine(outDir, "gui-preview.png");
                    using (var fs = new FileStream(pngPath, FileMode.Create, FileAccess.Write))
                    {
                        encoder.Save(fs);
                    }
                    report.Add($"[PASS] Rendered high-DPI WPF screenshot: {pngPath} ({pxW}x{pxH})");
                }

                // 5. Test embedded payload extraction into isolated sandbox folder
                string sandboxExtractDir = Path.Combine(outDir, "extracted-payload");
                int extracted = PayloadAndRunnerService.ExtractEmbeddedPayload(sandboxExtractDir);
                if (extracted < 17)
                    throw new InvalidOperationException($"Expected >=17 extracted payload files, got {extracted}");
                report.Add($"[PASS] Extracted {extracted} embedded payload files cleanly to sandbox");

                File.WriteAllLines(Path.Combine(outDir, "smoke-report.txt"), report);
                Application.Current.Shutdown(0);
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(outDir, "smoke-error.txt"), ex.ToString());
                Application.Current.Shutdown(2);
            }
        }
    }
}
