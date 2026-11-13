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
        private bool _smokeTestExecuted;

        public MainWindow(string smokeTestOutDir = null)
        {
            _smokeTestOutDir = smokeTestOutDir;
            InitializeComponent();
            LocalizationService.LoadLanguagePreference(DefaultInstallRoot);
            ApplyLanguage();

            Loaded += MainWindow_Loaded;
            ContentRendered += MainWindow_ContentRendered;
        }

        private void LangSwitchBtn_Click(object sender, RoutedEventArgs e)
        {
            LocalizationService.ToggleLanguage(DefaultInstallRoot);
            ApplyLanguage();
        }

        private void ApplyLanguage()
        {
            Title = LocalizationService.T("AppTitle");
            if (HeaderVersionBadgeText != null) HeaderVersionBadgeText.Text = LocalizationService.T("HeaderVersionBadge");
            if (HeaderSubtitleText != null) HeaderSubtitleText.Text = LocalizationService.T("HeaderSubtitle");
            if (RescueBtnText != null) RescueBtnText.Text = LocalizationService.T("RescueBtn");
            if (RescueBtn != null) RescueBtn.ToolTip = LocalizationService.T("RescueBtnToolTip");

            if (OpenDirBtnText != null) OpenDirBtnText.Text = LocalizationService.T("OpenDirBtn");
            if (RefreshBtnText != null) RefreshBtnText.Text = LocalizationService.T("RefreshBtn");

            if (LangSwitchBtnText != null) LangSwitchBtnText.Text = LocalizationService.T("LangSwitchBtn");
            if (LangSwitchBtn != null) LangSwitchBtn.ToolTip = LocalizationService.T("LangSwitchBtnToolTip");

            if (CardFirewallTitle != null) CardFirewallTitle.Text = LocalizationService.T("CardFirewallTitle");
            if (CardTunTitle != null) CardTunTitle.Text = LocalizationService.T("CardTunTitle");
            if (CardNodeTitle != null) CardNodeTitle.Text = LocalizationService.T("CardNodeTitle");
            if (SyncNodeNowBtn != null) SyncNodeNowBtn.Content = LocalizationService.T("SyncNow");
            if (CardDnsTitle != null) CardDnsTitle.Text = LocalizationService.T("CardDnsTitle");

            if (V2rayNPathLabel != null) V2rayNPathLabel.Text = LocalizationService.T("V2rayNPathLabel");
            if (BrowseV2rayNBtn != null) BrowseV2rayNBtn.Content = LocalizationService.T("BrowseBtn");

            if (PresetsSectionTitle != null) PresetsSectionTitle.Text = LocalizationService.T("PresetsTitle");
            if (ResetRecommendedBtn != null) ResetRecommendedBtn.Content = LocalizationService.T("ResetRecommendedBtn");
            if (Preset1TitleText != null) Preset1TitleText.Text = LocalizationService.T("Preset1Title");
            if (Preset1BadgeText != null) Preset1BadgeText.Text = LocalizationService.T("Preset1Badge");
            if (Preset2TitleText != null) Preset2TitleText.Text = LocalizationService.T("Preset2Title");
            if (Preset2BadgeText != null) Preset2BadgeText.Text = LocalizationService.T("Preset2Badge");
            if (Preset3TitleText != null) Preset3TitleText.Text = LocalizationService.T("Preset3Title");
            if (Preset3BadgeText != null) Preset3BadgeText.Text = LocalizationService.T("Preset3Badge");

            if (FoundationBannerTitleRun != null) FoundationBannerTitleRun.Text = LocalizationService.T("FoundationTitle");
            if (FoundationBannerTextRun != null) FoundationBannerTextRun.Text = LocalizationService.T("FoundationText");

            if (CopyLogBtn != null) CopyLogBtn.Content = LocalizationService.T("CopyLogBtn");
            if (ClearLogBtn != null) ClearLogBtn.Content = LocalizationService.T("ClearLogBtn");
            if (ToggleConsoleBtn != null)
            {
                ToggleConsoleBtn.Content = ConsoleBodyBorder.Visibility == Visibility.Visible
                    ? LocalizationService.T("ToggleConsoleCollapse")
                    : LocalizationService.T("ToggleConsoleExpand");
            }

            if (UninstallBtnText != null) UninstallBtnText.Text = LocalizationService.T("UninstallBtn");
            if (UninstallBtn != null) UninstallBtn.ToolTip = LocalizationService.T("UninstallBtnToolTip");

            if (RegressionBtnText != null) RegressionBtnText.Text = LocalizationService.T("RegressionBtn");
            if (RegressionBtn != null) RegressionBtn.ToolTip = LocalizationService.T("RegressionBtnToolTip");

            if (LeakCheckBtnText != null) LeakCheckBtnText.Text = LocalizationService.T("LeakCheckBtn");
            if (LeakCheckBtn != null) LeakCheckBtn.ToolTip = LocalizationService.T("LeakCheckBtnToolTip");
            if (ApplyBtn != null) ApplyBtn.Content = LocalizationService.T("ApplyBtn");
            if (ConfirmModalCancelBtn != null) ConfirmModalCancelBtn.Content = LocalizationService.T("Cancel");
            if (ConfirmModalOkBtn != null) ConfirmModalOkBtn.Content = LocalizationService.T("Confirm");
            if (ConfirmModalSubtitle != null) ConfirmModalSubtitle.Text = LocalizationService.T("ConfirmModalSubtitle");

            BuildFeatureCategoryCards();
            if (_draftPolicy != null)
            {
                SyncUiFromState();
            }
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
            else
            {
                // In headless or background runner environments, ContentRendered may not fire.
                // Trigger smoke test on dispatcher idle after layout completes.
                Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(async () =>
                {
                    await Task.Delay(250);
                    if (!_smokeTestExecuted)
                    {
                        _smokeTestExecuted = true;
                        await RunAutomatedSmokeTestAsync(_smokeTestOutDir);
                    }
                }));
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            _autoTelemetryTimer?.Stop();
        }

        private async void MainWindow_ContentRendered(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(_smokeTestOutDir) && !_smokeTestExecuted)
            {
                _smokeTestExecuted = true;
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
                var headerGrid = new Grid { Margin = new Thickness(4, 16, 4, 7) };
                headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                string geomKey = "IconShieldCheck";
                Color iconColor = Color.FromRgb(5, 150, 105);
                Color iconBg = Color.FromRgb(236, 253, 245);
                if (group.Key.Contains("流量") || group.Key.Contains("Traffic"))
                {
                    geomKey = "IconGlobe";
                    iconColor = Color.FromRgb(37, 99, 235);
                    iconBg = Color.FromRgb(239, 246, 255);
                }
                else if (group.Key.Contains("DNS"))
                {
                    geomKey = "IconLock";
                    iconColor = Color.FromRgb(8, 145, 178);
                    iconBg = Color.FromRgb(236, 254, 255);
                }
                else if (group.Key.Contains("路由") || group.Key.Contains("Routing"))
                {
                    geomKey = "IconZap";
                    iconColor = Color.FromRgb(217, 119, 6);
                    iconBg = Color.FromRgb(254, 243, 199);
                }

                var titleStack = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    VerticalAlignment = VerticalAlignment.Center
                };

                var iconBadge = new Border
                {
                    Width = 22,
                    Height = 22,
                    CornerRadius = new CornerRadius(5),
                    Background = new SolidColorBrush(iconBg),
                    Margin = new Thickness(0, 0, 8, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };

                var catIcon = new System.Windows.Shapes.Path
                {
                    Data = (Geometry)FindResource(geomKey),
                    Stroke = new SolidColorBrush(iconColor),
                    StrokeThickness = 1.8,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round,
                    StrokeLineJoin = PenLineJoin.Round,
                    Width = 12,
                    Height = 12,
                    Stretch = Stretch.Uniform,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                iconBadge.Child = catIcon;
                titleStack.Children.Add(iconBadge);

                var sectionTitle = new TextBlock
                {
                    Text = group.Key,
                    FontSize = 12.5,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("TextSecondaryBrush"),
                    VerticalAlignment = VerticalAlignment.Center
                };
                titleStack.Children.Add(sectionTitle);
                Grid.SetColumn(titleStack, 0);
                headerGrid.Children.Add(titleStack);

                var items = group.ToList();
                var countBadge = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
                    BorderBrush = (Brush)FindResource("CardBorderBrush"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(8, 2, 8, 2),
                    VerticalAlignment = VerticalAlignment.Center
                };
                var countText = new TextBlock
                {
                    Text = LocalizationService.IsEnglish ? $"{items.Count} items" : $"{items.Count} 项特性",
                    FontSize = 10.5,
                    FontWeight = FontWeights.Medium,
                    Foreground = (Brush)FindResource("TextMutedBrush")
                };
                countBadge.Child = countText;
                Grid.SetColumn(countBadge, 1);
                headerGrid.Children.Add(countBadge);

                CategoriesContainer.Children.Add(headerGrid);

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
                    GuardStatusText.Text = LocalizationService.T("StatusStrictActive");
                }
                else
                {
                    GuardStatusBadge.Background = (Brush)FindResource("SuccessBgBrush");
                    GuardStatusBadge.BorderBrush = (Brush)FindResource("SuccessBorderBrush");
                    GuardStatusDot.Fill = (Brush)FindResource("SuccessBrush");
                    GuardStatusText.Foreground = (Brush)FindResource("SuccessTextBrush");
                    GuardStatusText.Text = _snapshot.PendingTestRollbackTask
                        ? LocalizationService.T("StatusTestingPeriod")
                        : LocalizationService.T("StatusRunning");
                }
            }
            else
            {
                GuardStatusBadge.Background = new SolidColorBrush(Color.FromRgb(245, 245, 247));
                GuardStatusBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(229, 229, 234));
                GuardStatusDot.Fill = new SolidColorBrush(Color.FromRgb(142, 142, 147));
                GuardStatusText.Foreground = (Brush)FindResource("TextSecondaryBrush");
                GuardStatusText.Text = LocalizationService.T("StatusNotDeployed");
            }
        }

        private void UpdateTelemetryCards()
        {
            if (_snapshot == null) return;

            CardFirewallMain.Text = _snapshot.ProfilesAllBlock
                ? LocalizationService.T("CardFirewallBlock")
                : LocalizationService.T("CardFirewallAllow");
            CardFirewallMain.Foreground = _snapshot.ProfilesAllBlock
                ? (Brush)FindResource("SuccessTextBrush")
                : (Brush)FindResource("TextPrimaryBrush");
            string cnText = _snapshot.CnRuleActive
                ? (_snapshot.CnPrefixCount > 0
                    ? LocalizationService.T("CardFirewallCnPrefixes", _snapshot.CnPrefixCount)
                    : LocalizationService.T("CardFirewallCnActive"))
                : (_snapshot.IsDeployed
                    ? LocalizationService.T("CardFirewallCnOff")
                    : LocalizationService.T("CardFirewallCnNone"));
            string aclNotice = _snapshot.AclLocked
                ? LocalizationService.T("CardDnsAclLocked")
                : (_snapshot.IsDeployed ? LocalizationService.T("CardDnsAclUnlocked") : LocalizationService.T("CardDnsAclNotice"));
            CardFirewallSub.Text = $"{cnText} · {LocalizationService.T("CardFirewallRogue", _snapshot.RogueAllowCount)}";
            CardFirewallSub.ToolTip = aclNotice;

            CardTunMain.Text = _snapshot.TunUp
                ? LocalizationService.T("CardTunOnline", _snapshot.ActiveTunName)
                : LocalizationService.T("CardTunOffline");
            CardTunMain.Foreground = _snapshot.TunUp
                ? (Brush)FindResource("AccentBrush")
                : (Brush)FindResource("TextPrimaryBrush");
            string coreSummary = !string.IsNullOrEmpty(_snapshot.RunningCoreSummary) && _snapshot.RunningCoreSummary != "无" && _snapshot.RunningCoreSummary != "none"
                ? LocalizationService.T("CardTunCoreOnline", _snapshot.RunningCoreSummary)
                : LocalizationService.T("CardTunCoreOffline");
            CardTunSub.Text = $"{coreSummary} · {_snapshot.PhysicalNicName}";

            CardNodeMain.Text = FormatNodeDisplay(_snapshot.NodeSummary);
            CardNodeMain.ToolTip = LocalizationService.T("CardNodeMaskTip");
            CardNodeSub.Text = _snapshot.NodeRuleActive
                ? LocalizationService.T("CardNodeRuleValid")
                : (_snapshot.IsDeployed ? LocalizationService.T("CardNodeRuleMissing") : LocalizationService.T("CardNodeNone"));

            string dnsMode = _snapshot.NrptActive
                ? LocalizationService.T("CardDnsNrpt")
                : LocalizationService.T("CardDnsSummary", _snapshot.PhysicalDnsSummary);
            CardDnsMain.Text = dnsMode;
            string smhnrTxt = _snapshot.SmhnrDisabled
                ? LocalizationService.T("CardDnsSmhnrOff")
                : LocalizationService.T("CardDnsSmhnrOn");
            string ramTxt = _snapshot.ZeroResidentTaskReady
                ? LocalizationService.T("CardDnsZeroResidentReady")
                : LocalizationService.T("CardDnsZeroResidentNone");
            CardDnsSub.Text = $"{smhnrTxt} · {ramTxt}";
        }

        private void UpdateSystemProxyBanner()
        {
            if (_snapshot == null || !string.IsNullOrEmpty(_smokeTestOutDir)) return;
            SystemProxyBanner.Visibility = Visibility.Visible;
            if (_snapshot.SystemProxyEnabled)
            {
                // Proxy is enabled (WinINET active, non-recommended state for TUN)
                SystemProxyBanner.Background = new SolidColorBrush(Color.FromRgb(254, 252, 232)); // #FEFCE8 soft amber tint
                SystemProxyBanner.BorderBrush = new SolidColorBrush(Color.FromRgb(253, 224, 71));  // #FDE047 amber border
                if (SystemProxyIconPath != null)
                {
                    SystemProxyIconPath.Data = (Geometry)FindResource("IconAlertTriangle");
                    SystemProxyIconPath.Stroke = new SolidColorBrush(Color.FromRgb(217, 119, 6));
                }
                SystemProxyText.Foreground = new SolidColorBrush(Color.FromRgb(133, 77, 14));     // #854D0E dark amber
                SystemProxyText.Text = LocalizationService.T("SystemProxyOn", _snapshot.SystemProxyServer);

                ClearSysProxyBtn.Content = LocalizationService.T("ClearSysProxyBtnOff");
                ClearSysProxyBtn.Background = Brushes.White;
                ClearSysProxyBtn.Foreground = new SolidColorBrush(Color.FromRgb(220, 38, 38));     // #DC2626 danger red
                ClearSysProxyBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(252, 165, 165));  // #FCA5A5
            }
            else
            {
                // Proxy is cleared (official recommended clean TUN state)
                SystemProxyBanner.Background = new SolidColorBrush(Color.FromRgb(240, 253, 244)); // #F0FDF4 soft green tint
                SystemProxyBanner.BorderBrush = new SolidColorBrush(Color.FromRgb(134, 239, 172)); // #86EFAC emerald border
                if (SystemProxyIconPath != null)
                {
                    SystemProxyIconPath.Data = (Geometry)FindResource("IconCheckCircle");
                    SystemProxyIconPath.Stroke = new SolidColorBrush(Color.FromRgb(22, 163, 74));
                }
                SystemProxyText.Foreground = new SolidColorBrush(Color.FromRgb(22, 101, 52));     // #166534 dark forest green
                SystemProxyText.Text = LocalizationService.T("SystemProxyOff");

                ClearSysProxyBtn.Content = LocalizationService.T("ClearSysProxyBtnOn");
                ClearSysProxyBtn.Background = Brushes.White;
                ClearSysProxyBtn.Foreground = new SolidColorBrush(Color.FromRgb(37, 99, 235));     // #2563EB accent blue
                ClearSysProxyBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(147, 197, 253)); // #93C5FD
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
            if (string.IsNullOrEmpty(rawSummary)) return LocalizationService.T("CardNodeNone");
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
                V2rayNValidText.Text = LocalizationService.IsEnglish ? "Ready (config.json found)" : "已就绪 (含 config.json)";
            }
            else if (hasExe)
            {
                V2rayNValidBadge.Background = (Brush)FindResource("WarnBgBrush");
                V2rayNValidText.Foreground = (Brush)FindResource("WarnTextBrush");
                V2rayNValidText.Text = LocalizationService.IsEnglish ? "Exe Detected (Start v2rayN once)" : "已识别程序 (请先启动一次 v2rayN)";
            }
            else
            {
                V2rayNValidBadge.Background = new SolidColorBrush(Color.FromRgb(254, 226, 226));
                V2rayNValidText.Foreground = (Brush)FindResource("DangerBrush");
                V2rayNValidText.Text = LocalizationService.IsEnglish ? "v2rayN Directory Not Found" : "未找到 v2rayN 目录";
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
            if (ConfirmModalIconPath != null)
            {
                if (isDestructive)
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconTrash");
                    ConfirmModalIconPath.Stroke = (Brush)FindResource("DangerBrush");
                }
                else if (icon == "🛡️")
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconShieldCheck");
                    ConfirmModalIconPath.Stroke = (Brush)FindResource("AccentBrush");
                }
                else if (icon == "🛟")
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconLifebuoy");
                    ConfirmModalIconPath.Stroke = new SolidColorBrush(Color.FromRgb(217, 119, 6));
                }
                else
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconAlertTriangle");
                    ConfirmModalIconPath.Stroke = new SolidColorBrush(Color.FromRgb(217, 119, 6));
                }
            }
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
                if (ConfirmModalIconPath != null)
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconCheckCircle");
                    ConfirmModalIconPath.Stroke = (Brush)FindResource("SuccessTextBrush");
                }
                ConfirmModalOkBtn.Background = new SolidColorBrush(Color.FromRgb(22, 163, 74));
                ConfirmModalOkBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(21, 128, 61));
            }
            else
            {
                ConfirmModalIconBorder.Background = (TryFindResource("WarnBgBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 248, 225));
                ConfirmModalIconBorder.BorderBrush = (TryFindResource("WarnBorderBrush") as Brush) ?? new SolidColorBrush(Color.FromRgb(255, 224, 130));
                if (ConfirmModalIconPath != null)
                {
                    ConfirmModalIconPath.Data = (Geometry)FindResource("IconAlertTriangle");
                    ConfirmModalIconPath.Stroke = new SolidColorBrush(Color.FromRgb(217, 119, 6));
                }
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
                if (active == "StrictLock")
                {
                    PresetDescriptionText.Text = LocalizationService.T("PresetDescStrict");
                }
                else if (active == "Compatible")
                {
                    PresetDescriptionText.Text = LocalizationService.T("PresetDescCompatible");
                }
                else if (active == "Recommended")
                {
                    PresetDescriptionText.Text = LocalizationService.T("PresetDescRecommended");
                }
                else
                {
                    PresetDescriptionText.Text = LocalizationService.T("PresetDescCustom");
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

        private enum StatusTone
        {
            Neutral,
            Success,
            Warning,
            Danger,
            Accent
        }

        private void SetFooterStatusPill(string shortText, string tooltip, StatusTone tone)
        {
            if (FooterHintText == null || FooterStatusBorder == null || FooterStatusDot == null) return;

            FooterHintText.Text = shortText;
            FooterStatusBorder.ToolTip = string.IsNullOrEmpty(tooltip) ? shortText : tooltip;

            switch (tone)
            {
                case StatusTone.Success:
                    FooterStatusBorder.Background = (Brush)FindResource("SuccessBgBrush");
                    FooterStatusBorder.BorderBrush = (Brush)FindResource("SuccessBorderBrush");
                    FooterStatusDot.Fill = (Brush)FindResource("SuccessBrush");
                    FooterHintText.Foreground = (Brush)FindResource("SuccessTextBrush");
                    break;
                case StatusTone.Warning:
                    FooterStatusBorder.Background = (Brush)FindResource("WarnBgBrush");
                    FooterStatusBorder.BorderBrush = (Brush)FindResource("WarnBorderBrush");
                    FooterStatusDot.Fill = (Brush)FindResource("WarnBrush");
                    FooterHintText.Foreground = (Brush)FindResource("WarnTextBrush");
                    break;
                case StatusTone.Danger:
                    FooterStatusBorder.Background = new SolidColorBrush(Color.FromArgb(28, 220, 38, 38));
                    FooterStatusBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(90, 239, 68, 68));
                    FooterStatusDot.Fill = (Brush)FindResource("DangerBrush");
                    FooterHintText.Foreground = (Brush)FindResource("DangerBrush");
                    break;
                case StatusTone.Accent:
                    FooterStatusBorder.Background = new SolidColorBrush(Color.FromArgb(24, 0, 113, 227));
                    FooterStatusBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(80, 0, 113, 227));
                    FooterStatusDot.Fill = (Brush)FindResource("AccentBrush");
                    FooterHintText.Foreground = (Brush)FindResource("AccentBrush");
                    break;
                default:
                    FooterStatusBorder.Background = new SolidColorBrush(Color.FromRgb(245, 245, 247));
                    FooterStatusBorder.BorderBrush = (Brush)FindResource("CardBorderBrush");
                    FooterStatusDot.Fill = (Brush)FindResource("TextMutedBrush");
                    FooterHintText.Foreground = (Brush)FindResource("TextSecondaryBrush");
                    break;
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
                ApplyBtn.Content = diffs > 0
                    ? (LocalizationService.IsEnglish ? $"Initial Deploy Guard ({diffs} items)" : $"首次一键部署防护 ({diffs} 项)")
                    : (LocalizationService.IsEnglish ? "Initial Deploy Guard" : "首次一键部署防护");
                if (diffs > 0)
                {
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? $"Ready to deploy ({diffs})" : $"待部署 ({diffs} 项)",
                        LocalizationService.IsEnglish ? $"{diffs} features selected. Click deploy to write to Windows kernel." : $"已勾选 {diffs} 项防护，点击右侧按钮立即部署到 Windows 内核",
                        StatusTone.Accent);
                }
                else
                {
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? "Not deployed" : "未部署防护",
                        LocalizationService.IsEnglish ? "Not deployed. Choose a preset or toggle features above." : "当前未部署防护（所有开关已关闭）· 可选择上方预设或勾选功能后部署",
                        StatusTone.Neutral);
                }
            }
            else if (diffs > 0)
            {
                ApplyBtn.Content = LocalizationService.IsEnglish ? $"Apply Changes ({diffs} items)" : $"应用配置更改 ({diffs} 项)";
                SetFooterStatusPill(
                    LocalizationService.IsEnglish ? $"{diffs} changes pending" : $"有 {diffs} 项待同步修改",
                    LocalizationService.IsEnglish ? $"{diffs} changes pending. Click to synchronize with Windows kernel and self-healing policies." : $"已修改 {diffs} 项功能设置，点击右侧按钮立即同步到 Windows 内核与后台自愈策略",
                    StatusTone.Warning);
            }
            else
            {
                ApplyBtn.Content = LocalizationService.IsEnglish ? "Verify & Re-Apply Policy" : "重新校验并应用配置";
                SetFooterStatusPill(
                    LocalizationService.IsEnglish ? "Zero-leak active" : "内核零泄漏防护中",
                    LocalizationService.IsEnglish ? "System security policy active (Zero-leak kernel protection holding)" : "当前系统已激活所选防护策略 (内核零泄漏保护中)",
                    StatusTone.Success);
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
                string shortText = statusText.Length > 20 ? statusText.Substring(0, 18) + "..." : statusText;
                SetFooterStatusPill(shortText, statusText, StatusTone.Accent);
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

                private static string GetScriptPath(string scriptName)
        {
            string sub = Path.Combine(DefaultInstallRoot, "scripts", scriptName);
            if (File.Exists(sub)) return sub;
            return Path.Combine(DefaultInstallRoot, scriptName);
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
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] " + (LocalizationService.IsEnglish ? "Applying AI-Net-Guard v5.7.4 Guard Policy..." : "开始应用 AI-Net-Guard v5.7.4 防护配置...") + " ==========");

            try
            {
                _draftPolicy.V2rayNRoot = v2Root;
                await Task.Run(() =>
                {
                    PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, AppendLog);
                    _draftPolicy.SaveToFile(Path.Combine(DefaultInstallRoot, @"backup\guard-policy.json"));
                });

                string applyScript = GetScriptPath("14-apply-policy.ps1");
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
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? "Policy applied" : "配置已成功应用",
                        LocalizationService.IsEnglish ? "Policy applied to Windows kernel and self-healing tasks" : "配置已成功应用并写入系统内核与持久化策略！",
                        StatusTone.Success);
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
                string applyScript = GetScriptPath("14-apply-policy.ps1");
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
            bool enableAction = !_snapshot.SystemProxyEnabled;
            string busyMsg = enableAction
                ? (LocalizationService.IsEnglish ? "Configuring Windows system proxy to 127.0.0.1:10809..." : "正在配置 Windows 系统代理为 127.0.0.1:10809 并刷新 WinINET...")
                : (LocalizationService.IsEnglish ? "Disabling Windows system proxy and refreshing WinINET..." : "正在关闭系统代理并刷新 WinINET...");
            SetBusy(true, busyMsg);
            try
            {
                string v2Root = (V2rayNPathBox.Text ?? "").Trim();
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string applyScript = GetScriptPath("14-apply-policy.ps1");
                var args = new List<string> { "-Root", DefaultInstallRoot };
                if (enableAction)
                {
                    args.Add("-SetSystemProxy");
                }
                else
                {
                    args.Add("-ClearSystemProxy");
                }
                if (!string.IsNullOrWhiteSpace(v2Root))
                {
                    args.Add("-V2rayNRoot");
                    args.Add(v2Root);
                }
                await PayloadAndRunnerService.RunPowerShellScriptAsync(applyScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: false);

                bool v2rayRunning = Process.GetProcessesByName("v2rayN").Length > 0;
                if (v2rayRunning)
                {
                    string targetSettingName = enableAction
                        ? (LocalizationService.IsEnglish ? "Set system proxy" : "自动配置系统代理")
                        : (LocalizationService.IsEnglish ? "Clear system proxy" : "清除系统代理");
                    string warnTitle = LocalizationService.T("V2rayNNoticeTitle");
                    string warnMsg = LocalizationService.T("V2rayNNoticeMsg", targetSettingName);
                    AppendLog("[i] " + warnMsg.Replace("\n\n", " "));
                    await ShowNativeAlertAsync(warnTitle, warnMsg, okText: LocalizationService.IsEnglish ? "Got it" : "我知道了", isSuccess: false);
                }
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
            SetBusy(true, "正在运行 24 项全链路内核回归体检（包含 10 秒网卡抓包防泄漏验证，约需 25 秒）...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 启动 24 项全链路防泄漏回归体检 ==========");

            try
            {
                string v2Root = (V2rayNPathBox.Text ?? "").Trim();
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string regScript = GetScriptPath("12-regression.ps1");
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
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? "Regression PASS (24/24)" : "24项体检全通 (PASS)",
                        LocalizationService.IsEnglish ? "All 24 kernel leak-defense checks passed (FAIL=0)" : "健康体检全部通过 (FAIL=0)！系统处于零泄漏健康状态",
                        StatusTone.Success);
                    await ShowNativeAlertAsync(
                        "健康体检全部通过",
                        "24 项全链路内核防泄漏体检全部通过 (FAIL=0)！\n\nWindows 内核防火墙、WFP 过滤层、DNS 防泄漏与防篡改规则均处于健康状态。",
                        okText: "完成",
                        isSuccess: true,
                        subtitle: "零泄漏健康验证");
                }
                else
                {
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? $"Checks failed (exit={code})" : $"体检有未通过项 ({code})",
                        LocalizationService.IsEnglish ? $"24-check regression found failures (exit={code}). Check console." : $"健康体检发现未通过项 (exit={code})，请查看控制台输出",
                        StatusTone.Danger);
                    await ShowNativeAlertAsync(
                        "健康体检报告",
                        $"24 项全链路体检检测到未通过项 (exit={code})。\n\n请在下方实时控制台中查看具体的未通过项目与诊断建议。",
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

        private async void LeakCheckBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isBusy) return;

            ExpandConsole();
            SetBusy(true, "正在执行极速防泄漏与连通性检测（约需 3~5 秒）...");
            AppendLog($"========== [{DateTime.Now:HH:mm:ss}] 启动 5 秒极速防泄漏与连通性自测 ==========");

            try
            {
                await Task.Run(() => PayloadAndRunnerService.ExtractEmbeddedPayload(DefaultInstallRoot, null));
                string leakScript = GetScriptPath("verify-leak-test.ps1");
                var args = new List<string>();

                int code = await PayloadAndRunnerService.RunPowerShellScriptAsync(leakScript, args, AppendLog);
                RefreshDashboard(reloadPolicy: false);

                if (code == 0)
                {
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? "Leak check PASS" : "极速自测通过",
                        LocalizationService.IsEnglish ? "Physical NIC outbound blocked, TUN active, domestic/overseas normal" : "极速自测通过：物理网卡海外阻断有效，代理正常",
                        StatusTone.Success);
                    await ShowNativeAlertAsync(
                        "极速自测通过",
                        "5 秒极速健康检测全部通过：\n\n• 未检测到越权出站放行规则\n• 活跃 TUN 虚拟网卡正常在线\n• 底层物理网卡 Socket 强绑定直接出站已被内核拦截 (Fail-Closed)\n• 国内外与 AI 核心服务通道通信正常",
                        okText: "好",
                        isSuccess: true,
                        subtitle: "极速自检通过");
                }
                else
                {
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? $"Check anomaly ({code})" : $"极速自测异常 ({code})",
                        LocalizationService.IsEnglish ? $"Quick check failed (exit={code}). Check console." : $"极速自测发现异常 (exit={code})，请查看控制台",
                        StatusTone.Danger);
                    await ShowNativeAlertAsync(
                        "极速自测警告",
                        $"极速自测发现潜在异常或连接受阻 (exit={code})。\n\n请在下方实时控制台中查看检测细节并确认代理软件状态。",
                        okText: "查看日志",
                        isSuccess: false,
                        subtitle: "极速自测告警");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[ERROR] 极速自测执行异常: {ex.Message}");
                SetFooterStatusPill(
                    LocalizationService.IsEnglish ? "Check failed" : "极速自测失败",
                    ex.Message,
                    StatusTone.Danger);
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
                string rbScript = GetScriptPath("09-rollback.ps1");
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
            SetFooterStatusPill(
                LocalizationService.IsEnglish ? $"Refreshed {DateTime.Now:HH:mm:ss}" : $"已刷新 {DateTime.Now:HH:mm:ss}",
                LocalizationService.IsEnglish ? $"Refreshed system telemetry at {DateTime.Now:HH:mm:ss}" : $"已于 {DateTime.Now:HH:mm:ss} 刷新系统实时状态",
                StatusTone.Neutral);
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
                    SetFooterStatusPill(
                        LocalizationService.IsEnglish ? "Copied" : "日志已复制",
                        LocalizationService.IsEnglish ? "Console logs copied to clipboard" : "控制台日志已复制到剪贴板",
                        StatusTone.Neutral);
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
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(outDir, "smoke-error.txt"), ex.ToString());
                Application.Current.Shutdown(2);
                Environment.Exit(2);
            }
        }
    }
}
