# ******************************************************************
# Log4jScan GUI (PowerShell)
# ------------------------------------------------------------------
# One entry point, two front-ends:
#   * Windows              -> WPF graphical window (runspace-isolated)
#   * macOS / Linux        -> Terminal.Gui TUI if installed, otherwise
#                             an interactive console menu (-NoGui also
#                             forces the plain console flow)
#
# Usage:
#   pwsh Log4jScan-GUI.ps1                 # auto-select front-end
#   pwsh Log4jScan-GUI.ps1 -NoGui          # interactive console mode
#   powershell -ExecutionPolicy Bypass -File Log4jScan-GUI.ps1   # Windows
# ******************************************************************

[CmdletBinding()]
param(
    [switch]$NoGui,
    [string]$TargetFile = $null    # optional URL list to preload
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Modules/Log4jScan/Log4jScan.psd1') -Force

$isWindows = $IsWindows -or ($PSVersionTable.PSVersion.Major -le 5)

function Show-ConsoleMenu {
    <# Interactive console front-end (also the non-Windows fallback). #>
    Write-Host ''
    Write-Host '==================================================' -ForegroundColor Cyan
    Write-Host ' Log4jScan - Log4Shell vulnerability scanner (PS)' -ForegroundColor Cyan
    Write-Host '==================================================' -ForegroundColor Cyan

    $script:CveList = Get-Log4jCveInfo
    $dbMeta = (Get-Log4jCveDatabase).metadata
    Write-Host ("[*] CVE knowledge base v{0} ({1}) - {2} CVEs tracked" -f `
        $dbMeta.version, (Get-Log4jCveDatabasePath), $script:CveList.Count) -ForegroundColor DarkGray

    while ($true) {
        Write-Host ''
        Write-Host ' [1] Scan targets            [4] Export last results'
        Write-Host ' [2] Update CVE database     [5] Quit' -ForegroundColor Yellow
        $choice = Read-Host 'Choice'
        switch ($choice) {
            '1' {
                $targets = Read-Host 'Target URL(s), comma separated'
                $tArr = $targets -split ',\s*' | Where-Object { $_ }
                $cveIn = Read-Host ("CVEs to test (default: CVE-2021-44228; '*' = all; known: {0})" -f (($script:CveList | ForEach-Object Cve) -join ', '))
                $cves = if ([string]::IsNullOrWhiteSpace($cveIn)) { @('CVE-2021-44228') } else { $cveIn -split ',\s*' }
                $waf = (Read-Host 'WAF-bypass payloads? (y/N)') -match '^[Yy]'
                $all = (Read-Host 'Run POST form + JSON tests too? (y/N)') -match '^[Yy]'
                $script:LastResults = Invoke-Log4jTargetScan -Target $tArr -Cve $cves -WafBypass:$waf -RunAllTests:$all
                $script:LastResults | Format-Table Target, Cve, Severity, Verdict -AutoSize
            }
            '2' {
                Write-Host '[*] Contacting NVD API 2.0 and community payload feeds...' -ForegroundColor Cyan
                $r = Update-Log4jCveDatabase
                Write-Host ("[+] Done: {0} total CVEs (+{1} new, refreshed {2}, +{3} WAF payloads)" -f `
                    $r.TotalCves, $r.AddedFromNvd, $r.RefreshedFromNvd, $r.NewWafPayloads) -ForegroundColor Green
                $script:CveList = Get-Log4jCveInfo
            }
            '4' {
                if (-not $script:LastResults) { Write-Host '[!] No results yet.' -ForegroundColor Red; continue }
                $out = Read-Host 'Output CSV path'
                $script:LastResults | Select-Object Target, Cve, Title, Severity, Cvss, Verdict, CallbackHost, Timestamp |
                    Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
                Write-Host "[+] Saved to $out" -ForegroundColor Green
            }
            '5' { return }
            default { Write-Host '[!] Invalid choice' -ForegroundColor Red }
        }
    }
}

function Show-WpfGui {
    <# Native WPF window for Windows PowerShell / pwsh on Windows. #>
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

    [xml]$xaml = @'
    <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
            xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
            Title="Log4jScan - Log4Shell Vulnerability Scanner" Height="720" Width="1080"
            WindowStartupLocation="CenterScreen" Background="#1e1e2e">
      <Grid Margin="12">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="220"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
          <TextBlock Text="Log4jScan" FontSize="22" FontWeight="Bold" Foreground="#89b4fa"/>
          <TextBlock x:Name="DbStatus" Text="" FontSize="12" Foreground="#a6adc8" VerticalAlignment="Bottom" Margin="16,0,0,4"/>
        </StackPanel>

        <GroupBox Grid.Row="1" Header="Targets (one URL per line)" Foreground="#cdd6f4" BorderBrush="#45475a">
          <TextBox x:Name="TargetsBox" AcceptsReturn="True" FontFamily="Consolas"
                   VerticalScrollBarVisibility="Auto" Background="#313244" Foreground="#f5f5f5" BorderThickness="0"/>
        </GroupBox>

        <WrapPanel Grid.Row="2" Margin="0,8">
          <StackPanel Orientation="Horizontal" Margin="0,0,16,0">
            <TextBlock Text="CVEs:" Foreground="#cdd6f4" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <ComboBox x:Name="CveCombo" Width="260" SelectionMode="Multiple"/>
          </StackPanel>
          <CheckBox x:Name="WafCheck" Content="WAF-bypass payloads" Foreground="#cdd6f4" Margin="0,0,16,0"/>
          <CheckBox x:Name="AllTestsCheck" Content="POST form + JSON" Foreground="#cdd6f4" Margin="0,0,16,0"/>
          <TextBlock Text="Callback host:" Foreground="#cdd6f4" VerticalAlignment="Center" Margin="0,0,6,0"/>
          <TextBox x:Name="CallbackBox" Width="180" Background="#313244" Foreground="#f5f5f5" BorderThickness="0" Padding="4,2"/>
          <Button x:Name="ScanBtn" Content="  START SCAN  " Margin="16,0,8,0" Padding="10,6"
                  Background="#a6e3a1" FontWeight="Bold"/>
          <Button x:Name="UpdateBtn" Content=" UPDATE CVE DB " Padding="10,6" Background="#fab387" FontWeight="Bold"/>
          <Button x:Name="ExportBtn" Content=" Export CSV " Padding="10,6" Background="#89b4fa" FontWeight="Bold"/>
        </WrapPanel>

        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="380"/>
          </Grid.ColumnDefinitions>
          <GroupBox Grid.Column="0" Header="Results" Foreground="#cdd6f4" BorderBrush="#45475a">
            <DataGrid x:Name="ResultsGrid" AutoGenerateColumns="False" IsReadOnly="True"
                      Background="#313244" Foreground="#f5f5f5" RowBackground="#1e1e2e"
                      AlternatingRowBackground="#26263a" BorderThickness="0" HeadersVisibility="Column">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Verdict" Binding="{Binding Verdict}" Width="150"/>
                <DataGridTextColumn Header="Target" Binding="{Binding Target}" Width="*"/>
                <DataGridTextColumn Header="CVE" Binding="{Binding Cve}" Width="140"/>
                <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="90"/>
                <DataGridTextColumn Header="CVSS" Binding="{Binding Cvss}" Width="60"/>
                <DataGridTextColumn Header="Time" Binding="{Binding Timestamp}" Width="150"/>
              </DataGrid.Columns>
            </DataGrid>
          </GroupBox>
          <GroupBox Grid.Column="1" Header="Live log" Foreground="#cdd6f4" BorderBrush="#45475a">
            <TextBox x:Name="LogBox" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                     VerticalScrollBarVisibility="Auto" Background="#11111b" Foreground="#94e2d5" BorderThickness="0"/>
          </GroupBox>
        </Grid>

        <ProgressBar x:Name="Progress" Grid.Row="4" Height="6" Margin="0,8,0,0" IsIndeterminate="False" Foreground="#a6e3a1"/>
      </Grid>
    </Window>
'@

    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Named element references
    $targetsBox  = $window.FindName('TargetsBox')
    $dbStatus    = $window.FindName('DbStatus')
    $cveCombo    = $window.FindName('CveCombo')
    $wafCheck    = $window.FindName('WafCheck')
    $allTests    = $window.FindName('AllTestsCheck')
    $callbackBox = $window.FindName('CallbackBox')
    $scanBtn     = $window.FindName('ScanBtn')
    $updateBtn   = $window.FindName('UpdateBtn')
    $exportBtn   = $window.FindName('ExportBtn')
    $resultsGrid = $window.FindName('ResultsGrid')
    $logBox      = $window.FindName('LogBox')
    $progress    = $window.FindName('Progress')

    function Write-GuiLog([string]$msg) {
        $logBox.AppendText($msg + "`r`n")
        $logBox.ScrollToEnd()
    }

    # Populate CVE combo + DB status from the module
    $cveInfo = Get-Log4jCveInfo
    foreach ($c in $cveInfo) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = ('{0}  [{1}]' -f $c.Cve, $c.Severity)
        $item.Tag = $c.Cve
        if ($c.IsDefault) { $item.IsSelected = $true }
        $cveCombo.Items.Add($item) | Out-Null
    }
    $meta = (Get-Log4jCveDatabase).metadata
    $dbStatus.Text = ('Knowledge base v{0} - {1} CVEs - source: {2}' -f $meta.version, $cveInfo.Count, (Split-Path (Get-Log4jCveDatabasePath) -Leaf))

    if ($TargetFile -and (Test-Path $TargetFile)) {
        $targetsBox.Text = (Get-Content $TargetFile -Raw).Trim()
    }

    # ---- Background runspace plumbing ------------------------------------
    $ps = [powershell]::Create()
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'
    $rs.Open()
    $ps.Runspace = $rs
    # Import the module inside the worker runspace so scans never block the UI thread
    $ps.AddScript("Import-Module '$(Join-Path $PSScriptRoot 'Modules/Log4jScan/Log4jScan.psd1')' -Force").Invoke() | Out-Null

    $scanBtn.Add_Click({
        $targets = $targetsBox.Text -split "`r?`n" | Where-Object { $_.Trim() }
        if (-not $targets) { [Windows.MessageBox]::Show('Enter at least one target URL.', 'Log4jScan'); return }
        $selCves = @($cveCombo.SelectedItems | ForEach-Object { $_.Tag })
        if (-not $selCves) { $selCves = @('CVE-2021-44228') }

        $scanBtn.IsEnabled = $false
        $progress.IsIndeterminate = $true
        Write-GuiLog "[*] Scan started: $($targets.Count) target(s), CVEs: $($selCves -join ', ')"

        $cmd = 'Invoke-Log4jTargetScan -Target @($args[0]) -Cve @($args[1]) -CallbackHost $args[2] ' +
               '-WafBypass:([bool]$args[3]) -RunAllTests:([bool]$args[4]) ' +
               "-Logger ([ScriptBlock]::Create('param([string]`${m})'))"
        $ps.Commands.Clear() | Out-Null
        $ps.AddScript($cmd) | Out-Null
        $ps.AddArgument($targets) | Out-Null
        $ps.AddArgument($selCves) | Out-Null
        $ps.AddArgument($callbackBox.Text.Trim()) | Out-Null
        $ps.AddArgument([bool]$wafCheck.IsChecked) | Out-Null
        $ps.AddArgument([bool]$allTests.IsChecked) | Out-Null
        $handle = $ps.BeginInvoke()

        # Poll for completion on the dispatcher (no blocking)
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({
            if ($handle.IsCompleted) {
                $timer.Stop()
                $progress.IsIndeterminate = $false
                try {
                    $out = $ps.EndInvoke($handle)
                    $resultsGrid.ItemsSource = $out
                    $vulns = @($out | Where-Object { $_.Verdict -like 'VULNERABLE*' })
                    if ($vulns.Count) {
                        Write-GuiLog "[!!!] VULNERABLE: $($vulns.Count) finding(s) — review results grid."
                        [Windows.MessageBox]::Show(('{0} target(s) responded to JNDI callbacks!' -f $vulns.Count), 'Log4jScan',
                            'OK', 'Warning')
                    } else {
                        Write-GuiLog '[+] Scan finished. No OOB callbacks detected.'
                    }
                } catch {
                    Write-GuiLog "[!] Scan error: $($_.Exception.Message)"
                }
                $scanBtn.IsEnabled = $true
            }
        })
        $timer.Start()
    })

    $updateBtn.Add_Click({
        $updateBtn.IsEnabled = $false
        Write-GuiLog '[*] Updating CVE database from NVD + community feeds...'
        $ps.Commands.Clear() | Out-Null
        $ps.AddScript('Update-Log4jCveDatabase') | Out-Null
        $handle = $ps.BeginInvoke()
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromSeconds(1)
        $timer.Add_Tick({
            if ($handle.IsCompleted) {
                $timer.Stop()
                try {
                    $r = $ps.EndInvoke($handle) | Select-Object -First 1
                    Write-GuiLog ('[+] Updated: {0} CVEs total (+{1} new, {2} refreshed, +{3} WAF payloads) v{4}' -f `
                        $r.TotalCves, $r.AddedFromNvd, $r.RefreshedFromNvd, $r.NewWafPayloads, $r.Version)
                    $meta2 = (Get-Log4jCveDatabase).metadata
                    $dbStatus.Text = ('Knowledge base v{0} - {1} CVEs - source: {2}' -f $meta2.version, (Get-Log4jCveInfo).Count, (Split-Path (Get-Log4jCveDatabasePath) -Leaf))
                    $cveCombo.Items.Clear()
                    foreach ($c in (Get-Log4jCveInfo)) {
                        $item = New-Object System.Windows.Controls.ComboBoxItem
                        $item.Content = ('{0}  [{1}]' -f $c.Cve, $c.Severity)
                        $item.Tag = $c.Cve
                        if ($c.IsDefault) { $item.IsSelected = $true }
                        $cveCombo.Items.Add($item) | Out-Null
                    }
                } catch { Write-GuiLog "[!] Update failed: $($_.Exception.Message)" }
                $updateBtn.IsEnabled = $true
            }
        })
        $timer.Start()
    })

    $exportBtn.Add_Click({
        if (-not $resultsGrid.ItemsSource) { [Windows.MessageBox]::Show('No results to export.', 'Log4jScan'); return }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'CSV files (*.csv)|*.csv'
        $dlg.FileName = 'log4j-scan-results.csv'
        if ($dlg.ShowDialog()) {
            $resultsGrid.ItemsSource | Select-Object Target, Cve, Title, Severity, Cvss, Verdict, CallbackHost, Timestamp |
                Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
            Write-GuiLog "[+] Results exported to $($dlg.FileName)"
        }
    })

    $window.Add_Closed({ $ps.Dispose(); $rs.Dispose() })
    Write-GuiLog '[*] Welcome. Tip: click UPDATE CVE DB first to pull the latest advisories.'
    $window.ShowDialog() | Out-Null
}

# ------------------------------------------------------------------
# Entry point dispatch
# ------------------------------------------------------------------
if ($NoGui) {
    Show-ConsoleMenu
} elseif ($isWindows) {
    Show-WpfGui
} else {
    # Try Terminal.Gui-based TUI helper if present, else console menu
    $tui = Join-Path $PSScriptRoot 'tui/TerminalGui.ps1'
    if (Test-Path $tui) { & $tui } else {
        Write-Host '[i] WPF is Windows-only; falling back to the interactive console GUI.' -ForegroundColor Yellow
        Show-ConsoleMenu
    }
}
