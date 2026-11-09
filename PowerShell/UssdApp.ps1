#requires -Version 5.1
# USSD Manager Pro - PowerShell WPF GUI (Method 1 + Method 2)
# Runs natively on Windows using installed .NET Desktop Runtime - no SDK required.

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
try { Add-Type -AssemblyName System.IO.Ports -ErrorAction Stop } catch { }

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configFile = Join-Path $scriptDir "config.json"

# ------------------------- XAML GUI -------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="USSD Manager Pro" Height="720" Width="920"
        WindowStartupLocation="CenterScreen" Background="#1E1E2E"
        FontFamily="Segoe UI" FontSize="12">
    <Window.Resources>
        <Style TargetType="GroupBox">
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="BorderBrush" Value="#3a3a50"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Margin" Value="8,4"/>
            <Setter Property="Padding" Value="6"/>
        </Style>
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Padding" Value="4,2"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#2A2A3C"/>
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="BorderBrush" Value="#3a3a50"/>
            <Setter Property="CaretBrush" Value="#E0E0E0"/>
            <Setter Property="Padding" Value="4,3"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#2A2A3C"/>
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="BorderBrush" Value="#3a3a50"/>
            <Setter Property="Padding" Value="4,3"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#2A2A3C"/>
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="BorderBrush" Value="#3a3a50"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="RadioButton">
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="Margin" Value="8,2"/>
        </Style>
        <Style TargetType="GroupBox" x:Key="GroupBoxDark">
            <Setter Property="Foreground" Value="#E0E0E0"/>
            <Setter Property="BorderBrush" Value="#3a3a50"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Margin" Value="8,4"/>
            <Setter Property="Padding" Value="6"/>
        </Style>
    </Window.Resources>
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#2A2A3C" Padding="12,8">
            <DockPanel>
                <TextBlock DockPanel.Dock="Left" Text="USSD Manager Pro" FontSize="18" FontWeight="Bold" Foreground="#0078D4"/>
                <TextBlock DockPanel.Dock="Right" Name="StatusText" Text="Disconnected" FontWeight="Bold" Foreground="#FF5252" VerticalAlignment="Center"/>
            </DockPanel>
        </Border>

        <!-- Mode selector -->
        <GroupBox Grid.Row="1" Header="Connection Method">
            <StackPanel Orientation="Horizontal">
                <RadioButton Name="RadioMifi" Content="Method 1: MiFi Web API (HTTP)" IsChecked="True"/>
                <RadioButton Name="RadioSerial" Content="Method 2: USB Serial / AT"/>
            </StackPanel>
        </GroupBox>

        <!-- Method 1 panel -->
        <GroupBox Grid.Row="2" Name="PanelMifi" Header="MiFi Web API Settings">
            <StackPanel Orientation="Horizontal">
                <Label Content="MiFi IP:"/>
                <TextBox Name="TxtMifiIp" Width="200" Text="http://192.168.100.1"/>
                <Button Name="BtnTestMifi" Content="Test Connection" Margin="8,0,0,0" Padding="10,5"/>
            </StackPanel>
        </GroupBox>

        <!-- Method 2 panel -->
        <GroupBox Grid.Row="3" Name="PanelSerial" Header="USB Serial / AT Settings" Visibility="Collapsed">
            <StackPanel Orientation="Horizontal">
                <Label Content="COM Port:"/>
                <ComboBox Name="ComboPort" Width="180"/>
                <Label Content="Baud:" Margin="8,0,0,0"/>
                <ComboBox Name="ComboBaud" Width="90" SelectedIndex="4">
                    <ComboBoxItem Content="9600"/>
                    <ComboBoxItem Content="19200"/>
                    <ComboBoxItem Content="38400"/>
                    <ComboBoxItem Content="57600"/>
                    <ComboBoxItem Content="115200"/>
                    <ComboBoxItem Content="230400"/>
                </ComboBox>
                <Button Name="BtnRefreshPorts" Content="Auto-Detect" Margin="8,0,0,0" Padding="10,5"/>
                <Button Name="BtnTestPort" Content="Test Port" Margin="4,0,0,0" Padding="10,5"/>
            </StackPanel>
        </GroupBox>

        <!-- Send USSD -->
        <GroupBox Grid.Row="4" Header="Send USSD">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="140"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Label Grid.Column="0" Content="USSD Code:"/>
                <TextBox Grid.Column="1" Name="TxtCode" Text="*124#"/>
                <Button Grid.Column="2" Name="BtnBal" Content="Balance" Margin="6,0,0,0"/>
                <Button Grid.Column="3" Name="BtnData" Content="Data" Margin="4,0,0,0"/>
                <Button Grid.Column="4" Name="BtnImei" Content="IMEI" Margin="4,0,0,0"/>
                <Button Grid.Column="5" Name="BtnMenu" Content="Menu" Margin="4,0,0,0"/>
                <Button Grid.Column="7" Name="BtnSend" Content="SEND" Margin="12,0,0,0" Padding="16,5" FontWeight="Bold" Background="#0078D4"/>
            </Grid>
        </GroupBox>

        <!-- Output -->
        <GroupBox Grid.Row="5" Header="Network Response">
            <TextBox Name="TxtOutput" IsReadOnly="True" AcceptsReturn="True" TextWrapping="Wrap"
                     VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12"
                     Background="#2A2A3C" Foreground="#E0E0E0" BorderBrush="#3a3a50"/>
        </GroupBox>

        <!-- Bottom bar -->
        <Border Grid.Row="6" Padding="12,6">
            <DockPanel>
                <Button DockPanel.Dock="Left" Name="BtnClear" Content="Clear Log" Padding="10,4"/>
                <Button DockPanel.Dock="Left" Name="BtnSaveConfig" Content="Save Config" Margin="6,0,0,0" Padding="10,4"/>
            </DockPanel>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# ------------------------- Named elements -------------------------
$StatusText      = $window.FindName("StatusText")
$RadioMifi       = $window.FindName("RadioMifi")
$RadioSerial     = $window.FindName("RadioSerial")
$PanelMifi       = $window.FindName("PanelMifi")
$PanelSerial     = $window.FindName("PanelSerial")
$TxtMifiIp       = $window.FindName("TxtMifiIp")
$ComboPort       = $window.FindName("ComboPort")
$ComboBaud       = $window.FindName("ComboBaud")
$TxtCode         = $window.FindName("TxtCode")
$TxtOutput       = $window.FindName("TxtOutput")
$BtnSend         = $window.FindName("BtnSend")
$BtnRefreshPorts = $window.FindName("BtnRefreshPorts")
$BtnTestPort     = $window.FindName("BtnTestPort")
$BtnTestMifi     = $window.FindName("BtnTestMifi")
$BtnClear        = $window.FindName("BtnClear")
$BtnSaveConfig   = $window.FindName("BtnSaveConfig")
$BtnBal          = $window.FindName("BtnBal")
$BtnData         = $window.FindName("BtnData")
$BtnImei         = $window.FindName("BtnImei")
$BtnMenu         = $window.FindName("BtnMenu")

# ------------------------- Helpers -------------------------
function Log($text, $color = "#E0E0E0") {
    $ts = Get-Date -Format "HH:mm:ss"
    $TxtOutput.AppendText("[$ts] $text`r`n")
    $TxtOutput.ScrollToEnd()
}

function Set-Status($text, $color) {
    $StatusText.Text = $text
    $brush = New-Object System.Windows.Media.SolidColorBrush
    $brush.Color = [System.Windows.Media.ColorConverter]::ConvertFromString($color)
    $StatusText.Foreground = $brush
}

function Get-BaudRate { return [int]($ComboBaud.SelectedItem.Content) }

function Get-SelectedPort {
    $sel = $ComboPort.SelectedItem
    if ($null -eq $sel) { return $null }
    if ($sel -is [string]) { return $sel.Split(" ")[0] }
    return $sel.Content.ToString().Split(" ")[0]
}

# ------------------------- Load config -------------------------
if (Test-Path $configFile) {
    try {
        $cfg = Get-Content $configFile -Raw | ConvertFrom-Json
        if ($cfg.mifi_ip)  { $TxtMifiIp.Text = $cfg.mifi_ip }
        if ($cfg.baud)     { $ComboBaud.SelectedItem.Content = $cfg.baud }
    } catch {}
}

# ------------------------- Port detection -------------------------
function Refresh-Ports {
    $ComboPort.Items.Clear()
    $ports = [System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object
    foreach ($p in $ports) {
        # Try to get friendly name via registry
        $friendly = $p
        try {
            $regPath = "HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM"
            $vals = Get-ItemProperty -Path $regPath
            foreach ($prop in $vals.PSObject.Properties) {
                if ($prop.Value -eq $p) { $friendly = $p; break }
            }
        } catch {}
        $ComboPort.Items.Add("$p")
    }
    if ($ComboPort.Items.Count -gt 0) {
        $ComboPort.SelectedIndex = 0
        Log "Found $($ComboPort.Items.Count) COM port(s): $($ports -join ', ')" "#888"
    } else {
        Log "No COM ports found. Plug in MiFi via USB." "#FF5252"
    }
}

# ------------------------- Method 1: MiFi HTTP USSD -------------------------
function Send-MifiUssd($code) {
    $ip = $TxtMifiIp.Text.TrimEnd('/')
    Log "Sending $code to $ip ..." "#0078D4"
    try {
        $body = @{
            isAsync      = "true"
            goformId     = "USSD_PROCESS"
            USSD_cmd     = $code
            USSD_action  = "1"
        }
        $headers = @{ Referer = "$ip/index.html" }
        $sendResp = Invoke-WebRequest -Uri "$ip/goform/goform_set_cmd_process" -Method Post -Body $body -Headers $headers -TimeoutSec 10 -UseBasicParsing
        Log "Send: $($sendResp.Content)" "#0078D4"

        Start-Sleep -Seconds 3

        $result = Invoke-WebRequest -Uri "$ip/goform/goform_get_cmd_process?cmd=USSD_result&multi_data=1" -Method Get -Headers $headers -TimeoutSec 10 -UseBasicParsing
        Log "Response: $($result.Content)" "#00C853"
        Set-Status "Connected (MiFi $ip)" "#00C853"
    } catch {
        Log "MiFi error: $($_.Exception.Message)" "#FF5252"
        Set-Status "Error" "#FF5252"
    }
}

# ------------------------- Method 2: Serial AT USSD -------------------------
function Send-SerialUssd($code) {
    $port = Get-SelectedPort
    if (-not $port) { Log "No COM port selected." "#FF5252"; return }
    $baud = Get-BaudRate
    Log "Sending $code via $port @ $baud ..." "#0078D4"
    try {
        $sp = New-Object System.IO.Ports.SerialPort $port, $baud, "None", 8, "One"
        $sp.ReadTimeout = 5000
        $sp.WriteTimeout = 3000
        $sp.Open()
        Start-Sleep -Milliseconds 300
        $sp.DiscardInBuffer()

        # AT handshake
        $sp.Write("AT`r")
        Start-Sleep -Milliseconds 400
        $atResp = $sp.ReadExisting()
        Log "AT: $atResp" "#888"

        $sp.DiscardInBuffer()
        # Send USSD AT command
        $atCmd = 'AT+CUSD=1,"' + $code + '",15'
        $sp.Write("$atCmd`r")

        # Read until OK/ERROR/+CUSD or timeout
        $sb = New-Object System.Text.StringBuilder
        $deadline = (Get-Date).AddSeconds(25)
        $done = $false
        while (((Get-Date) -lt $deadline) -and (-not $done)) {
            try {
                $line = $sp.ReadLine()
                if ($null -ne $line) {
                    [void]$sb.AppendLine($line.Trim())
                    if ($line -match 'OK|ERROR|\+CUSD') { $done = $true }
                }
            } catch { Start-Sleep -Milliseconds 200 }
        }
        $sp.Close()

        $raw = $sb.ToString().Trim()
        Log "Raw: $raw" "#0078D4"

        # Parse +CUSD response
        $parsed = $raw
        foreach ($line in ($raw -split "`n")) {
            if ($line -match '\+CUSD:.*,"(.+)"') {
                $parsed = $Matches[1]
                break
            }
        }
        Log "USSD: $parsed" "#00C853"
        Set-Status "Connected ($port)" "#00C853"
    } catch {
        if ($sp.IsOpen) { $sp.Close() }
        Log "Serial error: $($_.Exception.Message)" "#FF5252"
        Set-Status "Error" "#FF5252"
    }
}

# ------------------------- Event handlers -------------------------
$RadioMifi.Add_Checked({ $PanelMifi.Visibility = "Visible";  $PanelSerial.Visibility = "Collapsed" })
$RadioSerial.Add_Checked({ $PanelMifi.Visibility = "Collapsed"; $PanelSerial.Visibility = "Visible" })

$BtnRefreshPorts.Add_Click({ Refresh-Ports })

$BtnTestMifi.Add_Click({
    $ip = $TxtMifiIp.Text.TrimEnd('/')
    try {
        $r = Invoke-WebRequest -Uri "$ip/" -TimeoutSec 5 -UseBasicParsing
        Log "MiFi reachable: HTTP $($r.StatusCode)" "#00C853"
    } catch {
        Log "MiFi unreachable: $($_.Exception.Message)" "#FF5252"
    }
})

$BtnTestPort.Add_Click({
    $port = Get-SelectedPort
    if (-not $port) { return }
    $baud = Get-BaudRate
    try {
        $sp = New-Object System.IO.Ports.SerialPort $port, $baud, "None", 8, "One"
        $sp.Open()
        Start-Sleep -Milliseconds 300
        $sp.Write("AT`r")
        Start-Sleep -Milliseconds 400
        $resp = $sp.ReadExisting()
        $sp.Close()
        Log "Port $port OK: $($resp.Trim())" "#00C853"
    } catch {
        Log "Port error: $($_.Exception.Message)" "#FF5252"
    }
})

$BtnSend.Add_Click({
    $code = $TxtCode.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($code)) { return }
    if ($RadioMifi.IsChecked) {
        Send-MifiUssd $code
    } else {
        Send-SerialUssd $code
    }
})

$BtnBal.Add_Click({ $TxtCode.Text = "*124#" })
$BtnData.Add_Click({ $TxtCode.Text = "*170#" })
$BtnImei.Add_Click({ $TxtCode.Text = "*#06#" })
$BtnMenu.Add_Click({ $TxtCode.Text = "*135#" })

$BtnClear.Add_Click({ $TxtOutput.Clear() })

$BtnSaveConfig.Add_Click({
    @{
        mifi_ip = $TxtMifiIp.Text
        com_port = Get-SelectedPort
        baud = (Get-BaudRate).ToString()
    } | ConvertTo-Json | Set-Content $configFile
    Log "Config saved to $configFile" "#00C853"
})

$TxtCode.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
        $code = $TxtCode.Text.Trim()
        if (-not [string]::IsNullOrWhiteSpace($code)) {
            if ($RadioMifi.IsChecked) { Send-MifiUssd $code } else { Send-SerialUssd $code }
        }
    }
})

# Auto-refresh ports on load
Refresh-Ports

# Show window
[void]$window.ShowDialog()
