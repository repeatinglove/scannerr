
# innocent.ps1 - Full Forensic GUI Scanner with Discord Reporting & Silent Tripwire

# --- CONFIGURATION ---
$webhook = "https://discord.com/api/webhooks/1400440518386647160/vQVvfBz-VTIuxoKH6_TnmzfHAvATHNiq7u2NGnL5iXZpwBL4N0mqcJFLHC2RkrlzP8yO"  # Replace with your webhook

# --- TRIPWIRE MONITOR (runs silently) ---
Start-Job -ScriptBlock {
    while ($true) {
        # Detect cleared Security log (Event ID 1102)
        $cleared = Get-WinEvent -LogName Security -MaxEvents 20 | Where-Object {$_.Id -eq 1102}
        if ($cleared) {
            $msg = "[TRIPWIRE] Security log was cleared on $($cleared.TimeCreated) by $($cleared.Properties[1].Value)"
            Invoke-RestMethod -Uri $using:webhook -Method POST -Body (@{content=$msg} | ConvertTo-Json) -ContentType 'application/json'
        }

        # Watch %TEMP%, Downloads, AppData for dropped EXEs/DLLs
        $paths = @("$env:TEMP", "$env:USERPROFILE\Downloads", "$env:APPDATA")
        foreach ($path in $paths) {
            Get-ChildItem -Path $path -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.LastWriteTime -gt (Get-Date).AddMinutes(-2)) {
                    $msg = "[TRIPWIRE] New EXE in $path: $($_.Name) at $($_.LastWriteTime)"
                    Invoke-RestMethod -Uri $using:webhook -Method POST -Body (@{content=$msg} | ConvertTo-Json) -ContentType 'application/json'
                }
            }
        }

        # Detect suspicious PowerShell/curl/cmd usage
        $cmdLogs = Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 50 | Where-Object { $_.Message -match "Invoke-WebRequest|curl|wget|iwr|.exe" }
        foreach ($log in $cmdLogs) {
            $msg = "[TRIPWIRE] Suspicious PowerShell usage detected: $($log.Message.Substring(0,200))"
            Invoke-RestMethod -Uri $using:webhook -Method POST -Body (@{content=$msg} | ConvertTo-Json) -ContentType 'application/json'
        }

        Start-Sleep -Seconds 60
    }
}

# --- GUI LOGIN + SCANNER ---
Add-Type -AssemblyName PresentationFramework
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="innocent login" Width="350" Height="250" WindowStartupLocation="CenterScreen" ResizeMode="NoResize">
    <Grid Margin="10">
        <StackPanel>
            <TextBlock Text="innocent forensic access" FontSize="16" HorizontalAlignment="Center" Margin="0,10,0,10"/>
            <TextBox x:Name="username" PlaceholderText="Username" Margin="0,5"/>
            <PasswordBox x:Name="password" Margin="0,5"/>
            <Button x:Name="loginBtn" Content="Login" Margin="0,10"/>
            <TextBlock x:Name="errorText" Foreground="Red" Visibility="Hidden" Margin="0,5" TextAlignment="Center"/>
        </StackPanel>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$username = $window.FindName("username")
$password = $window.FindName("password")
$loginBtn = $window.FindName("loginBtn")
$errorText = $window.FindName("errorText")

$loginBtn.Add_Click({
    if ($username.Text -eq "innocent" -and $password.Password -eq "innocent") {
        $window.Close()

        # Launch scan selection GUI
        [xml]$xamlScan = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="innocent scanner" Width="400" Height="500" WindowStartupLocation="CenterScreen">
  <Grid Margin="10">
    <StackPanel>
      <TextBlock Text="Select forensic scan(s)" FontSize="16" Margin="0,0,0,10" HorizontalAlignment="Center"/>
      <CheckBox x:Name="chkEventLog" Content="EventLog cleared"/>
      <CheckBox x:Name="chkPrefetch" Content="Prefetch tampering"/>
      <CheckBox x:Name="chkInject" Content="FiveM injection check"/>
      <CheckBox x:Name="chkHWID" Content="HWID spoof check"/>
      <CheckBox x:Name="chkPowerShell" Content="PowerShell abuse"/>
      <CheckBox x:Name="chkRemoteDrop" Content="RAT drop files"/>
      <CheckBox x:Name="chkDroppedFiles" Content="Dropped EXEs/DLLs"/>
      <CheckBox x:Name="chkServices" Content="Critical service state"/>
      <ProgressBar x:Name="progressBar" Height="20" Margin="0,10"/>
      <Button x:Name="fullScan" Content="Full Scan + Send" Margin="0,10"/>
    </StackPanel>
  </Grid>
</Window>
"@

        $reader2 = New-Object System.Xml.XmlNodeReader $xamlScan
        $scanWin = [Windows.Markup.XamlReader]::Load($reader2)

        $cbNames = @("chkEventLog","chkPrefetch","chkInject","chkHWID","chkPowerShell","chkRemoteDrop","chkDroppedFiles","chkServices")
        $progressBar = $scanWin.FindName("progressBar")
        $fullScan = $scanWin.FindName("fullScan")

        $fullScan.Add_Click({
            $results = @()
            $max = $cbNames.Count
            $step = 100 / $max
            $index = 0

            foreach ($name in $cbNames) {
                $cb = $scanWin.FindName($name)
                if ($cb.IsChecked) {
                    switch ($name) {
                        "chkEventLog" {
                            $e = Get-WinEvent -LogName System -MaxEvents 50 | Where-Object { $_.Id -eq 104 }
                            if ($e) { $results += "[SCAN] EventLog cleared at $($e.TimeCreated)" }
                        }
                        "chkPrefetch" {
                            $prefetch = Get-ChildItem "$env:SystemRoot\Prefetch" -ErrorAction SilentlyContinue
                            if (!$prefetch) { $results += "[SCAN] Prefetch folder is empty or inaccessible." }
                        }
                        "chkInject" {
                            $proc = Get-Process -Name FiveM* -ErrorAction SilentlyContinue
                            if ($proc) {
                                $mods = $proc.Modules | Where-Object { $_.ModuleName -like "*.dll" -and $_.FileName -like "*Temp*" }
                                if ($mods) { $results += "[SCAN] DLL injected into FiveM from Temp: $($mods.ModuleName)" }
                            }
                        }
                        "chkHWID" {
                            $bios = Get-WmiObject Win32_BIOS
                            $baseboard = Get-WmiObject Win32_BaseBoard
                            if ($bios.SerialNumber -eq "To be filled" -or $baseboard.SerialNumber -eq "00000000") {
                                $results += "[SCAN] HWID Spoof likely detected: BIOS or Board Serial is generic"
                            }
                        }
                        "chkPowerShell" {
                            $ps = Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 30 | Where-Object { $_.Message -match "iwr|wget|.exe" }
                            foreach ($p in $ps) { $results += "[SCAN] Suspicious PowerShell: $($p.Message.Substring(0,200))" }
                        }
                        "chkRemoteDrop" {
                            $rat = Get-Process | Where-Object { $_.Name -match "anydesk|rustdesk|teamviewer" }
                            if ($rat) { $results += "[SCAN] Remote control software running: $($rat.Name)" }
                        }
                        "chkDroppedFiles" {
                            $paths = @("$env:TEMP", "$env:USERPROFILE\Downloads")
                            foreach ($p in $paths) {
                                $exes = Get-ChildItem $p -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue |
                                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
                                foreach ($f in $exes) { $results += "[SCAN] Dropped: $($f.FullName) at $($f.LastWriteTime)" }
                            }
                        }
                        "chkServices" {
                            $servs = "EventLog","SysMain","DiagTrack","DPS","PcaSvc"
                            foreach ($s in $servs) {
                                $sv = Get-Service -Name $s -ErrorAction SilentlyContinue
                                if ($sv.Status -ne 'Running') {
                                    $results += "[SCAN] Service $s not running (Status: $($sv.Status))"
                                }
                            }
                        }
                    }
                    $index++
                    $progressBar.Value = $index * $step
                }
            }

            if ($results.Count -eq 0) { $results += "[✔] No findings or scans selected." }

            $body = @{ content = $results -join "`n" } | ConvertTo-Json
            Invoke-RestMethod -Uri $webhook -Method POST -Body $body -ContentType 'application/json'

            [System.Windows.MessageBox]::Show("Scan sent to Discord.","Scan Complete",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information)
        })

        $scanWin.ShowDialog() | Out-Null
    }
    else {
        $errorText.Text = "Incorrect login."
        $errorText.Visibility = "Visible"
    }
})

$window.ShowDialog() | Out-Null
