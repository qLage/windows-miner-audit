param([switch]$Deep)
# Read-only collector. No downloaded tools, registry writes or process termination.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$result = [ordered]@{ schema_version=1; scan_mode=$(if($Deep){'deep'}else{'quick'}); errors=@() }
$signatureCache=@{}
$signatureBudgetReported=$false
$nativeSecurityAvailable=$true
try { Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop }
catch { $nativeSecurityAvailable=$false; $result.errors+=('processes: Signature verification unavailable: '+$_.Exception.Message) }
function Read-Section([string]$name, [scriptblock]$read, $fallback) {
    [Console]::Error.WriteLine('Collecting: '+$name)
    try {
        if ($name -in @('processes','tasks','startup','hosts','acl_blocks','health','services','wmi','hijacks','connections','performance','startup_files')) {
            $script:result[$name] = @(& $read)
        } else { $script:result[$name] = & $read }
    }
    catch { $script:result[$name] = $fallback; $script:result.errors += ($name + ': ' + $_.Exception.Message) }
    # A timeout still leaves a usable partial snapshot for the Python caller.
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $script:result -Depth 8 -Compress))
}
Read-Section 'processes' {
    @(Get-CimInstance Win32_Process | ForEach-Object {
        $path = $_.ExecutablePath
        $signature = $null
        # Bounded verification: suspicious impersonators in quick mode, up to 40 writable-location executables in extended mode.
        if ($path -and $path -match '\\(ProgramData|AppData|Temp|Users\\Default(?: User)?)\\' -and
            ($Deep -or $_.Name -match '^(audiodg|taskhostw?|winlogon|svchost|microsofthost|apphost|steamwebhelper)\.exe$' -or
             $path -match '\\(WindowsTask|ReaItekHD|Windows Tasks Service)\\')) {
            if ($signatureCache.ContainsKey($path)) { $signature=$signatureCache[$path] }
            elseif ($signatureCache.Count -lt 40 -and $nativeSecurityAvailable) {
                try { $signature = [string](Get-AuthenticodeSignature -LiteralPath $path).Status }
                catch { $signature = 'Unavailable'; $script:result.errors += ('processes: Signature unavailable: ' + $path) }
                $signatureCache[$path]=$signature
            } elseif (!$signatureBudgetReported -and $nativeSecurityAvailable) {
                $script:result.errors+='processes: Signature verification limited to 40 executable paths.'
                $signatureBudgetReported=$true
            }
        }
        [pscustomobject]@{ pid=$_.ProcessId; path=$path; command=$_.CommandLine; signature=$signature }
    })
} @()
if (@($result.processes | Where-Object { !$_.path -and $_.pid -gt 4 }).Count -gt 0) {
    $result.errors += 'Some process paths/command lines are inaccessible. An elevated terminal may improve coverage.'
}
Read-Section 'tasks' {
    @(Get-ScheduledTask | ForEach-Object {
        $task = $_
        foreach ($action in $task.Actions) {
            [pscustomobject]@{ name=($task.TaskPath+$task.TaskName); enabled=([string]$task.State -ne 'Disabled');
                command=([string]$action.Execute+' '+[string]$action.Arguments) }
        }
    })
} @()
Read-Section 'startup' {
    $items = @()
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        if (Test-Path -LiteralPath $key) {
            $properties = Get-ItemProperty -LiteralPath $key
            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -notmatch '^PS') {
                    $items += [pscustomobject]@{name=($key+'\'+$property.Name);command=[string]$property.Value;enabled=$true}
                }
            }
        }
    }
    @($items)
} @()
Read-Section 'defender' {
    $status=Get-MpComputerStatus
    $pref=Get-MpPreference
    $policyPaths=@(); $policyExtensions=@()
    $policy='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
    foreach ($type in @('Paths','Extensions')) {
        $key=Join-Path $policy $type
        if (Test-Path -LiteralPath $key) {
            $names=@((Get-Item -LiteralPath $key).GetValueNames())
            if ($type -eq 'Paths') { $policyPaths=$names } else { $policyExtensions=$names }
        }
    }
    @{ realtime_enabled=[bool]$status.RealTimeProtectionEnabled; tamper_protected=[bool]$status.IsTamperProtected;
       script_scanning_enabled=(!$pref.DisableScriptScanning); cloud_reporting=[int]$pref.MAPSReporting;
       paths=@($pref.ExclusionPath | Where-Object { $_ }); extensions=@($pref.ExclusionExtension | Where-Object { $_ });
       policy_paths=$policyPaths; policy_extensions=$policyExtensions }
} @{}
Read-Section 'hosts' { @([IO.File]::ReadAllLines("$env:SystemRoot\System32\drivers\etc\hosts")) } @()
Read-Section 'acl_blocks' {
    $blocks=@()
    $products=@('360safe','AVAST Software','Avira','Doctor Web','ESET','grizzly','Kaspersky Lab',
        'Kaspersky Lab Setup Files','Malwarebytes','MB3Install','McAfee','Norton')
    foreach ($product in $products) {
        $path=Join-Path $env:ProgramData $product
        if (!(Test-Path -LiteralPath $path)) { continue }
        try {
            foreach ($rule in ([IO.DirectoryInfo]$path).GetAccessControl().Access) {
                $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                $current=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                if (!$rule.IsInherited -and $rule.AccessControlType -eq 'Deny' -and
                    $sid -in @('S-1-5-18','S-1-1-0',$current) -and
                    ([int]$rule.FileSystemRights -band [int][System.Security.AccessControl.FileSystemRights]::Write)) {
                    $blocks += @{path=$path; identity=$sid; rights=[string]$rule.FileSystemRights}
                }
            }
        } catch { $script:result.errors += ('ACL: '+$path+': '+$_.Exception.Message) }
    }
    @($blocks)
} @()
Read-Section 'remote' {
    $rdp=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $listening=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -eq 3389).Count -gt 0
    @{rdp_enabled=($rdp.fDenyTSConnections -eq 0); rdp_listening=$listening}
} @{}
Read-Section 'health' {
    @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        @{drive=$_.DeviceID; free_gb=[math]::Round($_.FreeSpace/1GB,2)}
    })
} @()
if ($Deep) {
    Read-Section 'services' {
        @(Get-CimInstance Win32_Service | ForEach-Object {
            @{name=$_.Name; command=$_.PathName; enabled=($_.StartMode -ne 'Disabled'); state=$_.State}
        })
    } @()
    Read-Section 'wmi' {
        $entries=@()
        foreach ($class in @('CommandLineEventConsumer','ActiveScriptEventConsumer')) {
            foreach ($consumer in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $class)) {
                $entries += @{name=$consumer.Name; kind=$class;
                    command=([string]$consumer.CommandLineTemplate+' '+[string]$consumer.ScriptText)}
            }
        }
        @($entries)
    } @()
    Read-Section 'hijacks' {
        $entries=@()
        $ifeo='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path -LiteralPath $ifeo) {
            foreach ($key in Get-ChildItem -LiteralPath $ifeo) {
                $debugger=$key.GetValue('Debugger')
                if ($debugger) { $entries+=@{name=$key.PSChildName;kind='IFEO';command=[string]$debugger} }
            }
        }
        $winlogon=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell=([string]$winlogon.Shell).Trim()
        $userinit=([string]$winlogon.Userinit).Trim().TrimEnd(',')
        if ($shell -and $shell -ine 'explorer.exe' -and $shell -ine "$env:SystemRoot\explorer.exe") {
            $entries+=@{name='Winlogon Shell';kind='Winlogon';command=$shell}
        }
        if ($userinit -and $userinit -ine "$env:SystemRoot\system32\userinit.exe") {
            $entries+=@{name='Winlogon Userinit';kind='Winlogon';command=$userinit}
        }
        $windows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        if ($windows.AppInit_DLLs) { $entries+=@{name='AppInit_DLLs';kind='AppInit';command=[string]$windows.AppInit_DLLs} }
        @($entries)
    } @()
    Read-Section 'connections' {
        @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
            $_.RemotePort -in @(3333,4444,5555,7777,9999,14444)
        } | ForEach-Object { @{pid=$_.OwningProcess;port=$_.RemotePort;address=$_.RemoteAddress} })
    } @()
    Read-Section 'performance' {
        $before=@{}; $watch=[Diagnostics.Stopwatch]::StartNew()
        foreach ($proc in Get-Process) { try { $before[$proc.Id]=$proc.TotalProcessorTime.TotalSeconds } catch {} }
        Start-Sleep -Milliseconds 1000
        $elapsed=$watch.Elapsed.TotalSeconds
        $entries=@()
        foreach ($proc in Get-Process) {
            if (!$before.ContainsKey($proc.Id)) { continue }
            try {
                $cpu=[math]::Round(100*($proc.TotalProcessorTime.TotalSeconds-$before[$proc.Id])/$elapsed/[Environment]::ProcessorCount,1)
                if ($cpu -ge 5) { $entries+=@{pid=$proc.Id;cpu_percent=$cpu} }
            } catch {}
        }
        @($entries)
    } @()
    Read-Section 'startup_files' {
        $entries=@(); $shell=New-Object -ComObject WScript.Shell
        foreach ($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))) {
            if (!$folder -or !(Test-Path -LiteralPath $folder)) { continue }
            foreach ($file in @(Get-ChildItem -LiteralPath $folder -File | Select-Object -First 120)) {
                $command=$file.FullName
                if ($file.Extension -ieq '.lnk') {
                    $shortcut=$shell.CreateShortcut($file.FullName)
                    $command=([string]$shortcut.TargetPath+' '+[string]$shortcut.Arguments)
                } elseif ($file.Extension -in @('.ps1','.cmd','.bat','.vbs','.js') -and $file.Length -le 65536) {
                    $command+=' '+[IO.File]::ReadAllText($file.FullName)
                }
                $entries+=@{name=$file.Name;command=$command;enabled=$true}
            }
        }
        @($entries)
    } @()
}
# Explicitly preserve array shape when PowerShell emits zero or one result.
foreach ($section in @('processes','tasks','startup','hosts','acl_blocks','health')) {
    $result[$section]=@($result[$section])
}
ConvertTo-Json -InputObject $result -Depth 8 -Compress
