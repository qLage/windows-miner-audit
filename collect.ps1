# Read-only collector. No downloaded tools, registry writes or process termination.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$result = [ordered]@{ schema_version=1; errors=@() }
function Read-Section([string]$name, [scriptblock]$read, $fallback) {
    [Console]::Error.WriteLine('Collecting: '+$name)
    try {
        if ($name -in @('processes','tasks','startup','hosts','acl_blocks','health')) {
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
        # Signature checks only for plausible impersonators outside Windows/Program Files.
        if ($path -and $path -match '\\(ProgramData|AppData|Temp|Users\\Default(?: User)?)\\' -and
            ($_.Name -match '^(audiodg|taskhostw?|winlogon|svchost|microsofthost|apphost|steamwebhelper)\.exe$' -or
             $path -match '\\(WindowsTask|ReaItekHD|Windows Tasks Service)\\')) {
            try { $signature = [string](Get-AuthenticodeSignature -LiteralPath $path).Status }
            catch { $signature = 'Unavailable'; $script:result.errors += ('Signature unavailable: ' + $path) }
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
# Explicitly preserve array shape when PowerShell emits zero or one result.
foreach ($section in @('processes','tasks','startup','hosts','acl_blocks','health')) {
    $result[$section]=@($result[$section])
}
ConvertTo-Json -InputObject $result -Depth 8 -Compress
