<#
.SYNOPSIS
    Collects system and security data for forensic analysis.

.DESCRIPTION
    This script gathers various data points including system information, hardware details, user accounts,
    firewall status, startup entries, scheduled tasks, recent file changes, suspicious files, network connections,
    security events, PowerShell events, installed software, USB device history, and running processes with 
    command lines, parent process details, and child process IDs. The data is saved to CSV files in a timestamped output directory.

.NOTES
    Run this script as an Administrator to ensure access to all required data.
#>

# Define output directory with timestamp to avoid overwriting previous collections
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "C:\InvestigationData"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# Define script blocks for independent tasks

# Collect system information
$systemInfoScript = {
    param($outputDir)
    Get-WmiObject -Class Win32_OperatingSystem | 
        Select-Object Caption, Version, OSArchitecture | 
        Export-Csv -Path "$outputDir\SystemInfo.csv" -NoTypeInformation
}

# Collect hardware information
$hardwareInfoScript = {
    param($outputDir)
    Get-WmiObject -Class Win32_ComputerSystem | 
        Select-Object Manufacturer, Model, TotalPhysicalMemory | 
        Export-Csv -Path "$outputDir\HardwareInfo.csv" -NoTypeInformation
}

# Collect local administrators
$adminUsersScript = {
    param($outputDir)
    Get-LocalGroupMember -Group "Administrators" | 
        Select-Object Name | 
        Export-Csv -Path "$outputDir\AdminUsers.csv" -NoTypeInformation
}

# Collect firewall status
$firewallStatusScript = {
    param($outputDir)
    Get-NetFirewallProfile | 
        Select-Object Name, Enabled | 
        Export-Csv -Path "$outputDir\FirewallStatus.csv" -NoTypeInformation
}

# Collect startup entries from registry
$startupEntriesScript = {
    param($outputDir)
    $startupKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $startupEntries = foreach ($key in $startupKeys) {
        $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($items) {
            $propertyNames = $items | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            foreach ($prop in $propertyNames) {
                [PSCustomObject]@{
                    'Key'   = $key
                    'Name'  = $prop
                    'Value' = $items.$prop
                }
            }
        }
    }
    if ($startupEntries) {
        $startupEntries | Export-Csv -Path "$outputDir\StartupEntries.csv" -NoTypeInformation
    }
}

# Collect scheduled tasks
$scheduledTasksScript = {
    param($outputDir)
    Get-ScheduledTask | 
        Where-Object { $_.State -eq 'Ready' } | 
        Select-Object TaskName, TaskPath, Author, Description, LastRunTime, NextRunTime | 
        Export-Csv -Path "$outputDir\ScheduledTasks.csv" -NoTypeInformation
}

# Collect recent file changes in C:\Users (limited to last 7 days)
$recentFileChangesScript = {
    param($outputDir)
    $days = 7
    $cutoffDate = (Get-Date).AddDays(-$days)
    Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -ge $cutoffDate } |
        ForEach-Object {
            $filePath = $_.FullName
            try {
                if (Test-Path $filePath) {
                    try {
                        $owner = (Get-Acl $filePath).Owner
                    } catch {
                        if ($_.CategoryInfo.Category -eq 'PermissionDenied') {
                            $owner = "Access Denied"
                        } else {
                            $owner = "Error: $($_.Exception.Message)"
                        }
                    }
                } else {
                    $owner = "File Not Found"
                }
            } catch {
                $owner = "Access Denied"
            }
            [PSCustomObject]@{
                FullName      = $filePath
                LastWriteTime = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                Owner         = $owner
            }
        } | Export-Csv -Path "$outputDir\RecentFileChanges.csv" -NoTypeInformation
}

# Collect suspicious .exe files
$suspiciousFilesScript = {
    param($outputDir)
    Get-ChildItem -Path C:\Users, C:\ProgramData -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object { $_.Extension -eq '.exe' -and $_.DirectoryName -notlike '*Windows*' -and $_.DirectoryName -notlike '*Program Files*' } | 
        Select-Object FullName, LastWriteTime, @{Name='SHA256Hash'; Expression={
            try { (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash } catch { "AccessDeniedOrNotFound" }
        }} | 
        Export-Csv -Path "$outputDir\SuspiciousFiles.csv" -NoTypeInformation
}

# Collect network connections
$networkConnectionsScript = {
    param($outputDir)
    Get-NetTCPConnection | 
        ForEach-Object { 
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $path = $p.Path
            try { $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash } catch { $hash = "AccessDeniedOrNotFound" }
            [PSCustomObject]@{ 
                TimeCollected = Get-Date
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                PID           = $_.OwningProcess
                ProcessName   = $p.Name
                ProcessPath   = $path
                SHA256Hash    = $hash 
            } 
        } | Export-Csv -Path "$outputDir\NetworkConnections.csv" -NoTypeInformation
}

# Collect security events and build logon IP lookup
$securityEventsScript = {
    param($outputDir)
    try {
        $logs = Get-WinEvent -LogName Security -MaxEvents 1000 -ErrorAction Stop
        $securityEvents = foreach ($evt in $logs) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.'#text' }
            }
            [PSCustomObject]@{
                TimeCreated      = $evt.TimeCreated
                Id               = $evt.Id
                LevelDisplayName = $evt.LevelDisplayName
                Message          = $evt.Message
                SubjectUserName  = $data['SubjectUserName']
                TargetUserName   = $data['TargetUserName']
                TargetDomainName = $data['TargetDomainName']
                IpAddress        = $data['IpAddress']
                LogonType        = $data['LogonType']
            }
        }
        $securityEvents | Export-Csv -Path "$outputDir\SecurityLogs.csv" -NoTypeInformation

        # Build logon IP lookup
        $logonEvents = $securityEvents | Where-Object { $_.Id -eq 4624 }
        $recentLogons = $logonEvents | Group-Object -Property { "$($_.TargetDomainName)\$($_.TargetUserName)" } | 
            ForEach-Object { $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1 }
        $logonIpLookup = @{}
        foreach ($logon in $recentLogons) {
            $key = "$($logon.TargetDomainName)\$($logon.TargetUserName)"
            $logonIpLookup[$key] = $logon.IpAddress
        }
        $logonIpLookup | ConvertTo-Json | Set-Content -Path "$outputDir\logonIpLookup.json"

        # Collect firewall modification events
        $firewallEvents = $securityEvents | Where-Object { $_.Id -in 4946,4947,4948,4950 }
        if ($firewallEvents) {
            $firewallEvents | Select-Object TimeCreated, Id, SubjectUserName, IpAddress, Message | 
                Export-Csv -Path "$outputDir\FirewallModificationEvents.csv" -NoTypeInformation
        } else {
            # Create empty CSV with headers if no events found
            [PSCustomObject]@{
                TimeCreated     = $null
                Id              = $null
                SubjectUserName = $null
                IpAddress       = $null
                Message         = $null
            } | Export-Csv -Path "$outputDir\FirewallModificationEvents.csv" -NoTypeInformation
        }
    } catch {
        Write-Warning "Error collecting security events: $($_.Exception.Message)"
    }
}


# Collect application logs
$applicationLogsScript = {
    param($outputDir)
    try {
        $appLogs = Get-WinEvent -LogName Application -MaxEvents 1000 -ErrorAction SilentlyContinue
        $appEvents = foreach ($evt in $appLogs) {
            [PSCustomObject]@{
                TimeCreated      = $evt.TimeCreated
                Id               = $evt.Id
                LevelDisplayName = $evt.LevelDisplayName
                ProviderName     = $evt.ProviderName
                Message          = $evt.Message
            }
        }
        $appEvents | Export-Csv -Path "$outputDir\ApplicationLogs.csv" -NoTypeInformation
    } catch {
        Write-Warning "Error collecting application logs: $($_.Exception.Message)"
    }
}

# Collect system logs
$systemLogsScript = {
    param($outputDir)
    try {
        $sysLogs = Get-WinEvent -LogName System -MaxEvents 1000 -ErrorAction SilentlyContinue
        $sysEvents = foreach ($evt in $sysLogs) {
            [PSCustomObject]@{
                TimeCreated      = $evt.TimeCreated
                Id               = $evt.Id
                LevelDisplayName = $evt.LevelDisplayName
                ProviderName     = $evt.ProviderName
                Message          = $evt.Message
            }
        }
        $sysEvents | Export-Csv -Path "$outputDir\SystemLogs.csv" -NoTypeInformation
    } catch {
        Write-Warning "Error collecting system logs: $($_.Exception.Message)"
    }
}

# Collect installation events and enhance installed software list
$installEventsScript = {
    param($outputDir)
    $sidCache = @{}
    $installEvents = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; Id=11707 } -MaxEvents 10000 -ErrorAction SilentlyContinue
    $installData = foreach ($evt in $installEvents) {
        $sid = $evt.UserId
        $user = if ($sidCache.ContainsKey($sid)) {
            $sidCache[$sid]
        } else {
            try {
                $translated = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                $sidCache[$sid] = $translated
                $translated
            } catch {
                $sidCache[$sid] = "Unknown"
                "Unknown"
            }
        }
        $message = $evt.Message
        $product = if ($message -match 'Product: (.+?) --') { $matches[1] } else { "Unknown" }
        [PSCustomObject]@{
            TimeCreated = $evt.TimeCreated
            Product     = $product
            User        = $user
        }
    }
    $installLookup = @{}
    $installData | Group-Object -Property Product | ForEach-Object {
        $product = $_.Name
        $mostRecent = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $installLookup[$product] = $mostRecent
    }

    # Collect and enhance installed software
    $installedSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Where-Object { $_.DisplayName } | 
        Select-Object @{Name='Name'; Expression={$_.DisplayName}}, @{Name='Version'; Expression={$_.DisplayVersion}}
    $enhancedSoftware = foreach ($software in $installedSoftware) {
        $product = $software.Name
        $installEvent = $installLookup[$product]
        if ($installEvent) {
            $installTime = $installEvent.TimeCreated
            $installedBy = $installEvent.User
        } else {
            $installTime = $null
            $installedBy = "Unknown"
        }
        [PSCustomObject]@{
            Name        = $software.Name
            Version     = $software.Version
            InstallTime = $installTime
            InstalledBy = $installedBy
        }
    }
    $enhancedSoftware | Export-Csv -Path "$outputDir\InstalledSoftware.csv" -NoTypeInformation
}

# Collect USB device history from registry
$usbDeviceHistoryScript = {
    param($outputDir)
    try {
        $usbDevices = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction Stop | 
            Select-Object FriendlyName, DeviceDesc, Mfg, Service, Driver, ClassGUID, 
                @{Name='LastConnected'; Expression={$_.PSChildName}}
        $usbDevices | Export-Csv -Path "$outputDir\USBDeviceHistory.csv" -NoTypeInformation
    } catch {
        Write-Warning "Failed to collect USB device history: $($_.Exception.Message)"
        # Create an empty CSV with headers
        [PSCustomObject]@{
            FriendlyName  = $null
            DeviceDesc    = $null
            Mfg           = $null
            Service       = $null
            Driver        = $null
            ClassGUID     = $null
            LastConnected = $null
        } | Export-Csv -Path "$outputDir\USBDeviceHistory.csv" -NoTypeInformation
    }
}

# Define script blocks for dependent tasks

# Collect user accounts, dependent on logonIpLookup
$userAccountsScript = {
    param($outputDir, $logonIpLookupPath)
    $logonIpLookup = Get-Content -Path $logonIpLookupPath | ConvertFrom-Json
    Get-LocalUser | 
        Select-Object Name, Enabled, LastLogon, 
            @{Name='LastLogonIp'; Expression={$logonIpLookup."$env:COMPUTERNAME\$($_.Name)"}}, 
            @{Name='IsAdmin'; Expression={(Get-LocalGroupMember -Group "Administrators" -Member $_.Name -ErrorAction SilentlyContinue) -ne $null}} | 
        Export-Csv -Path "$outputDir\UserAccounts.csv" -NoTypeInformation
}

# Collect running processes, dependent on logonIpLookup, with command line, parent process, and child process details
$runningProcessesScript = {
    param($outputDir, $logonIpLookupPath)
    $logonIpLookup = Get-Content -Path $logonIpLookupPath | ConvertFrom-Json

    # Get all Win32_Process instances for additional process details
    $win32Processes = Get-CimInstance -Class Win32_Process
    # Create a hashtable for quick lookup by ProcessId
    $processLookup = @{}
    foreach ($proc in $win32Processes) {
        $processLookup[[int]$proc.ProcessId] = $proc
    }

    # Collect and enhance running process information
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        $procId = [int]$proc.Id
        $win32Proc = $processLookup[$procId]

        if ($win32Proc) {
            # Extract command line
            $commandLine = $win32Proc.CommandLine

            # Get parent process details
            $parentProcessId = [int]$win32Proc.ParentProcessId
            $parentProc = $processLookup[$parentProcessId]
            $parentName = if ($parentProc) { $parentProc.Name } else { "N/A" }

            # Get child process IDs
            $childProcessIds = ($win32Processes | Where-Object { [int]$_.ParentProcessId -eq $procId }).ProcessId -join ','

            # Output enhanced process object
            [PSCustomObject]@{
                Id               = $proc.Id
                Name             = $proc.Name
                Path             = $proc.Path
                StartTime        = $proc.StartTime
                UserName         = $proc.UserName
                CPU              = $proc.CPU
                WorkingSet       = $proc.WorkingSet
                LastLogonIp      = $logonIpLookup."$($proc.UserName)"
                CommandLine      = $commandLine
                ParentProcessId  = $parentProcessId
                ParentProcessName= $parentName
                ChildProcessIds  = $childProcessIds
            }
        } else {
            # Handle cases where Win32_Process data is unavailable
            [PSCustomObject]@{
                Id               = $proc.Id
                Name             = $proc.Name
                Path             = $proc.Path
                StartTime        = $proc.StartTime
                UserName         = $proc.UserName
                CPU              = $proc.CPU
                WorkingSet       = $proc.WorkingSet
                LastLogonIp      = $logonIpLookup."$($proc.UserName)"
                CommandLine      = "N/A"
                ParentProcessId  = "N/A"
                ParentProcessName= "N/A"
                ChildProcessIds  = "N/A"
            }
        }
    } | Export-Csv -Path "$outputDir\RunningProcesses.csv" -NoTypeInformation
}
# Collect ARP table entries
$arpTableScript = {
    param($outputDir)
    Get-NetNeighbor | 
        Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | 
        Export-Csv -Path "$outputDir\ARP_Table.csv" -NoTypeInformation
}

# Collect DNS client cache
$dnsCacheScript = {
    param($outputDir)
    Get-DnsClientCache | 
        Select-Object Entry, Name, Data, DataLength, Type, Section | 
        Export-Csv -Path "$outputDir\DNS_Cache.csv" -NoTypeInformation
}

# Collect browser history (Chrome/Edge)
$browserHistoryScript = {
    param($outputDir)
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    )
    $browserData = foreach ($path in $browserPaths) {
        if (Test-Path $path) {
            try {
                $db = New-Object System.Data.SQLite.SQLiteConnection
                $db.ConnectionString = "Data Source=$path; Read Only=True"
                $db.Open()
                $query = $db.CreateCommand()
                $query.CommandText = "SELECT url, title, visit_count, last_visit_time FROM urls"
                $adapter = New-Object System.Data.SQLite.SQLiteDataAdapter $query
                $dataset = New-Object System.Data.DataTable
                $adapter.Fill($dataset) | Out-Null
                $dataset | ForEach-Object {
                    [PSCustomObject]@{
                        Browser = Split-Path (Split-Path $path -Parent) -Leaf
                        URL     = $_.url
                        Title   = $_.title
                        Visits  = $_.visit_count
                        LastVisit = [DateTime]::FromFileTime($_.last_visit_time)
                    }
                }
            } catch {
                Write-Warning "Failed to read "
            } finally {
                if ($db.State -eq 'Open') { $db.Close() }
            }
        }
    }
    if ($browserData) {
        $browserData | Export-Csv -Path "$outputDir\BrowserHistory.csv" -NoTypeInformation
    }
}

# Collect environment variables
$envVarsScript = {
    param($outputDir)
    Get-ChildItem Env: | 
        Select-Object Name, Value | 
        Export-Csv -Path "$outputDir\EnvironmentVariables.csv" -NoTypeInformation
}

# Collect Group Policy settings
$gpoScript = {
    param($outputDir)
    gpresult /H "$outputDir\GPO_Report.html" | Out-Null
}

# Collect open shares and sessions
$openSharesScript = {
    param($outputDir)
    Get-SmbShare | 
        Select-Object Name, Path, Description | 
        Export-Csv -Path "$outputDir\OpenShares.csv" -NoTypeInformation
    Get-SmbSession | 
        Select-Object ClientComputerName, ClientUserName, Dialect, NumOpens | 
        Export-Csv -Path "$outputDir\SmbSessions.csv" -NoTypeInformation
}

# Collect RDP sessions
$rdpSessionsScript = {
    param($outputDir)
    qwinsta | 
        ForEach-Object { 
            if ($_ -match '\s{2,}') { 
                $split = $_ -split '\s+' 
                [PSCustomObject]@{
                    SessionName = $split[0]
                    Username    = $split[1]
                    ID          = $split[2]
                    State       = $split[3]
                }
            }
        } | 
        Export-Csv -Path "$outputDir\RDP_Sessions.csv" -NoTypeInformation
}

# Collect loaded DLLs for running processes
$loadedDllsScript = {
    param($outputDir)
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            $modules = $proc.Modules | 
                Select-Object ModuleName, FileName, FileVersion, @{Name='SHA256'; Expression={
                    try { (Get-FileHash $_.FileName -Algorithm SHA256).Hash } catch { "AccessDenied" }
                }}
            foreach ($module in $modules) {
                [PSCustomObject]@{
                    ProcessID   = $proc.Id
                    ProcessName = $proc.Name
                    DLLName     = $module.ModuleName
                    DLLPath     = $module.FileName
                    SHA256      = $module.SHA256
                }
            }
        } catch {
            Write-Warning "Failed to collect DLLs for $($proc.Name): $($_.Exception.Message)"
        }
    } | Export-Csv -Path "$outputDir\LoadedDLLs.csv" -NoTypeInformation
}

# Collect disk and volume information
$diskInfoScript = {
    param($outputDir)
    Get-Disk | 
        Select-Object Number, FriendlyName, Size, PartitionStyle | 
        Export-Csv -Path "$outputDir\DiskInfo.csv" -NoTypeInformation
    Get-Volume | 
        Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining | 
        Export-Csv -Path "$outputDir\VolumeInfo.csv" -NoTypeInformation
}

# Start independent jobs
$systemInfoJob = Start-Job -ScriptBlock $systemInfoScript -ArgumentList $outputDir
$hardwareInfoJob = Start-Job -ScriptBlock $hardwareInfoScript -ArgumentList $outputDir
$adminUsersJob = Start-Job -ScriptBlock $adminUsersScript -ArgumentList $outputDir
$firewallStatusJob = Start-Job -ScriptBlock $firewallStatusScript -ArgumentList $outputDir
$startupEntriesJob = Start-Job -ScriptBlock $startupEntriesScript -ArgumentList $outputDir
$scheduledTasksJob = Start-Job -ScriptBlock $scheduledTasksScript -ArgumentList $outputDir
$recentFileChangesJob = Start-Job -ScriptBlock $recentFileChangesScript -ArgumentList $outputDir
$suspiciousFilesJob = Start-Job -ScriptBlock $suspiciousFilesScript -ArgumentList $outputDir
$networkConnectionsJob = Start-Job -ScriptBlock $networkConnectionsScript -ArgumentList $outputDir
$securityEventsJob = Start-Job -ScriptBlock $securityEventsScript -ArgumentList $outputDir
$installEventsJob = Start-Job -ScriptBlock $installEventsScript -ArgumentList $outputDir
$applicationLogsJob = Start-Job -ScriptBlock $applicationLogsScript -ArgumentList $outputDir
$systemLogsJob = Start-Job -ScriptBlock $systemLogsScript -ArgumentList $outputDir
$usbDeviceHistoryJob = Start-Job -ScriptBlock $usbDeviceHistoryScript -ArgumentList $outputDir
$arpTableJob = Start-Job -ScriptBlock $arpTableScript -ArgumentList $outputDir
$dnsCacheJob = Start-Job -ScriptBlock $dnsCacheScript -ArgumentList $outputDir
$browserHistoryJob = Start-Job -ScriptBlock $browserHistoryScript -ArgumentList $outputDir
$envVarsJob = Start-Job -ScriptBlock $envVarsScript -ArgumentList $outputDir
$gpoJob = Start-Job -ScriptBlock $gpoScript -ArgumentList $outputDir
$openSharesJob = Start-Job -ScriptBlock $openSharesScript -ArgumentList $outputDir
$rdpSessionsJob = Start-Job -ScriptBlock $rdpSessionsScript -ArgumentList $outputDir
$loadedDllsJob = Start-Job -ScriptBlock $loadedDllsScript -ArgumentList $outputDir
$diskInfoJob = Start-Job -ScriptBlock $diskInfoScript -ArgumentList $outputDir

# Wait for security events job to complete (produces logonIpLookup.json needed by dependent jobs)
Wait-Job $securityEventsJob

# Start dependent jobs
$userAccountsJob = Start-Job -ScriptBlock $userAccountsScript -ArgumentList $outputDir, "$outputDir\logonIpLookup.json"
$runningProcessesJob = Start-Job -ScriptBlock $runningProcessesScript -ArgumentList $outputDir, "$outputDir\logonIpLookup.json"

# Collect all jobs
$allJobs = @($systemInfoJob, $hardwareInfoJob, $adminUsersJob, $firewallStatusJob, $startupEntriesJob, 
             $scheduledTasksJob, $recentFileChangesJob, $suspiciousFilesJob, $networkConnectionsJob, 
             $securityEventsJob,  $installEventsJob, $applicationLogsJob, $systemLogsJob,
             $userAccountsJob, $runningProcessesJob, $usbDeviceHistoryJob,$arpTableJob, $dnsCacheJob, $browserHistoryJob, $envVarsJob, 
    $gpoJob, $openSharesJob, $rdpSessionsJob, $loadedDllsJob, $diskInfoJob)

# Wait for all jobs to complete
Wait-Job -Job $allJobs


# Check for job failures
$allJobs | ForEach-Object {
    if ($_.State -eq 'Failed') {
        Write-Warning "Job $($_.Name) failed: $($_.Error)"
    }
}

# Receive job outputs and clean up
Receive-Job -Job $allJobs -AutoRemoveJob -Wait

# Display completion message and list collected files
Write-Host "Data collection complete. Files saved to $outputDir"
Get-ChildItem $outputDir | ForEach-Object {
    Write-Host "$($_.Name): $($_.Length) bytes"
}