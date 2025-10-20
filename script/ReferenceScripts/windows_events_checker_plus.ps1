<#
.SYNOPSIS
  Windows Security EventID coverage checker for Microsoft Sentinel analytic rules ("plus" version, user-tuned).

.DESCRIPTION
  Differences vs prior plus version per user feedback:
   - Prints real analytic rule NAMES (not Rule-1, Rule-2...)
   - New ASCII art banner (no "Branding" word in output)
   - XPath now targets the FULL set of required EventIDs (not only missing)
   - Removed JSON-style report block from output entirely
   - Adds optional billed volume view for EventIDs that are INGESTED but UNUSED by analyzed rules (30 days) shown in **MB**
   - Keeps optional WindowsEvent checks and UNION mode, with safe fallback to SecurityEvent-only

.NOTES
  Author: Rishi Aggarwal (Trustwave)
  File: windows_events_checker_plus.ps1
#>

[CmdletBinding()]
param (
    # -------- Global parameters (unchanged) --------
    [Parameter(Mandatory=$true)]
    [string] $subscriptionId,

    [Parameter(Mandatory=$true)]
    [string] $workspaceId,

    [Parameter(Mandatory=$false)]
    [int] $timespan = 7,

    # -------- ArmTemplate mode --------
    [switch] $useArmTemplates = $false,
    [Parameter(Mandatory=$false)]
    [string] $analyticsArmFolder,

    # -------- autoCheck mode --------
    [switch] $useAutoCheck = $false,
    [Parameter(Mandatory=$false)]
    [string] $resourceGroupName,
    [Parameter(Mandatory=$false)]
    [string] $workspaceName,

    # -------- "plus" flags --------
    [switch] $CheckWindowsEvent = $false,
    [switch] $UseUnion = $false,
    [int]    $UnionTimespan = 90,

    # Banner text (display only; NOT printed as "Branding")
    [string] $BannerText = "built for Microsoft Sentinel by Rishi Aggarwal (Trustwave)",

    # Optional: compute billed volume for UNUSED EventIDs across last N days (default 30)
    [int] $UnusedVolumeDays = 30
)

# region --------- Utility ---------
function Show-AsciiBanner {
@"

██╗    ██╗██╗███╗   ██╗    ███████╗██╗   ██╗███████╗███╗   ██╗████████╗     ██████╗  █████╗ ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
██║    ██║██║████╗  ██║    ██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝    ██╔════╝ ██╔══██╗██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
██║ █╗ ██║██║██╔██╗ ██║    █████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║       ██║  ███╗███████║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██║███╗██║██║██║╚██╗██║    ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║       ██║   ██║██╔══██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
╚███╔███╔╝██║██║ ╚████║    ███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║       ╚██████╔╝██║  ██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝    ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝        ╚═════╝ ╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
This script is $BannerText
"@ | Write-Host
}

function Ensure-ModuleOrWarn {
    param([string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Warning "Required module '$ModuleName' is not installed or not available in this session."
        return $false
    }
    return $true
}

function Ensure-AzContext {
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if (-not $ctx) { throw "No Az context." }
        return $true
    } catch {
        Write-Warning "No active Az context. Run: Connect-AzAccount; Select-AzSubscription -SubscriptionId $subscriptionId"
        return $false
    }
}

function Invoke-LogAnalyticsQuery {
    param(
        [string] $WorkspaceId,
        [string] $Query,
        [int]    $LookbackDays
    )
    try {
        $span = New-TimeSpan -Days $LookbackDays
        $res = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -Timespan $span -ErrorAction Stop
        if ($res -and $res.Results) { return $res.Results }
        return @()
    } catch {
        throw "Invoke-LogAnalyticsQuery failed: $($_.Exception.Message)"
    }
}
# endregion Utility

# region --------- Banner ---------
Show-AsciiBanner
# endregion Banner

# region --------- Parameter guards ---------
if (-not ($useArmTemplates -xor $useAutoCheck)) {
    throw "Select exactly one mode: -useArmTemplates OR -useAutoCheck."
}

if ($useArmTemplates -and [string]::IsNullOrWhiteSpace($analyticsArmFolder)) {
    throw "-analyticsArmFolder is required for -useArmTemplates mode."
}
if ($useAutoCheck) {
    if ([string]::IsNullOrWhiteSpace($resourceGroupName) -or [string]::IsNullOrWhiteSpace($workspaceName)) {
        throw "-resourceGroupName and -workspaceName are required for -useAutoCheck mode."
    }
}

# Modules check (warn only)
$hasOpInsights = Ensure-ModuleOrWarn -ModuleName "Az.OperationalInsights"
$hasSecInsights = Ensure-ModuleOrWarn -ModuleName "Az.SecurityInsights"
$hasAccounts    = Ensure-ModuleOrWarn -ModuleName "Az.Accounts"
if (-not (Ensure-AzContext)) {
    Write-Warning "Proceeding may fail when accessing Azure APIs."
}

# endregion guards

# region --------- KQL blocks ---------
$securityEventsQuery = @"
SecurityEvent
| where TimeGenerated > ago(${timespan}d)
| distinct EventID
"@

$windowsEventsQuery = @"
WindowsEvent
| where TimeGenerated > ago(${timespan}d)
| distinct EventID
"@

$unionEventsQuery = @"
union isfuzzy=true
  (SecurityEvent | where TimeGenerated > ago(${UnionTimespan}d) | project EventID),
  (WindowsEvent  | where TimeGenerated > ago(${UnionTimespan}d) | project EventID)
| where isnotempty(EventID)
| summarize by EventID
"@

# For billed size of ingested-but-unused EventIDs
$unusedVolumeQuery = @"
union withsource=TableName1 WindowsEvent, SecurityEvent
| where _IsBillable == true
| summarize ['Table Size'] = sum(_BilledSize) by TableName=TableName1, EventID
"@
# endregion KQL blocks

# region --------- Regex for EventIDs (unchanged) ---------
$eventIdRegex = 'EventID==(\d{3,4})|EventID == (\d{3,4})|EventID=="(\d{3,4})"|EventID == "(\d{3,4})"|EventID==''(\d{3,4})''|EventID == ''(\d{3,4})''|"((?:\d{3,4})+)",?|''((?:\d{3,4})+)'',?|\((\d{3,4}),?|[,\s]((?:\d{3,4})+)[,\s]|((?:\d{3,4})+)(?=\))'
# endregion Regex

# region --------- Load Analytic rules (with REAL names) ---------
function Get-AnalyticQueriesFromArmTemplates {
    param([string]$Folder)
    $rules = New-Object System.Collections.Generic.List[object]
    try {
        if (-not (Test-Path -LiteralPath $Folder)) {
            throw "Folder not found: $Folder"
        }
        Get-ChildItem -LiteralPath $Folder -Recurse -Include *.json | ForEach-Object {
            try {
                $json = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
                $candidates = @()
                if ($json.resources) { $candidates += $json.resources }
                if ($json.properties) { $candidates += $json }  # sometimes properties on root

                foreach ($res in $candidates) {
                    $q = $null
                    $displayName = $null
                    if ($res.properties) {
                        $q = $res.properties.query
                        $displayName = $res.properties.displayName
                    }
                    if (-not $displayName) { $displayName = $res.name }
                    if ($q) {
                        $rules.Add([pscustomobject]@{ Name = [string]$displayName; Query = [string]$q })
                    }
                }
            } catch {
                Write-Warning "Failed to parse template '$_': $($_.Exception.Message)"
            }
        }
    } catch {
        throw "Get-AnalyticQueriesFromArmTemplates failed: $($_.Exception.Message)"
    }
    return $rules
}

function Get-AnalyticQueriesFromWorkspace {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName
    )
    $rules = New-Object System.Collections.Generic.List[object]
    $apiVersions = @("2024-01-01","2023-11-01-preview","2023-02-01-preview")
    foreach ($v in $apiVersions) {
        try {
            $uri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$v"
            $res = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
            if ($res.StatusCode -ge 200 -and $res.StatusCode -lt 300) {
                $data = $res.Content | ConvertFrom-Json
                foreach ($item in $data.value) {
                    $kind = $item.kind
                    if ($kind -ne "Scheduled") { continue }
                    $q = $item.properties.query
                    $displayName = $item.properties.displayName
                    if (-not $displayName) { $displayName = $item.name }
                    if ($q) { $rules.Add([pscustomobject]@{ Name = [string]$displayName; Query = [string]$q }) }
                }
                if ($rules.Count -gt 0) { return $rules }
            }
        } catch {
            Write-Warning "Invoke-AzRestMethod (api $v) failed: $($_.Exception.Message)"
        }
    }
    # Fallback via module, if available
    try {
        if (Get-Command -Name Get-AzSentinelAlertRule -ErrorAction SilentlyContinue) {
            $list = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop
            foreach ($r in $list) {
                if ($r.Kind -eq "Scheduled" -and $r.Query) {
                    $name = $r.DisplayName
                    if (-not $name) { $name = $r.Name }
                    $rules.Add([pscustomobject]@{ Name = [string]$name; Query = [string]$r.Query })
                }
            }
        }
    } catch {
        Write-Warning "Get-AzSentinelAlertRule fallback failed: $($_.Exception.Message)"
    }
    return $rules
}
# endregion Load rules

# region --------- Gather Analytic rules ---------
$analyticRules = New-Object System.Collections.Generic.List[object]
if ($useArmTemplates) {
    Write-Host "Mode: ArmTemplate" -ForegroundColor Cyan
    $analyticRules = Get-AnalyticQueriesFromArmTemplates -Folder $analyticsArmFolder
} else {
    Write-Host "Mode: autoCheck" -ForegroundColor Cyan
    $analyticRules = Get-AnalyticQueriesFromWorkspace -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName
}

if (-not $analyticRules -or $analyticRules.Count -eq 0) {
    Write-Warning "No analytic rules found."
}
# endregion Gather

# region --------- Extract EventIDs per rule (with table guard) ---------
$perRule = @()
$allReferencedEventIds = New-Object System.Collections.Generic.HashSet[int]

foreach ($rule in $analyticRules) {
    $query = [string]$rule.Query
    $ruleName = [string]$rule.Name

    # Only consider rules that query SecurityEvent or WindowsEvent and also reference EventID
    $hasTargetTable = ($query -match '\bSecurityEvent\b' -or $query -match '\bWindowsEvent\b')
    $hasEventIdTerm = ($query -match '\bEventID\b')
    if (-not ($hasTargetTable -and $hasEventIdTerm)) { continue }

    $matches = Select-String -Pattern $eventIdRegex -InputObject $query -AllMatches
    $ids = @()
    foreach ($m in $matches.Matches) {
        foreach ($g in 1..$m.Groups.Count) {
            $val = $m.Groups[$g].Value
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $split = $val -split "[^\d]"
            foreach ($s in $split) {
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                if ($s -match '^\d{3,4}$') {
                    $n = [int]$s
                    if (-not $ids.Contains($n)) { $ids += $n }
                }
            }
        }
    }

    foreach ($n in $ids) { [void]$allReferencedEventIds.Add($n) }

    $perRule += [pscustomobject]@{
        RuleName           = $ruleName
        EventIDsReferenced = ($ids -join ", ")
    }
}

Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ Event IDs found per rule (real rule names)" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
$perRule | Sort-Object RuleName | Format-Table -AutoSize | Out-String | Write-Host

$usedEventIds = @([int[]]$allReferencedEventIds) | Sort-Object -Unique
Write-Host "All referenced EventIDs: $($usedEventIds -join ', ')" -ForegroundColor DarkGray
# endregion Extract

# region --------- Query ingested EventIDs (with safe fallback) ---------
$ingestedEventIds = @()
try {
    if ($UseUnion) {
        $u = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $unionEventsQuery -LookbackDays $UnionTimespan
        $ingestedEventIds = $u | ForEach-Object { $_.EventID } | Sort-Object -Unique
        Write-Host "Using UNION of SecurityEvent + WindowsEvent over last $UnionTimespan days." -ForegroundColor DarkGray
    }
    elseif ($CheckWindowsEvent) {
        $w = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $windowsEventsQuery -LookbackDays $timespan
        $s = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $securityEventsQuery -LookbackDays $timespan
        $ingestedEventIds = @($s + $w | ForEach-Object { $_.EventID }) | Sort-Object -Unique
        Write-Host "Combined SecurityEvent + WindowsEvent over last $timespan days." -ForegroundColor DarkGray
    }
    else {
        $s = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $securityEventsQuery -LookbackDays $timespan
        $ingestedEventIds = $s | ForEach-Object { $_.EventID } | Sort-Object -Unique
        Write-Host "Using SecurityEvent only over last $timespan days (original behavior)." -ForegroundColor DarkGray
    }
}
catch {
    Write-Warning "Extended ingestion checks failed (Union/WindowsEvent). Falling back to SecurityEvent only. Error: $($_.Exception.Message)"
    try {
        $s = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $securityEventsQuery -LookbackDays $timespan
        $ingestedEventIds = $s | ForEach-Object { $_.EventID } | Sort-Object -Unique
    } catch {
        throw "SecurityEvent fallback failed: $($_.Exception.Message)"
    }
}

if (-not $ingestedEventIds) { $ingestedEventIds = @() }
Write-Host "Ingested EventIDs (lookback): $($ingestedEventIds -join ', ')" -ForegroundColor DarkGray
# endregion Ingested

# region --------- Per-rule status vs ingested ---------
$ruleStatus = foreach ($row in $perRule) {
    $ids = @()
    if ($row.EventIDsReferenced) {
        $ids = $row.EventIDsReferenced -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d{3,4}$' } | ForEach-Object { [int]$_ }
    }
    $present = @($ids | Where-Object { $_ -in $ingestedEventIds })
    $missing = @($ids | Where-Object { $_ -notin $ingestedEventIds })

    [pscustomobject]@{
        RuleName           = $row.RuleName
        Present            = ($present -join ", ")
        Missing            = ($missing -join ", ")
    }
}

Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ Per-rule EventID coverage (Present/Missing)" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
$ruleStatus | Sort-Object RuleName | Format-Table -AutoSize | Out-String | Write-Host
# endregion Per-rule

# region --------- Consolidated view ---------
$neededMissing     = @($usedEventIds | Where-Object { $_ -notin $ingestedEventIds }) | Sort-Object -Unique
$neededPresent     = @($usedEventIds | Where-Object { $_ -in  $ingestedEventIds }) | Sort-Object -Unique
$ingestedButUnused = @($ingestedEventIds | Where-Object { $_ -notin $usedEventIds }) | Sort-Object -Unique

Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ Consolidated View" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow

Write-Host "Needed & MISSING (referenced by rules but not ingested):" -ForegroundColor Red
if ($neededMissing.Count -gt 0) { ($neededMissing -join ", ") | Write-Host } else { Write-Host "(none)" -ForegroundColor DarkGray }

Write-Host "`nNeeded & PRESENT (referenced by rules and ingested):" -ForegroundColor Green
if ($neededPresent.Count -gt 0) { ($neededPresent -join ", ") | Write-Host } else { Write-Host "(none)" -ForegroundColor DarkGray }

Write-Host "`nIngested but UNUSED by analyzed rules:" -ForegroundColor Cyan
if ($ingestedButUnused.Count -gt 0) { ($ingestedButUnused -join ", ") | Write-Host } else { Write-Host "(none)" -ForegroundColor DarkGray }
# endregion Consolidated

# region --------- XPath output (FULL required set) ---------
$XPathAllRequired = "Security!*[System["
if ($usedEventIds.Count -gt 0) {
    $conditions = $usedEventIds | ForEach-Object { "(EventID=$_)"} 
    $XPathAllRequired += ($conditions -join " or ")
}
$XPathAllRequired += "]]"

Write-Host "┏━━━" -ForegroundColor Yellow
Write-Host "┃ XPath to ingest ALL required events referenced by detection rules:" -ForegroundColor Yellow
Write-Host "┗━━━" -ForegroundColor Yellow
Write-Host " $XPathAllRequired"
# endregion XPath

# region --------- Optional: volume for UNUSED EventIDs (last N days, shown in MB) ---------
try {
    if ($ingestedButUnused.Count -gt 0) {
        $vol = Invoke-LogAnalyticsQuery -WorkspaceId $workspaceId -Query $unusedVolumeQuery -LookbackDays $UnusedVolumeDays
        if ($vol -and $vol.Count -gt 0) {
            # Sum volume per EventID across tables (bytes)
            $byId = @{}
            foreach ($row in $vol) {
                $eid = $row.EventID
                if ($null -eq $eid) { continue }
                if (-not $byId.ContainsKey($eid)) { $byId[$eid] = 0 }
                $byId[$eid] += [double]$row.'Table Size'
            }

            $propName = "BilledSizeMB_Last${UnusedVolumeDays}d"

            $unusedWithVol = $ingestedButUnused | ForEach-Object {
                $sizeBytes = 0
                if ($byId.ContainsKey($_)) { $sizeBytes = [double]$byId[$_] }
                $sizeMB = [math]::Round($sizeBytes / 1MB, 2)
                $ht = [ordered]@{ EventID = $_ }
                $ht[$propName] = $sizeMB
                [pscustomobject]$ht
            } | Sort-Object -Property $propName -Descending

            Write-Host "`n┏━━━" -ForegroundColor Yellow
            Write-Host "┃ Ingested but UNUSED — billed volume (last $UnusedVolumeDays days, MB)" -ForegroundColor Yellow
            Write-Host "┗━━━" -ForegroundColor Yellow
            $unusedWithVol | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
} catch {
    Write-Warning "Failed to compute billed volume for unused EventIDs: $($_.Exception.Message)"
}
# endregion Volume
