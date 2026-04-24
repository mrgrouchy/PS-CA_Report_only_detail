<#
.SYNOPSIS
WIP script to evaluate report-only Conditional Access MFA/risk impact.

.DESCRIPTION
Early/in-progress utility. Behavior and parameters may change.

.EXAMPLE
PS> .\CA_report.ps1
Runs the current draft workflow.

.NOTES
Required Microsoft Graph scopes: AuditLog.Read.All, Policy.Read.All, Group.Read.All
When using -UseLogAnalytics, ensure Az.Accounts and Az.OperationalInsights are installed
and that your account has permission to query the target workspace.
#>

param(
    [string]$TargetPolicy,
    [switch]$AllPolicies,
    [string]$ProdPolicy,
    [switch]$All,
    [switch]$UseLogAnalytics,
    [string]$LogAnalyticsWorkspaceId,
    [switch]$NoGroupCheck,
    [switch]$UseGraphAPI,
    [switch]$SimpleCA002ATest
)

# Default to Log Analytics (the working path from -SimpleCA002ATest)
if (-not $UseGraphAPI) {
    $UseLogAnalytics = $true
}

# Hardcode expected-impact group IDs here (recommended: object IDs, not names).
# If populated, these groups take precedence over -ProdPolicy/auto-discovery.
$HardcodedExpectedGroupIds = @(
    # "00000000-0000-0000-0000-000000000001",
    # "00000000-0000-0000-0000-000000000002",
    # "00000000-0000-0000-0000-000000000003",
    # "00000000-0000-0000-0000-000000000004"
)

# Hardcoded Log Analytics workspace (redacted)
$WorkspaceId = "00000000-0000-0000-0000-000000000000"

# ------------------------------------------------------------
# Graph connection
# ------------------------------------------------------------

$TenantId  = "00000000-0000-0000-0000-000000000000"
$ClientId  = "00000000-0000-0000-0000-000000000000"
$Thumbprint = "0000000000000000000000000000000000000000"   # cert must exist in CurrentUser\My or LocalMachine\My

function Test-GraphConnectivity {
  try {
    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=1&`$select=id" -Method GET -ErrorAction Stop | Out-Null
    return $true
  }
  catch {
    return $false
  }
}

$usingExistingGraph = $false
try {
  $ctx = Get-MgContext -ErrorAction Stop
  if ($ctx -and $ctx.Account -and (Test-GraphConnectivity)) {
    $usingExistingGraph = $true
    Write-Host "Using existing Microsoft Graph session: $($ctx.Account) ($($ctx.TenantId))" -ForegroundColor DarkGray
  }
}
catch {
  $usingExistingGraph = $false
}

if (-not $usingExistingGraph) {
  $hasAppAuthConfig = (-not [string]::IsNullOrWhiteSpace($TenantId)) -and
                      (-not [string]::IsNullOrWhiteSpace($ClientId)) -and
                      (-not [string]::IsNullOrWhiteSpace($Thumbprint))

  if ($hasAppAuthConfig) {
    Write-Host "No active Graph session found. Connecting with app certificate auth..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -NoWelcome
  }
  else {
    Write-Host "No active Graph session found and app auth values are empty. Using interactive Graph sign-in for testing..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Policy.Read.All", "Group.Read.All" -NoWelcome
  }
}

# Verify Graph connection is established before proceeding
$finalContext = Get-MgContext -ErrorAction Stop
if (-not $finalContext -or (-not $finalContext.Account -and -not $finalContext.ClientId)) {
  Write-Host "ERROR: Microsoft Graph connection failed or was not established. Exiting." -ForegroundColor Red
  exit 1
}

$authType = if ($finalContext.AuthType -eq 'AppOnly') { "AppOnly (Certificate)" } else { $finalContext.AuthType }
$accountDisplay = if ($finalContext.Account) { $finalContext.Account } else { $finalContext.ClientId }
Write-Host "Graph connection verified: $accountDisplay / Tenant: $($finalContext.TenantId) / Auth: $authType" -ForegroundColor Green

# Define time range for analysis (adjust as needed)
$startDate = (Get-Date).AddDays(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

function Get-SafePercentage {
    param(
        [double]$Numerator,
        [double]$Denominator
    )

    if ($Denominator -le 0) {
        return 0
    }

    return [math]::Round(($Numerator / $Denominator) * 100, 2)
}

function Get-GroupMemberUserIds {
    param(
        [string[]]$GroupIds
    )

    $userIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $resolvedGroups = @()

    foreach ($groupId in @($GroupIds | Where-Object { $_ -and $_ -ne 'All' })) {
        $groupName = $groupId
        try {
            $groupInfo = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId?`$select=displayName,id" -Method GET
            if ($groupInfo.displayName) {
                $groupName = $groupInfo.displayName
            }
        } catch {}

        $resolvedGroups += [PSCustomObject]@{
            GroupId = $groupId
            GroupName = $groupName
        }

        $membersUri = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
        do {
            try {
                $memberResponse = Invoke-MgGraphRequest -Uri $membersUri -Method GET
                foreach ($member in @($memberResponse.value)) {
                    if ($member.id) {
                        $null = $userIds.Add($member.id)
                    }
                }
                $membersUri = $memberResponse.'@odata.nextLink'
            } catch {
                Write-Host "Warning: Unable to read members for group '$groupName' ($groupId). Skipping this group." -ForegroundColor Yellow
                break
            }
        } while ($membersUri)
    }

    return [PSCustomObject]@{
        UserIds = $userIds
        Groups = $resolvedGroups
    }
}

function Convert-JsonIfString {
    param(
        [Parameter(Mandatory = $false)]
        $Value,
        [switch]$AsArray,
        [switch]$AsObject
    )

    if ($null -eq $Value) {
        if ($AsArray) { return @() }
        if ($AsObject) { return [PSCustomObject]@{} }
        return $null
    }

    $parsed = $Value
    if ($Value -is [string]) {
        try {
            $parsed = $Value | ConvertFrom-Json -Depth 20
        } catch {
            $parsed = $Value
        }
    }

    if ($AsArray) {
        if ($parsed -is [string]) {
            if ([string]::IsNullOrWhiteSpace($parsed)) {
                return @()
            }
            return @($parsed)
        }
        return @($parsed)
    }

    if ($AsObject) {
        if ($parsed -is [string]) {
            return [PSCustomObject]@{}
        }
        return $parsed
    }

    return $parsed
}

function Convert-LogAnalyticsSignIn {
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    [PSCustomObject]@{
        createdDateTime = if ($Record.createdDateTime) { $Record.createdDateTime } else { $Record.CreatedDateTime }
        userPrincipalName = if ($Record.userPrincipalName) { $Record.userPrincipalName } else { $Record.UserPrincipalName }
        userDisplayName = if ($Record.userDisplayName) { $Record.userDisplayName } else { $Record.UserDisplayName }
        userId = if ($Record.userId) { $Record.userId } else { $Record.UserId }

        appliedConditionalAccessPolicies = Convert-JsonIfString -Value $(if ($Record.appliedConditionalAccessPolicies) { $Record.appliedConditionalAccessPolicies } else { $Record.ConditionalAccessPolicies }) -AsArray
        riskLevelDuringSignIn = if ($Record.riskLevelDuringSignIn) { $Record.riskLevelDuringSignIn } else { $Record.RiskLevelDuringSignIn }
        userRiskLevel = if ($Record.userRiskLevel) { $Record.userRiskLevel } else { $Record.UserRiskLevel }
        riskState = if ($Record.riskState) { $Record.riskState } else { $Record.RiskState }
        riskEventTypes_v2 = Convert-JsonIfString -Value $(if ($Record.riskEventTypes_v2) { $Record.riskEventTypes_v2 } else { $Record.RiskEventTypes_V2 }) -AsArray
        riskDetail = if ($Record.riskDetail) { $Record.riskDetail } else { $Record.RiskDetail }

        authenticationMethodsUsed = Convert-JsonIfString -Value $(if ($Record.authenticationMethodsUsed) { $Record.authenticationMethodsUsed } else { $Record.AuthenticationMethodsUsed }) -AsArray
        authenticationRequirement = if ($Record.authenticationRequirement) { $Record.authenticationRequirement } else { $Record.AuthenticationRequirement }

        appDisplayName = if ($Record.appDisplayName) { $Record.appDisplayName } else { $Record.AppDisplayName }
        appId = if ($Record.appId) { $Record.appId } else { $Record.AppId }
        resourceDisplayName = if ($Record.resourceDisplayName) { $Record.resourceDisplayName } else { $Record.ResourceDisplayName }

        deviceDetail = Convert-JsonIfString -Value $(if ($Record.deviceDetail) { $Record.deviceDetail } else { $Record.DeviceDetail }) -AsObject
        location = Convert-JsonIfString -Value $(if ($Record.location) { $Record.location } else { $Record.Location }) -AsObject

        ipAddress = if ($Record.ipAddress) { $Record.ipAddress } else { $Record.IPAddress }
        clientAppUsed = if ($Record.clientAppUsed) { $Record.clientAppUsed } else { $Record.ClientAppUsed }
        isInteractive = if ($null -ne $Record.isInteractive) { $Record.isInteractive } else { $Record.IsInteractive }

        status = Convert-JsonIfString -Value $(if ($Record.status) { $Record.status } else { $Record.Status }) -AsObject
        correlationId = if ($Record.correlationId) { $Record.correlationId } else { $Record.CorrelationId }
        id = if ($Record.id) { $Record.id } else { $Record.Id }

        matchedPolicyId = if ($Record.matchedPolicyId) { $Record.matchedPolicyId } else { $Record.MatchedPolicyId }
        matchedPolicyResult = if ($Record.matchedPolicyResult) { $Record.matchedPolicyResult } else { $Record.MatchedPolicyResult }
        matchedPolicyDisplayName = if ($Record.matchedPolicyDisplayName) { $Record.matchedPolicyDisplayName } else { $Record.MatchedPolicyDisplayName }
    }
}

Write-Host "=== SIGN-IN RISK & MFA REQUIREMENT ANALYSIS ===" -ForegroundColor Cyan
Write-Host "Analyzing report-only CA policies for sign-in risk and MFA impact..." -ForegroundColor Yellow
Write-Host "Date range: $((Get-Date).AddDays(-2).ToString('yyyy-MM-dd')) to $((Get-Date).ToString('yyyy-MM-dd'))`n" -ForegroundColor Yellow

if ($SimpleCA002ATest) {
    $TargetPolicy = "CA002A - All apps All Users: Require MFA when High or Medium User sign-in risk"
    $AllPolicies = $false
    $NoGroupCheck = $true
    $UseLogAnalytics = $true
    Write-Host "Simple test mode enabled: CA002A, last 48 hours, reportOnlyInterrupted only, no group exclusion." -ForegroundColor Yellow
}

# Fetch all CA policies to identify risk-based ones
Write-Host "Fetching Conditional Access policies..." -ForegroundColor Cyan
$caPolicies = @()
$policyUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=200"
do {
    $policyResponse = Invoke-MgGraphRequest -Uri $policyUri -Method GET
    $caPolicies += $policyResponse.value
    $policyUri = $policyResponse.'@odata.nextLink'
} while ($policyUri)

$reportOnlyPolicies = $caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }

# Identify risk-based policies (sign-in risk, user risk, or MFA/passwordChange grant controls)
$riskPolicies = $reportOnlyPolicies | Where-Object {
    $_.Conditions.SignInRiskLevels.Count -gt 0 -or
    $_.Conditions.UserRiskLevels.Count -gt 0 -or
    $_.GrantControls.BuiltInControls -contains 'mfa' -or
    $_.GrantControls.BuiltInControls -contains 'passwordChange'
} | Sort-Object DisplayName

$riskPolicies = @($riskPolicies)
if ($riskPolicies.Count -eq 0) {
    Write-Host "No report-only policies with risk/MFA conditions were found. Exiting." -ForegroundColor Red
    return
}

Write-Host "Found $($riskPolicies.Count) report-only policies with risk/MFA conditions:" -ForegroundColor Green
$riskPolicies | ForEach-Object {
    Write-Host "  - $($_.DisplayName)" -ForegroundColor White
    Write-Host "    Sign-in risk levels: $(($_.Conditions.SignInRiskLevels -join ', '))" -ForegroundColor Gray
    Write-Host "    User risk levels:    $(($_.Conditions.UserRiskLevels -join ', '))" -ForegroundColor Gray
    Write-Host "    Grant controls:      $(($_.GrantControls.BuiltInControls -join ', '))" -ForegroundColor Gray
}

# Select target policy/policies
$targetPolicies = $riskPolicies
if (-not $AllPolicies) {
    if ($TargetPolicy) {
        $targetPolicies = @(
            $riskPolicies | Where-Object {
                $_.DisplayName -like "*$TargetPolicy*" -or $_.Id -eq $TargetPolicy
            }
        )

        if ($targetPolicies.Count -eq 0) {
            Write-Host "No report-only policy matched '$TargetPolicy'. Exiting." -ForegroundColor Red
            return
        }

        if ($targetPolicies.Count -gt 1) {
            Write-Host "Multiple policies matched '$TargetPolicy'. Use a more specific name or policy ID." -ForegroundColor Red
            $targetPolicies | ForEach-Object { Write-Host "  - $($_.DisplayName) [$($_.Id)]" -ForegroundColor Yellow }
            return
        }
    } else {
        Write-Host "`nSelect a target policy:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $riskPolicies.Count; $i++) {
            Write-Host "  [$($i + 1)] $($riskPolicies[$i].DisplayName)" -ForegroundColor White
        }
        Write-Host "  [A] All policies" -ForegroundColor White

        $selection = Read-Host "Enter selection (number or A, default A)"
        if ($selection -and $selection.Trim().ToUpper() -ne "A") {
            $selectedIndex = 0
            if (-not [int]::TryParse($selection, [ref]$selectedIndex) -or $selectedIndex -lt 1 -or $selectedIndex -gt $riskPolicies.Count) {
                Write-Host "Invalid selection '$selection'. Exiting." -ForegroundColor Red
                return
            }
            $targetPolicies = @($riskPolicies[$selectedIndex - 1])
        }
    }
}

$targetPolicyIds = @($targetPolicies.Id)
Write-Host "`nTarget policy scope: $($targetPolicies.Count) policy/policies selected." -ForegroundColor Green
$targetPolicies | ForEach-Object { Write-Host "  - $($_.DisplayName) [$($_.Id)]" -ForegroundColor White }

# Resolve prod policy users that are expected to be impacted already
$prodPolicies = $caPolicies | Where-Object {
    $_.State -eq 'enabled' -and (
        $_.Conditions.SignInRiskLevels.Count -gt 0 -or
        $_.Conditions.UserRiskLevels.Count -gt 0 -or
        $_.GrantControls.BuiltInControls -contains 'mfa' -or
        $_.GrantControls.BuiltInControls -contains 'passwordChange'
    )
}

$expectedUserIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$expectedGroups = @()
if ($NoGroupCheck) {
    Write-Host "`n-NoGroupCheck specified. Skipping group-based expected-user exclusion." -ForegroundColor Yellow
} elseif ($All) {
    Write-Host "`n-All switch specified. Group-based expected-user exclusion is disabled." -ForegroundColor Yellow
} else {
    $hardcodedGroupIds = @($HardcodedExpectedGroupIds | Where-Object { $_ -and $_ -ne 'All' })
    if ($hardcodedGroupIds.Count -gt 0) {
        Write-Host "`nResolving expected impacted users from hardcoded target groups..." -ForegroundColor Cyan

        $groupLookup = Get-GroupMemberUserIds -GroupIds $hardcodedGroupIds
        $expectedUserIds = $groupLookup.UserIds
        $expectedGroups = $groupLookup.Groups

        Write-Host "Found $($expectedGroups.Count) hardcoded groups with $($expectedUserIds.Count) unique users to exclude as expected impact." -ForegroundColor Green
        $expectedGroups | ForEach-Object {
            Write-Host "  - $($_.GroupName) [$($_.GroupId)]" -ForegroundColor Gray
        }
    } else {
        $selectedProdPolicy = $null
        if ($ProdPolicy) {
            $matchedProdPolicies = @(
                $prodPolicies | Where-Object {
                    $_.DisplayName -like "*$ProdPolicy*" -or $_.Id -eq $ProdPolicy
                }
            )

            if ($matchedProdPolicies.Count -eq 1) {
                $selectedProdPolicy = $matchedProdPolicies[0]
            } elseif ($matchedProdPolicies.Count -gt 1) {
                Write-Host "Multiple enabled prod policies matched '$ProdPolicy'. Using the first match: $($matchedProdPolicies[0].DisplayName)" -ForegroundColor Yellow
                $selectedProdPolicy = $matchedProdPolicies[0]
            } else {
                Write-Host "No enabled prod policy matched '$ProdPolicy'. No expected-user exclusion will be applied." -ForegroundColor Yellow
            }
        } else {
            $fourGroupCandidates = @($prodPolicies | Where-Object { @($_.Conditions.Users.IncludeGroups).Count -eq 4 })
            if ($fourGroupCandidates.Count -ge 1) {
                $selectedProdPolicy = $fourGroupCandidates[0]
            } elseif ($prodPolicies.Count -eq 1) {
                $selectedProdPolicy = $prodPolicies[0]
            }
        }

        if ($selectedProdPolicy) {
            $prodTargetGroupIds = @($selectedProdPolicy.Conditions.Users.IncludeGroups | Where-Object { $_ -and $_ -ne 'All' })
            if ($prodTargetGroupIds.Count -gt 0) {
                Write-Host "`nResolving expected impacted users from prod policy group targets..." -ForegroundColor Cyan
                Write-Host "Prod policy: $($selectedProdPolicy.DisplayName) [$($selectedProdPolicy.Id)]" -ForegroundColor White

                $groupLookup = Get-GroupMemberUserIds -GroupIds $prodTargetGroupIds
                $expectedUserIds = $groupLookup.UserIds
                $expectedGroups = $groupLookup.Groups

                Write-Host "Found $($expectedGroups.Count) target groups with $($expectedUserIds.Count) unique users to exclude as expected impact." -ForegroundColor Green
                $expectedGroups | ForEach-Object {
                    Write-Host "  - $($_.GroupName) [$($_.GroupId)]" -ForegroundColor Gray
                }
            } else {
                Write-Host "Prod policy '$($selectedProdPolicy.DisplayName)' has no explicit include groups. No expected-user exclusion will be applied." -ForegroundColor Yellow
            }
        } else {
            Write-Host "`nNo prod policy was auto-resolved for expected-user exclusion. Run with -ProdPolicy to force a specific enabled policy." -ForegroundColor Yellow
        }
    }
}

# Fetch sign-in logs with report-only results
Write-Host "`nFetching sign-in logs (this may take several minutes)..." -ForegroundColor Cyan

$allSignIns = @()
if ($UseLogAnalytics) {
    $queryWorkspaceId = if ($LogAnalyticsWorkspaceId) { $LogAnalyticsWorkspaceId } else { $WorkspaceId }
    if (-not $queryWorkspaceId) {
        Write-Host "-UseLogAnalytics requires -LogAnalyticsWorkspaceId or a hardcoded \$WorkspaceId. Exiting." -ForegroundColor Red
        return
    }

    if (-not (Get-Command Invoke-AzOperationalInsightsQuery -ErrorAction SilentlyContinue)) {
        Write-Host "Invoke-AzOperationalInsightsQuery is not available. Install/import Az.OperationalInsights and retry." -ForegroundColor Red
        return
    }

    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Write-Host "Connecting to Azure for Log Analytics query..." -ForegroundColor Cyan
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }

    # --- Pre-flight: verify Az connectivity and workspace reachability ---
    Write-Host "  Verifying Azure context and Log Analytics workspace connectivity..." -ForegroundColor Cyan
    try {
        $azCtx = Get-AzContext -ErrorAction Stop
        Write-Host "  Azure context OK: $($azCtx.Account) / Subscription: $($azCtx.Subscription.Name) [$($azCtx.Subscription.Id)]" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Could not retrieve Azure context. Run Connect-AzAccount and retry." -ForegroundColor Red
        return
    }
    try {
            Write-Host "  Checking Log Analytics workspace access..." -ForegroundColor DarkCyan
        $null = Invoke-AzOperationalInsightsQuery -WorkspaceId $queryWorkspaceId -Query "search * | take 1" -ErrorAction Stop
        Write-Host "  Log Analytics workspace '$queryWorkspaceId' is reachable." -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Cannot reach Log Analytics workspace '$queryWorkspaceId'." -ForegroundColor Red
        Write-Host "  Details: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Check that the workspace ID is correct and that '$($azCtx.Account)' has the Reader role on it." -ForegroundColor Yellow
        return
    }
    # --- End pre-flight ---

    # Build policy ID list for KQL in() operator (single-quoted, comma-separated)
    $quotedPolicyIds = @($targetPolicyIds | Where-Object { $_ } | ForEach-Object { "'$_'" })
    if ($quotedPolicyIds.Count -eq 0) {
        $quotedPolicyIds = @("'__NO_POLICY_IDS__'")
    }
    $policyIdList = $quotedPolicyIds -join ", "

    Write-Host "  Preparing Log Analytics query for $($targetPolicyIds.Count) target policy/policies..." -ForegroundColor Cyan
    Write-Host "  Query window: $startDate to $endDate" -ForegroundColor DarkCyan

    # Split long ranges into smaller chunks to avoid Az.OperationalInsights client timeout (100s default).
    $chunkHours = 6
    $windowStart = [datetime]::Parse($startDate)
    $windowEnd = [datetime]::Parse($endDate)
    $laRows = @()

    Write-Host "  Running Log Analytics query in $chunkHours-hour chunks..." -ForegroundColor Cyan
    $chunkStart = $windowStart
    while ($chunkStart -lt $windowEnd) {
        $chunkEnd = $chunkStart.AddHours($chunkHours)
        if ($chunkEnd -gt $windowEnd) { $chunkEnd = $windowEnd }

        $chunkStartText = $chunkStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $chunkEndText = $chunkEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")

        # Use mv-expand to reliably filter on the per-policy result inside the dynamic array.
        # Filter: reportOnlyInterrupted only (Report-only: User action required)
        $kql = @"
SigninLogs
| where TimeGenerated >= datetime($chunkStartText) and TimeGenerated < datetime($chunkEndText)
| where ConditionalAccessPolicies != "[]"
| mv-expand cap = ConditionalAccessPolicies
| where tostring(cap["id"]) in ($policyIdList)
| extend capResult = tostring(cap["result"])
| where capResult == "reportOnlyInterrupted"
| extend matchedPolicyId = tostring(cap["id"]),
         matchedPolicyResult = capResult,
         matchedPolicyDisplayName = tostring(cap["displayName"])
| summarize arg_max(TimeGenerated, *) by CorrelationId
"@

        Write-Host "    Querying chunk: $chunkStartText -> $chunkEndText" -ForegroundColor DarkCyan
        try {
            $laResponse = Invoke-AzOperationalInsightsQuery -WorkspaceId $queryWorkspaceId -Query $kql -ErrorAction Stop
            $chunkRows = @($laResponse.Results)
            $laRows += $chunkRows
            Write-Host "      Returned $($chunkRows.Count) rows (running total: $($laRows.Count))." -ForegroundColor Gray
        } catch {
            Write-Host "  ERROR: Log Analytics chunk query failed for $chunkStartText -> $chunkEndText" -ForegroundColor Red
            Write-Host "  Details: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Try a shorter lookback window while testing." -ForegroundColor Yellow
            return
        }

        $chunkStart = $chunkEnd
    }

    Write-Host "  Query complete. Returned $($laRows.Count) sign-in rows across all chunks." -ForegroundColor Green

    Write-Host "  Converting Log Analytics rows into report objects..." -ForegroundColor Cyan
    foreach ($row in $laRows) {
        $allSignIns += Convert-LogAnalyticsSignIn -Record $row
    }

    # KQL already filtered to reportOnlyInterrupted for target policies,
    # but re-filter in PowerShell to be safe after JSON deserialisation.
    Write-Host "  Applying final in-memory policy/result filter..." -ForegroundColor DarkCyan
    $allSignIns = @(
        $allSignIns | Where-Object {
            $caps = @($_.appliedConditionalAccessPolicies)
            (($_.matchedPolicyResult -eq 'reportOnlyInterrupted') -and ($_.matchedPolicyId -in $targetPolicyIds)) -or
            (@($caps | Where-Object { $_.result -eq 'reportOnlyInterrupted' -and $_.id -in $targetPolicyIds }).Count -gt 0)
        }
    )
    Write-Host "  Fetched $($allSignIns.Count) relevant sign-ins from Log Analytics (user action required)." -ForegroundColor Yellow
}
else {
    $signInSelect = "id,createdDateTime,userPrincipalName,userDisplayName,userId,appliedConditionalAccessPolicies,riskLevelDuringSignIn,userRiskLevel,riskState,riskEventTypes_v2,riskDetail,authenticationMethodsUsed,authenticationRequirement,appDisplayName,appId,resourceDisplayName,deviceDetail,location,ipAddress,clientAppUsed,isInteractive,status,correlationId"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate and createdDateTime le $endDate&`$top=999&`$select=$signInSelect"

    do {
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        $signIns = $response.value

        # Keep only sign-ins where report-only result is "User action required".
        # reportOnlyInterrupted = "Report-only: User action required"
        $relevantSignIns = $signIns | Where-Object {
            $caps = @($_.appliedConditionalAccessPolicies)
            @($caps | Where-Object { $_.result -eq 'reportOnlyInterrupted' -and $_.id -in $targetPolicyIds }).Count -gt 0
        }

        $allSignIns += $relevantSignIns

        Write-Host "  Fetched $($allSignIns.Count) relevant sign-ins..." -ForegroundColor Yellow

        $uri = $response.'@odata.nextLink'
    } while ($uri)
}

Write-Host "Total sign-ins with risk/MFA policy evaluation: $($allSignIns.Count)`n" -ForegroundColor Green

# Build detailed MFA requirement report
Write-Host "Analyzing MFA challenges and risk-based requirements..." -ForegroundColor Cyan

$mfaImpactReport = @(
foreach ($signIn in $allSignIns) {
    # Get only policies with report-only user action required.
    # reportOnlyInterrupted = Report-only: User action required
    $matchedPolicies = @($signIn.appliedConditionalAccessPolicies | Where-Object {
        $_.result -eq 'reportOnlyInterrupted' -and
        $_.id -in $targetPolicyIds
    })

    if ($matchedPolicies.Count -eq 0 -and $signIn.matchedPolicyResult -eq 'reportOnlyInterrupted' -and $signIn.matchedPolicyId -in $targetPolicyIds) {
        $matchedDisplayName = if ($signIn.matchedPolicyDisplayName) {
            $signIn.matchedPolicyDisplayName
        } else {
            ($targetPolicies | Where-Object { $_.Id -eq $signIn.matchedPolicyId } | Select-Object -First 1 -ExpandProperty DisplayName)
        }

        $matchedPolicies = @([PSCustomObject]@{
            id = $signIn.matchedPolicyId
            result = $signIn.matchedPolicyResult
            displayName = $matchedDisplayName
        })
    }

    if ($matchedPolicies.Count -eq 0) { continue }

    foreach ($policy in $matchedPolicies) {
        # Determine outcome label based on report-only result.
        $riskLevel = $signIn.riskLevelDuringSignIn
        $userRiskLevel = $signIn.userRiskLevel
        $riskState = $signIn.riskState
        $mfaRequired = if ($policy.result -eq 'reportOnlyInterrupted') {
            "Yes - User Action Required"
        } else {
            "Yes - Would Block"
        }
        $reason = if ($riskLevel -in @('high', 'medium', 'low')) {
            "Sign-in risk detected: $riskLevel"
        } elseif ($userRiskLevel -in @('high', 'medium', 'low')) {
            "User risk detected: $userRiskLevel"
        } else {
            "Policy requires MFA (grant control not satisfied)"
        }

        # Determine specific risk types
        $riskTypes = if ($signIn.riskEventTypes_v2) {
            ($signIn.riskEventTypes_v2 -join '; ')
        } else { "None" }

        [PSCustomObject]@{
            Timestamp = $signIn.createdDateTime

            # User Details
            UserPrincipalName = $signIn.userPrincipalName
            UserDisplayName = $signIn.userDisplayName
            UserId = $signIn.userId

            # MFA Impact Assessment
            WouldRequireMFA = $mfaRequired
            MFAReason = $reason

            # Risk Details
            SignInRiskLevel = if ($riskLevel) { $riskLevel } else { "none" }
            UserRiskLevel = if ($userRiskLevel) { $userRiskLevel } else { "none" }
            SignInRiskState = if ($riskState) { $riskState } else { "none" }
            RiskDetectionTypes = $riskTypes
            RiskDetail = $signIn.riskDetail

            # Current Authentication
            CurrentAuthMethod = ($signIn.authenticationMethodsUsed -join '; ')
            AuthRequirement = $signIn.authenticationRequirement
            MFAAlreadyUsed = if ($signIn.authenticationRequirement -eq 'multiFactorAuthentication') { 'Yes' } else { 'No' }

            # Policy Details
            PolicyName = $policy.displayName
            PolicyId = $policy.id
            PolicyResult = $policy.result

            # Application Context
            AppDisplayName = $signIn.appDisplayName
            AppId = $signIn.appId
            ResourceDisplayName = $signIn.resourceDisplayName

            # Device Context
            DeviceDisplayName = $signIn.deviceDetail.displayName
            DeviceOS = $signIn.deviceDetail.operatingSystem
            DeviceBrowser = $signIn.deviceDetail.browser
            DeviceTrustType = $signIn.deviceDetail.trustType
            DeviceCompliant = $signIn.deviceDetail.isCompliant
            DeviceManaged = $signIn.deviceDetail.isManaged

            # Location Context
            City = $signIn.location.city
            Country = $signIn.location.countryOrRegion
            State = $signIn.location.state
            IPAddress = $signIn.ipAddress

            # Session Details
            ClientAppUsed = $signIn.clientAppUsed
            IsInteractive = $signIn.isInteractive

            # Sign-in Status
            SignInStatus = $signIn.status.errorCode
            SignInSuccessful = if ($signIn.status.errorCode -eq 0) { 'Yes' } else { 'No' }

            # Identifiers
            CorrelationId = $signIn.correlationId
            SignInId = $signIn.id

            # Scope Check
            IsMemberOfExpectedGroups = if ($expectedUserIds.Count -gt 0 -and $signIn.userId -and $expectedUserIds.Contains($signIn.userId)) { 'Yes' } else { 'No' }
        }
    }
}
)

# Keep only unexpected impact users (exclude users already targeted by prod policy groups)
if ($expectedUserIds.Count -gt 0) {
    $preFilterCount = $mfaImpactReport.Count
    $mfaImpactReport = @(
        $mfaImpactReport | Where-Object {
            -not ($_.UserId -and $expectedUserIds.Contains($_.UserId))
        }
    )
    $postFilterCount = $mfaImpactReport.Count
    Write-Host "`nExcluded $($preFilterCount - $postFilterCount) rows for users already covered by prod policy target groups." -ForegroundColor Green
} else {
    Write-Host "`nExpected-user exclusion not applied; continuing with all impacted users." -ForegroundColor Yellow
}

# Export detailed report
$mfaImpactReport | Export-Csv -Path "CA_SignInRisk_MFA_Impact_Detail.csv" -NoTypeInformation
Write-Host "Report exported to: CA_SignInRisk_MFA_Impact_Detail.csv" -ForegroundColor Green
