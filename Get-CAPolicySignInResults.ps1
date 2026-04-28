<#
.SYNOPSIS
Reports Microsoft Entra ID Conditional Access successes and failures for one policy.

.DESCRIPTION
Queries Microsoft Graph sign-in logs for a specific Conditional Access policy over a
lookback window supplied with -Hours or -Days. The script resolves the policy by
display name or object ID, filters sign-ins where that policy was evaluated, and
exports detail and summary CSV files.

.PARAMETER Policy
Conditional Access policy display name or policy object ID.

.PARAMETER Hours
Number of hours to look back. Use either -Hours or -Days, not both.

.PARAMETER Days
Number of days to look back. Use either -Hours or -Days, not both.

.PARAMETER OutputPath
Folder to write CSV output to. Defaults to the current directory.

.PARAMETER Export
Export detail and summary CSV files. Without this switch, results are displayed only.

.PARAMETER IncludeOtherResults
Include policy results outside success/failure, such as notApplied, reportOnlyNotApplied,
notEnabled, unknown, or reportOnlyInterrupted.

.EXAMPLE
.\Get-CAPolicySignInResults.ps1 -Policy "Require MFA for admins" -Hours 12

.EXAMPLE
.\Get-CAPolicySignInResults.ps1 -Policy "00000000-0000-0000-0000-000000000000" -Days 7 -IncludeOtherResults -Export

.NOTES
Required Microsoft Graph scopes:
- AuditLog.Read.All
- Policy.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Policy,

    [ValidateRange(1, 2160)]
    [int]$Hours,

    [ValidateRange(1, 90)]
    [int]$Days,

    [string]$OutputPath = ".",

    [switch]$Export,

    [switch]$IncludeOtherResults
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-GuidString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $parsedGuid = [Guid]::Empty
    return [Guid]::TryParse($Value, [ref]$parsedGuid)
}

function Test-GraphConnectivity {
    try {
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1&`$select=id" | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Connect-GraphIfNeeded {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph PowerShell SDK is not installed. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $context = $null
    try {
        $context = Get-MgContext -ErrorAction Stop
    }
    catch {
        $context = $null
    }

    if ($context -and (Test-GraphConnectivity)) {
        $account = if ($context.Account) { $context.Account } else { $context.ClientId }
        Write-Host "Using existing Microsoft Graph session: $account / Tenant: $($context.TenantId)" -ForegroundColor DarkGray
        return
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Policy.Read.All" -NoWelcome
}

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $items = @()
    $nextUri = $Uri

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        $items += @(Get-ObjectValue -InputObject $response -PropertyName "value")

        $nextUri = Get-ObjectValue -InputObject $response -PropertyName "@odata.nextLink"
    } while ($nextUri)

    return $items
}

function Resolve-ConditionalAccessPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyValue
    )

    $select = "id,displayName,state"
    $policies = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=$select"

    if (Test-GuidString -Value $PolicyValue) {
        $match = @($policies | Where-Object { (Get-ObjectValue -InputObject $_ -PropertyName "id") -eq $PolicyValue })
        if ($match.Count -eq 1) {
            return $match[0]
        }
    }

    $exactMatches = @($policies | Where-Object { (Get-ObjectValue -InputObject $_ -PropertyName "displayName") -eq $PolicyValue })
    if ($exactMatches.Count -eq 1) {
        return $exactMatches[0]
    }

    if ($exactMatches.Count -gt 1) {
        throw "Multiple Conditional Access policies have the display name '$PolicyValue'. Re-run with the policy ID."
    }

    $partialMatches = @($policies | Where-Object { (Get-ObjectValue -InputObject $_ -PropertyName "displayName") -like "*$PolicyValue*" })
    if ($partialMatches.Count -eq 1) {
        return $partialMatches[0]
    }

    if ($partialMatches.Count -gt 1) {
        $names = ($partialMatches |
            Sort-Object { Get-ObjectValue -InputObject $_ -PropertyName "displayName" } |
            ForEach-Object {
                "$(Get-ObjectValue -InputObject $_ -PropertyName "displayName") ($(Get-ObjectValue -InputObject $_ -PropertyName "id"))"
            }) -join "`n  - "
        throw "Multiple policies matched '$PolicyValue'. Re-run with the exact display name or policy ID:`n  - $names"
    }

    throw "No Conditional Access policy found matching '$PolicyValue'."
}

function Get-CAPolicyResultBucket {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Result
    )

    switch ($Result) {
        "success" { return "Success" }
        "reportOnlySuccess" { return "Success" }
        "failure" { return "Failure" }
        "reportOnlyFailure" { return "Failure" }
        default { return "Other" }
    }
}

function ConvertTo-FlatText {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    if ($Value -is [array]) {
        return (@($Value | Where-Object { $null -ne $_ }) -join "; ")
    }

    return [string]$Value
}

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

function Get-ObjectValue {
    param(
        [Parameter(Mandatory = $false)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

if ($Hours -and $Days) {
    throw "Use either -Hours or -Days, not both."
}

if (-not $Hours -and -not $Days) {
    $Hours = 24
}

$lookback = if ($Hours) {
    [TimeSpan]::FromHours($Hours)
} else {
    [TimeSpan]::FromDays($Days)
}

$endDate = (Get-Date).ToUniversalTime()
$startDate = $endDate.Subtract($lookback)
$startFilter = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
$endFilter = $endDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

Connect-GraphIfNeeded

$resolvedPolicy = Resolve-ConditionalAccessPolicy -PolicyValue $Policy
$resolvedPolicyName = Get-ObjectValue -InputObject $resolvedPolicy -PropertyName "displayName"
$resolvedPolicyId = Get-ObjectValue -InputObject $resolvedPolicy -PropertyName "id"
$resolvedPolicyState = Get-ObjectValue -InputObject $resolvedPolicy -PropertyName "state"
Write-Host "Policy: $resolvedPolicyName ($resolvedPolicyId) / State: $resolvedPolicyState" -ForegroundColor Green
Write-Host "Timeframe: $startFilter to $endFilter UTC" -ForegroundColor Green

$signInSelect = @(
    "id",
    "createdDateTime",
    "userPrincipalName",
    "userDisplayName",
    "userId",
    "appDisplayName",
    "appId",
    "resourceDisplayName",
    "ipAddress",
    "clientAppUsed",
    "correlationId",
    "conditionalAccessStatus",
    "appliedConditionalAccessPolicies",
    "isInteractive",
    "status",
    "deviceDetail",
    "location"
) -join ","

$filter = "createdDateTime ge $startFilter and createdDateTime le $endFilter"
$encodedFilter = [uri]::EscapeDataString($filter)
$uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$encodedFilter&`$top=999&`$select=$signInSelect"

Write-Host "Fetching sign-in logs..." -ForegroundColor Cyan
$signIns = Invoke-GraphGetAll -Uri $uri
Write-Host "Fetched $($signIns.Count) sign-ins in the requested window." -ForegroundColor DarkGray

$detail = @(
    foreach ($signIn in $signIns) {
        $matchedPolicies = @(Get-ObjectValue -InputObject $signIn -PropertyName "appliedConditionalAccessPolicies" | Where-Object {
            (Get-ObjectValue -InputObject $_ -PropertyName "id") -eq $resolvedPolicyId
        })
        if ($matchedPolicies.Count -eq 0) {
            continue
        }

        foreach ($matchedPolicy in $matchedPolicies) {
            $policyResult = Get-ObjectValue -InputObject $matchedPolicy -PropertyName "result"
            $bucket = Get-CAPolicyResultBucket -Result $policyResult
            if (-not $IncludeOtherResults -and $bucket -eq "Other") {
                continue
            }

            $status = Get-ObjectValue -InputObject $signIn -PropertyName "status"
            $device = Get-ObjectValue -InputObject $signIn -PropertyName "deviceDetail"
            $location = Get-ObjectValue -InputObject $signIn -PropertyName "location"

            [PSCustomObject]@{
                TimestampUtc = Get-ObjectValue -InputObject $signIn -PropertyName "createdDateTime"
                UserPrincipalName = Get-ObjectValue -InputObject $signIn -PropertyName "userPrincipalName"
                UserDisplayName = Get-ObjectValue -InputObject $signIn -PropertyName "userDisplayName"
                UserId = Get-ObjectValue -InputObject $signIn -PropertyName "userId"
                ResultType = $bucket
                PolicyResult = $policyResult
                ConditionalAccessStatus = Get-ObjectValue -InputObject $signIn -PropertyName "conditionalAccessStatus"
                SignInErrorCode = Get-ObjectValue -InputObject $status -PropertyName "errorCode"
                FailureReason = Get-ObjectValue -InputObject $status -PropertyName "failureReason"
                AdditionalDetails = Get-ObjectValue -InputObject $status -PropertyName "additionalDetails"
                AppDisplayName = Get-ObjectValue -InputObject $signIn -PropertyName "appDisplayName"
                AppId = Get-ObjectValue -InputObject $signIn -PropertyName "appId"
                ResourceDisplayName = Get-ObjectValue -InputObject $signIn -PropertyName "resourceDisplayName"
                ClientAppUsed = Get-ObjectValue -InputObject $signIn -PropertyName "clientAppUsed"
                IsInteractive = Get-ObjectValue -InputObject $signIn -PropertyName "isInteractive"
                IpAddress = Get-ObjectValue -InputObject $signIn -PropertyName "ipAddress"
                City = Get-ObjectValue -InputObject $location -PropertyName "city"
                State = Get-ObjectValue -InputObject $location -PropertyName "state"
                CountryOrRegion = Get-ObjectValue -InputObject $location -PropertyName "countryOrRegion"
                DeviceDisplayName = Get-ObjectValue -InputObject $device -PropertyName "displayName"
                DeviceOperatingSystem = Get-ObjectValue -InputObject $device -PropertyName "operatingSystem"
                DeviceBrowser = Get-ObjectValue -InputObject $device -PropertyName "browser"
                DeviceTrustType = Get-ObjectValue -InputObject $device -PropertyName "trustType"
                AuthRequirement = Get-ObjectValue -InputObject $signIn -PropertyName "authenticationRequirement"
                AuthMethodsUsed = ConvertTo-FlatText -Value (Get-ObjectValue -InputObject $signIn -PropertyName "authenticationMethodsUsed")
                SignInRiskLevel = Get-ObjectValue -InputObject $signIn -PropertyName "riskLevelDuringSignIn"
                UserRiskLevel = Get-ObjectValue -InputObject $signIn -PropertyName "userRiskLevel"
                RiskState = Get-ObjectValue -InputObject $signIn -PropertyName "riskState"
                CorrelationId = Get-ObjectValue -InputObject $signIn -PropertyName "correlationId"
                SignInId = Get-ObjectValue -InputObject $signIn -PropertyName "id"
                PolicyName = $resolvedPolicyName
                PolicyId = $resolvedPolicyId
            }
        }
    }
)

$summary = @(
    $detail |
        Group-Object ResultType, PolicyResult |
        Sort-Object Count -Descending |
        ForEach-Object {
            $firstRow = @($_.Group)[0]
            [PSCustomObject]@{
                ResultType = $firstRow.ResultType
                PolicyResult = $firstRow.PolicyResult
                Count = $_.Count
            }
        }
)

$userSummary = @(
    $detail |
        Group-Object UserPrincipalName |
        Sort-Object Count -Descending |
        ForEach-Object {
            $rows = @($_.Group)
            [PSCustomObject]@{
                UserPrincipalName = $_.Name
                Total = $_.Count
                Successes = @($rows | Where-Object { $_.ResultType -eq "Success" }).Count
                Failures = @($rows | Where-Object { $_.ResultType -eq "Failure" }).Count
                Other = @($rows | Where-Object { $_.ResultType -eq "Other" }).Count
                LastSeenUtc = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).TimestampUtc
            }
        }
)

$appSummary = @(
    $detail |
        Group-Object AppDisplayName |
        Sort-Object Count -Descending |
        ForEach-Object {
            $rows = @($_.Group)
            [PSCustomObject]@{
                AppDisplayName = if ([string]::IsNullOrWhiteSpace($_.Name)) { "(unknown)" } else { $_.Name }
                Total = $_.Count
                Successes = @($rows | Where-Object { $_.ResultType -eq "Success" }).Count
                Failures = @($rows | Where-Object { $_.ResultType -eq "Failure" }).Count
                Other = @($rows | Where-Object { $_.ResultType -eq "Other" }).Count
                UniqueUsers = @($rows | Where-Object { $_.UserPrincipalName } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
                LastSeenUtc = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).TimestampUtc
            }
        }
)

$failureReasonSummary = @(
    $detail |
        Where-Object { $_.ResultType -eq "Failure" } |
        Group-Object FailureReason |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                FailureReason = if ([string]::IsNullOrWhiteSpace($_.Name)) { "(not provided)" } else { $_.Name }
                Count = $_.Count
            }
        }
)

$failingSignIns = @(
    $detail |
        Where-Object { $_.ResultType -eq "Failure" } |
        Sort-Object TimestampUtc -Descending
)

$failingUserSummary = @(
    $failingSignIns |
        Group-Object UserPrincipalName |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            $rows = @($_.Group)
            [PSCustomObject]@{
                UserPrincipalName = if ([string]::IsNullOrWhiteSpace($_.Name)) { "(unknown)" } else { $_.Name }
                Failures = $_.Count
                Apps = (@($rows | Where-Object { $_.AppDisplayName } | Select-Object -ExpandProperty AppDisplayName -Unique) -join "; ")
                LastFailureUtc = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).TimestampUtc
                LastFailureReason = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).FailureReason
                LastCorrelationId = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).CorrelationId
            }
        }
)

$failingAppSummary = @(
    $failingSignIns |
        Group-Object AppDisplayName |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            $rows = @($_.Group)
            [PSCustomObject]@{
                AppDisplayName = if ([string]::IsNullOrWhiteSpace($_.Name)) { "(unknown)" } else { $_.Name }
                Failures = $_.Count
                UniqueUsers = @($rows | Where-Object { $_.UserPrincipalName } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
                LastFailureUtc = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).TimestampUtc
                LastFailureReason = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).FailureReason
                LastCorrelationId = ($rows | Sort-Object TimestampUtc -Descending | Select-Object -First 1).CorrelationId
            }
        }
)

$recentFailures = @(
    $failingSignIns |
        Select-Object -First 15 TimestampUtc, UserPrincipalName, AppDisplayName, ClientAppUsed, IpAddress, FailureReason, SignInErrorCode, CorrelationId
)

Write-Host ""
Write-Host "Conditional Access post-change monitor" -ForegroundColor Cyan
if ($summary.Count -gt 0) {
    $totalEvaluations = $detail.Count
    $successCount = @($detail | Where-Object { $_.ResultType -eq "Success" }).Count
    $failureCount = @($detail | Where-Object { $_.ResultType -eq "Failure" }).Count
    $otherCount = @($detail | Where-Object { $_.ResultType -eq "Other" }).Count
    $uniqueUsers = @($detail | Where-Object { $_.UserPrincipalName } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $uniqueApps = @($detail | Where-Object { $_.AppDisplayName } | Select-Object -ExpandProperty AppDisplayName -Unique).Count
    $orderedDetail = @($detail | Sort-Object TimestampUtc)

    [PSCustomObject]@{
        TotalEvaluations = $totalEvaluations
        Successes = $successCount
        Failures = $failureCount
        Other = $otherCount
        SuccessRate = "$(Get-SafePercentage -Numerator $successCount -Denominator $totalEvaluations)%"
        FailureRate = "$(Get-SafePercentage -Numerator $failureCount -Denominator $totalEvaluations)%"
        UniqueUsers = $uniqueUsers
        UniqueApps = $uniqueApps
        FirstSeenUtc = $orderedDetail[0].TimestampUtc
        LastSeenUtc = $orderedDetail[-1].TimestampUtc
    } | Format-List

    if ($failureCount -gt 0) {
        Write-Host "Action focus: failing authentications detected" -ForegroundColor Yellow
        [PSCustomObject]@{
            FailingUsers = @($failingSignIns | Where-Object { $_.UserPrincipalName } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
            FailingApps = @($failingSignIns | Where-Object { $_.AppDisplayName } | Select-Object -ExpandProperty AppDisplayName -Unique).Count
            MostRecentFailureUtc = $failingSignIns[0].TimestampUtc
            MostRecentFailureUser = $failingSignIns[0].UserPrincipalName
            MostRecentFailureApp = $failingSignIns[0].AppDisplayName
            MostRecentFailureReason = $failingSignIns[0].FailureReason
            MostRecentCorrelationId = $failingSignIns[0].CorrelationId
        } | Format-List
    } else {
        Write-Host "No failing authentications found for this policy in the selected window." -ForegroundColor Green
    }

    Write-Host "By policy result" -ForegroundColor Cyan
    $summary | Format-Table -AutoSize

    if ($failingUserSummary.Count -gt 0) {
        Write-Host "Users with failures" -ForegroundColor Yellow
        $failingUserSummary | Format-Table -AutoSize
    }

    if ($failingAppSummary.Count -gt 0) {
        Write-Host "Apps with failures" -ForegroundColor Yellow
        $failingAppSummary | Format-Table -AutoSize
    }

    if ($recentFailures.Count -gt 0) {
        Write-Host "Recent failures" -ForegroundColor Yellow
        $recentFailures | Format-Table -AutoSize
    }

    if ($userSummary.Count -gt 0) {
        Write-Host "Top users by total evaluations" -ForegroundColor Cyan
        $userSummary | Select-Object -First 10 | Format-Table -AutoSize
    }

    if ($appSummary.Count -gt 0) {
        Write-Host "Top apps by total evaluations" -ForegroundColor Cyan
        $appSummary | Select-Object -First 10 | Format-Table -AutoSize
    }

    if ($failureReasonSummary.Count -gt 0) {
        Write-Host "Top failure reasons" -ForegroundColor Cyan
        $failureReasonSummary | Format-Table -AutoSize
    }
} else {
    Write-Host "No matching success/failure policy evaluations found." -ForegroundColor Yellow
    if (-not $IncludeOtherResults) {
        Write-Host "Tip: re-run with -IncludeOtherResults to include notApplied/report-only interrupted outcomes." -ForegroundColor Yellow
    }
}

if (-not $Export) {
    Write-Host ""
    Write-Host "CSV export skipped. Re-run with -Export to write files." -ForegroundColor DarkGray
    return
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$safePolicyName = ($resolvedPolicyName -replace '[\\/:*?"<>|]', '_').Trim()
if ([string]::IsNullOrWhiteSpace($safePolicyName)) {
    $safePolicyName = $resolvedPolicyId
}

$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$detailPath = Join-Path $OutputPath "CA_Policy_Results_${safePolicyName}_${timestamp}_Detail.csv"
$summaryPath = Join-Path $OutputPath "CA_Policy_Results_${safePolicyName}_${timestamp}_Summary.csv"
$userSummaryPath = Join-Path $OutputPath "CA_Policy_Results_${safePolicyName}_${timestamp}_UserSummary.csv"
$appSummaryPath = Join-Path $OutputPath "CA_Policy_Results_${safePolicyName}_${timestamp}_AppSummary.csv"

$detail | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
$summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$userSummary | Export-Csv -Path $userSummaryPath -NoTypeInformation -Encoding UTF8
$appSummary | Export-Csv -Path $appSummaryPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Wrote:" -ForegroundColor Green
Write-Host "  $detailPath"
Write-Host "  $summaryPath"
Write-Host "  $userSummaryPath"
Write-Host "  $appSummaryPath"
