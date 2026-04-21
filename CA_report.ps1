<#
.SYNOPSIS
Analyzes report-only Conditional Access sign-in risk and MFA challenge impact.

.DESCRIPTION
Connects to Microsoft Graph, reads report-only Conditional Access policies, correlates
them with recent sign-in activity, and exports detailed CSV reports that show where MFA
would have been required if those policies were enforced.

.EXAMPLE
PS> .\CA_report.ps1
Prompts you to choose a target report-only policy (or all), runs the analysis for the
last 30 days, and exports CSV reports to the current directory.

.EXAMPLE
PS> pwsh -ExecutionPolicy Bypass -File .\CA_report.ps1
Runs the same analysis from a PowerShell host where script execution policy is restricted.

.EXAMPLE
PS> .\CA_report.ps1 -TargetPolicy "Require MFA for risky sign-ins"
Runs analysis for the specified report-only policy name (or policy ID) without interactive
selection.

.NOTES
Required Microsoft Graph scopes: AuditLog.Read.All, Policy.Read.All
#>

param(
    [string]$TargetPolicy,
    [switch]$AllPolicies
)

# Connect with required permissions
Connect-MgGraph -Scopes "AuditLog.Read.All", "Policy.Read.All"

# Define time range for analysis (adjust as needed)
$startDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
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

Write-Host "=== SIGN-IN RISK & MFA REQUIREMENT ANALYSIS ===" -ForegroundColor Cyan
Write-Host "Analyzing report-only CA policies for sign-in risk and MFA impact..." -ForegroundColor Yellow
Write-Host "Date range: $((Get-Date).AddDays(-30).ToString('yyyy-MM-dd')) to $((Get-Date).ToString('yyyy-MM-dd'))`n" -ForegroundColor Yellow

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

# Identify risk-based policies
$riskPolicies = $reportOnlyPolicies | Where-Object {
    $_.Conditions.SignInRiskLevels.Count -gt 0 -or
    $_.GrantControls.BuiltInControls -contains 'mfa'
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
    Write-Host "    Grant controls: $(($_.GrantControls.BuiltInControls -join ', '))" -ForegroundColor Gray
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

# Fetch sign-in logs with report-only results
Write-Host "`nFetching sign-in logs (this may take several minutes)..." -ForegroundColor Cyan

$allSignIns = @()
$uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate and createdDateTime le $endDate&`$top=999"

do {
    $response = Invoke-MgGraphRequest -Uri $uri -Method GET
    $signIns = $response.value

    # Filter for sign-ins with report-only policy results AND risk or MFA relevance
    $relevantSignIns = $signIns | Where-Object {
        ($_.appliedConditionalAccessPolicies | Where-Object {
            $_.result -in @('reportOnlySuccess', 'reportOnlyFailure') -and
            $_.id -in $targetPolicyIds
        }) -or
        $_.riskLevelDuringSignIn -in @('low', 'medium', 'high')
    }

    $allSignIns += $relevantSignIns

    Write-Host "  Fetched $($allSignIns.Count) relevant sign-ins..." -ForegroundColor Yellow

    $uri = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Total sign-ins with risk/MFA policy evaluation: $($allSignIns.Count)`n" -ForegroundColor Green

# Build detailed MFA requirement report
Write-Host "Analyzing MFA challenges and risk-based requirements..." -ForegroundColor Cyan

$mfaImpactReport = foreach ($signIn in $allSignIns) {
    # Get report-only policy evaluations
    $matchedPolicies = $signIn.appliedConditionalAccessPolicies | Where-Object {
        $_.result -in @('reportOnlySuccess', 'reportOnlyFailure') -and
        $_.id -in $targetPolicyIds
    }

    # If no policies matched, but there was risk, create a synthetic entry
    if (-not $matchedPolicies -and $signIn.riskLevelDuringSignIn -in @('low', 'medium', 'high')) {
        $matchedPolicies = @([PSCustomObject]@{
            displayName = "No policy (risk detected)"
            id = "N/A"
            result = "riskDetectedNoPolicy"
        })
    }

    foreach ($policy in $matchedPolicies) {
        # Determine MFA requirement status
        $mfaRequired = "No"
        $reason = ""
        $riskLevel = $signIn.riskLevelDuringSignIn
        $riskState = $signIn.riskState

        if ($policy.result -eq 'reportOnlyFailure') {
            $mfaRequired = "Yes - Would Challenge"

            # Determine the reason for MFA requirement
            if ($riskLevel -in @('high', 'medium', 'low')) {
                $reason = "Sign-in risk detected: $riskLevel"
            } else {
                $reason = "Policy requires MFA"
            }
        }
        elseif ($policy.result -eq 'reportOnlySuccess') {
            # Check if MFA was already satisfied
            if ($signIn.authenticationRequirement -eq 'multiFactorAuthentication') {
                $mfaRequired = "No - Already Completed MFA"
                $reason = "User already performed MFA for this session"
            }
            elseif ($riskLevel -eq 'none' -or $riskLevel -eq $null) {
                $mfaRequired = "No - No Risk Detected"
                $reason = "Sign-in risk is none"
            }
            else {
                $mfaRequired = "No - Risk Accepted"
                $reason = "Risk level $riskLevel but policy passed"
            }
        }
        elseif ($policy.result -eq 'riskDetectedNoPolicy') {
            $mfaRequired = "Risk Present - No Policy"
            $reason = "Risk detected but no report-only policy evaluated"
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
        }
    }
}

# Export detailed report
$mfaImpactReport | Export-Csv -Path "CA_SignInRisk_MFA_Impact_Detail.csv" -NoTypeInformation
Write-Host "Detailed MFA impact report exported to: CA_SignInRisk_MFA_Impact_Detail.csv" -ForegroundColor Green

# === EXECUTIVE SUMMARY: MFA CHALLENGE VOLUME ===
Write-Host "`n=== EXECUTIVE SUMMARY: MFA CHALLENGE IMPACT ===" -ForegroundColor Magenta

$mfaChallenges = $mfaImpactReport | Where-Object { $_.WouldRequireMFA -eq 'Yes - Would Challenge' }
$totalSignIns = $mfaImpactReport.Count
$uniqueUsersChallenged = ($mfaChallenges | Select-Object -Unique UserPrincipalName).Count
$totalUsers = ($mfaImpactReport | Select-Object -Unique UserPrincipalName).Count

Write-Host "`nTenant-Wide Impact:" -ForegroundColor Yellow
Write-Host "  Total sign-ins analyzed: $totalSignIns" -ForegroundColor White
Write-Host "  Sign-ins that would trigger MFA: $($mfaChallenges.Count) ($(Get-SafePercentage -Numerator $mfaChallenges.Count -Denominator $totalSignIns)%)" -ForegroundColor White
Write-Host "  Unique users who would be challenged: $uniqueUsersChallenged of $totalUsers ($(Get-SafePercentage -Numerator $uniqueUsersChallenged -Denominator $totalUsers)%)" -ForegroundColor White

# MFA Challenge breakdown by risk level
$riskLevelBreakdown = $mfaChallenges | Group-Object SignInRiskLevel | ForEach-Object {
    [PSCustomObject]@{
        RiskLevel = $_.Name
        Challenges = $_.Count
        Percentage = Get-SafePercentage -Numerator $_.Count -Denominator $mfaChallenges.Count
        UniqueUsers = ($_.Group | Select-Object -Unique UserPrincipalName).Count
    }
} | Sort-Object @{Expression={
    switch($_.RiskLevel) {
        'high' {3}
        'medium' {2}
        'low' {1}
        default {0}
    }
}} -Descending

Write-Host "`nMFA Challenges by Risk Level:" -ForegroundColor Yellow
$riskLevelBreakdown | Format-Table RiskLevel, Challenges, Percentage, UniqueUsers -AutoSize

# Export risk level summary
$riskLevelBreakdown | Export-Csv -Path "CA_SignInRisk_MFA_By_RiskLevel.csv" -NoTypeInformation

# === USER IMPACT ANALYSIS ===
Write-Host "`nGenerating user impact analysis..." -ForegroundColor Cyan

$userImpact = $mfaImpactReport | Group-Object UserPrincipalName | ForEach-Object {
    $userSignIns = $_.Group
    $userChallenges = $userSignIns | Where-Object { $_.WouldRequireMFA -eq 'Yes - Would Challenge' }

    if ($userChallenges.Count -gt 0) {
        # Get risk breakdown for this user
        $highRisk = ($userChallenges | Where-Object { $_.SignInRiskLevel -eq 'high' }).Count
        $mediumRisk = ($userChallenges | Where-Object { $_.SignInRiskLevel -eq 'medium' }).Count
        $lowRisk = ($userChallenges | Where-Object { $_.SignInRiskLevel -eq 'low' }).Count

        # Get most common risk types
        $commonRiskTypes = $userChallenges | Where-Object { $_.RiskDetectionTypes -ne 'None' } |
            ForEach-Object { $_.RiskDetectionTypes -split '; ' } |
            Group-Object | Sort-Object Count -Descending | Select-Object -First 3 -ExpandProperty Name

        [PSCustomObject]@{
            UserPrincipalName = $_.Name
            UserDisplayName = ($userSignIns | Select-Object -First 1).UserDisplayName

            TotalSignIns = $userSignIns.Count
            MFAChallenges = $userChallenges.Count
            ChallengeRate = [math]::Round(($userChallenges.Count / $userSignIns.Count) * 100, 2)

            HighRiskSignIns = $highRisk
            MediumRiskSignIns = $mediumRisk
            LowRiskSignIns = $lowRisk

            MostCommonRiskTypes = ($commonRiskTypes -join '; ')

            UniqueAppsAffected = ($userChallenges | Select-Object -Unique AppDisplayName).Count
            TopApps = (($userChallenges | Group-Object AppDisplayName |
                Sort-Object Count -Descending | Select-Object -First 3).Name -join '; ')

            UniqueLocations = ($userChallenges | Select-Object -Unique Country).Count
            Countries = (($userChallenges | Select-Object -Unique Country).Country -join '; ')

            AlreadyUsesMFA = if ($userSignIns | Where-Object { $_.MFAAlreadyUsed -eq 'Yes' }) { 'Yes' } else { 'No' }
            MFAUsageRate = [math]::Round((($userSignIns | Where-Object { $_.MFAAlreadyUsed -eq 'Yes' }).Count / $userSignIns.Count) * 100, 2)

            FirstChallenge = ($userChallenges | Sort-Object Timestamp | Select-Object -First 1).Timestamp
            LastChallenge = ($userChallenges | Sort-Object Timestamp | Select-Object -Last 1).Timestamp
        }
    }
} | Where-Object { $_ } | Sort-Object MFAChallenges -Descending

$userImpact | Export-Csv -Path "CA_SignInRisk_MFA_User_Impact.csv" -NoTypeInformation
Write-Host "User impact analysis exported to: CA_SignInRisk_MFA_User_Impact.csv" -ForegroundColor Green

Write-Host "`n=== TOP 20 USERS WHO WOULD BE CHALLENGED ===" -ForegroundColor Magenta
$userImpact | Select-Object -First 20 |
    Format-Table UserPrincipalName, TotalSignIns, MFAChallenges, ChallengeRate,
    HighRiskSignIns, MediumRiskSignIns, AlreadyUsesMFA -AutoSize

# === RISK TYPE ANALYSIS ===
Write-Host "`nAnalyzing risk detection types..." -ForegroundColor Cyan

$riskTypeAnalysis = $mfaChallenges | Where-Object { $_.RiskDetectionTypes -ne 'None' } |
    ForEach-Object {
        $signIn = $_
        $_.RiskDetectionTypes -split '; ' | ForEach-Object {
            [PSCustomObject]@{
                RiskType = $_
                UserPrincipalName = $signIn.UserPrincipalName
                RiskLevel = $signIn.SignInRiskLevel
                Country = $signIn.Country
                Timestamp = $signIn.Timestamp
            }
        }
    } | Group-Object RiskType | ForEach-Object {
    [PSCustomObject]@{
        RiskDetectionType = $_.Name
        Occurrences = $_.Count
        UniqueUsers = ($_.Group | Select-Object -Unique UserPrincipalName).Count
        HighRiskCount = ($_.Group | Where-Object { $_.RiskLevel -eq 'high' }).Count
        MediumRiskCount = ($_.Group | Where-Object { $_.RiskLevel -eq 'medium' }).Count
        LowRiskCount = ($_.Group | Where-Object { $_.RiskLevel -eq 'low' }).Count
        TopCountries = (($_.Group | Group-Object Country | Sort-Object Count -Descending |
            Select-Object -First 3).Name -join '; ')
    }
} | Sort-Object Occurrences -Descending

$riskTypeAnalysis | Export-Csv -Path "CA_SignInRisk_MFA_RiskTypes.csv" -NoTypeInformation
Write-Host "Risk type analysis exported to: CA_SignInRisk_MFA_RiskTypes.csv" -ForegroundColor Green

Write-Host "`n=== RISK DETECTION TYPES ===" -ForegroundColor Magenta
$riskTypeAnalysis | Format-Table RiskDetectionType, Occurrences, UniqueUsers, HighRiskCount, MediumRiskCount -AutoSize

# === POLICY-SPECIFIC IMPACT ===
Write-Host "`nAnalyzing impact by policy..." -ForegroundColor Cyan

$policyImpact = $mfaImpactReport | Where-Object { $_.PolicyId -ne 'N/A' } |
    Group-Object PolicyName | ForEach-Object {
    $policySignIns = $_.Group
    $challenges = $policySignIns | Where-Object { $_.WouldRequireMFA -eq 'Yes - Would Challenge' }

    [PSCustomObject]@{
        PolicyName = $_.Name
        PolicyId = ($policySignIns | Select-Object -First 1).PolicyId

        TotalEvaluations = $policySignIns.Count
        WouldChallenge = $challenges.Count
        ChallengeRate = [math]::Round(($challenges.Count / $policySignIns.Count) * 100, 2)

        UniqueUsersImpacted = ($challenges | Select-Object -Unique UserPrincipalName).Count

        HighRisk = ($challenges | Where-Object { $_.SignInRiskLevel -eq 'high' }).Count
        MediumRisk = ($challenges | Where-Object { $_.SignInRiskLevel -eq 'medium' }).Count
        LowRisk = ($challenges | Where-Object { $_.SignInRiskLevel -eq 'low' }).Count

        TopRiskTypes = ((($challenges | ForEach-Object { $_.RiskDetectionTypes -split '; ' } |
            Where-Object { $_ -ne 'None' } | Group-Object | Sort-Object Count -Descending |
            Select-Object -First 3).Name) -join '; ')
    }
} | Sort-Object WouldChallenge -Descending

$policyImpact | Export-Csv -Path "CA_SignInRisk_MFA_Policy_Impact.csv" -NoTypeInformation
Write-Host "Policy impact analysis exported to: CA_SignInRisk_MFA_Policy_Impact.csv" -ForegroundColor Green

Write-Host "`n=== POLICY IMPACT SUMMARY ===" -ForegroundColor Magenta
$policyImpact | Format-Table PolicyName, TotalEvaluations, WouldChallenge, ChallengeRate, UniqueUsersImpacted -AutoSize

# === APPLICATION IMPACT ===
Write-Host "`nAnalyzing application impact..." -ForegroundColor Cyan

$appImpact = $mfaChallenges | Group-Object AppDisplayName | ForEach-Object {
    [PSCustomObject]@{
        ApplicationName = $_.Name
        MFAChallenges = $_.Count
        UniqueUsers = ($_.Group | Select-Object -Unique UserPrincipalName).Count
        HighRiskEvents = ($_.Group | Where-Object { $_.SignInRiskLevel -eq 'high' }).Count
        MediumRiskEvents = ($_.Group | Where-Object { $_.SignInRiskLevel -eq 'medium' }).Count
    }
} | Sort-Object MFAChallenges -Descending

$appImpact | Export-Csv -Path "CA_SignInRisk_MFA_App_Impact.csv" -NoTypeInformation
Write-Host "Application impact analysis exported to: CA_SignInRisk_MFA_App_Impact.csv" -ForegroundColor Green

Write-Host "`n=== TOP 10 APPLICATIONS AFFECTED ===" -ForegroundColor Magenta
$appImpact | Select-Object -First 10 | Format-Table ApplicationName, MFAChallenges, UniqueUsers, HighRiskEvents -AutoSize

# === FINAL SUMMARY ===
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nFiles Generated:" -ForegroundColor Cyan
Write-Host "  1. CA_SignInRisk_MFA_Impact_Detail.csv - Every sign-in with MFA requirement status" -ForegroundColor White
Write-Host "  2. CA_SignInRisk_MFA_By_RiskLevel.csv - MFA challenges broken down by risk level" -ForegroundColor White
Write-Host "  3. CA_SignInRisk_MFA_User_Impact.csv - Per-user impact showing challenge frequency" -ForegroundColor White
Write-Host "  4. CA_SignInRisk_MFA_RiskTypes.csv - Risk detection types triggering MFA" -ForegroundColor White
Write-Host "  5. CA_SignInRisk_MFA_Policy_Impact.csv - Impact by individual CA policy" -ForegroundColor White
Write-Host "  6. CA_SignInRisk_MFA_App_Impact.csv - Applications most affected by MFA challenges" -ForegroundColor White

Write-Host "`nKey Metrics:" -ForegroundColor Cyan
Write-Host "  • MFA Challenge Rate: $(Get-SafePercentage -Numerator $mfaChallenges.Count -Denominator $totalSignIns)% of sign-ins" -ForegroundColor White
Write-Host "  • User Impact: $uniqueUsersChallenged of $totalUsers users ($(Get-SafePercentage -Numerator $uniqueUsersChallenged -Denominator $totalUsers)%)" -ForegroundColor White
Write-Host "  • High Risk Events: $(($mfaChallenges | Where-Object { $_.SignInRiskLevel -eq 'high' }).Count)" -ForegroundColor White
Write-Host "  • Medium Risk Events: $(($mfaChallenges | Where-Object { $_.SignInRiskLevel -eq 'medium' }).Count)" -ForegroundColor White
