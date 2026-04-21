# Conditional Access Report-Only MFA Impact Report

This repository contains a PowerShell script that analyzes Microsoft Entra ID sign-ins against **report-only** Conditional Access (CA) policies and estimates where MFA would have been challenged if those policies were enforced.

## Script

- `CA_report.ps1`

## What It Does

The script:

1. Connects to Microsoft Graph with required read scopes.
2. Finds CA policies in `enabledForReportingButNotEnforced` state.
3. Filters for policies related to sign-in risk and/or MFA grant controls.
4. Pulls sign-in logs for the last 30 days.
5. Correlates policy evaluation results with sign-in risk and authentication context.
6. Exports detailed and summary CSV reports.

## Prerequisites

- PowerShell 7+
- Microsoft Graph PowerShell SDK installed
- Permissions/scopes:
  - `AuditLog.Read.All`
  - `Policy.Read.All`
- Ability to run scripts in your PowerShell environment

## Usage

Run from this repository directory:

```powershell
.\CA_report.ps1
```

Interactive mode now lets you choose:
- A single report-only policy by number
- Or all policies (`A`, default)

If execution policy blocks script start:

```powershell
pwsh -ExecutionPolicy Bypass -File .\CA_report.ps1
```

Run non-interactively for one target policy (name or ID):

```powershell
.\CA_report.ps1 -TargetPolicy "Require MFA for risky sign-ins"
```

Run all matching report-only policies without prompt:

```powershell
.\CA_report.ps1 -AllPolicies
```

## Output Files

The script generates:

1. `CA_SignInRisk_MFA_Impact_Detail.csv` - Per-sign-in detail and MFA impact assessment.
2. `CA_SignInRisk_MFA_By_RiskLevel.csv` - MFA challenge distribution by risk level.
3. `CA_SignInRisk_MFA_User_Impact.csv` - User-level impact and challenge rates.
4. `CA_SignInRisk_MFA_RiskTypes.csv` - Risk detection type frequency and affected users.
5. `CA_SignInRisk_MFA_Policy_Impact.csv` - Policy-level challenge impact.
6. `CA_SignInRisk_MFA_App_Impact.csv` - Application-level MFA challenge impact.

## Notes

- The current script uses a fixed 30-day lookback window.
- This report is based on report-only policy evaluation and historical sign-in data; it is intended for impact analysis before enforcing CA policies.
