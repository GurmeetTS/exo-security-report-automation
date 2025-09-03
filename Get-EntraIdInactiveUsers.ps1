<#
.SYNOPSIS
  Entra ID Inactive Users Report Automation

.DESCRIPTION
  Generates a report of users in Entra ID who have been inactive for more than 90 days.
  Supports interactive and app-only (certificate) authentication.
  Can send email reports via Azure Automation.

.PARAMETER TenantId
  The Entra ID tenant ID (required)

.PARAMETER AuthMode
  Authentication mode: Interactive or AppOnly (default: Interactive)

.PARAMETER AppId
  Application ID for app-only authentication

.PARAMETER CertificateThumbprint
  Certificate thumbprint for app-only authentication

.PARAMETER DaysInactive
  Number of days to consider a user inactive (default: 90)

.PARAMETER OutputPath
  Output directory for reports (default: ./output)

.PARAMETER SendEmail
  Send email report via Microsoft Graph

.PARAMETER EmailTo
  Email recipient address

.PARAMETER EmailFrom
  Email sender address (must have permissions)

.PARAMETER SkipHtml
  Skip generating HTML report

.EXAMPLE
  .\Get-EntraIdInactiveUsers.ps1 -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644"

.EXAMPLE
  .\Get-EntraIdInactiveUsers.ps1 -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" -AuthMode AppOnly -AppId <appId> -CertificateThumbprint <thumb> -SendEmail -EmailTo "gurmeet.kohli@newvision-software.com"

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Interactive','AppOnly')]
    [string]$AuthMode = 'Interactive',

    [Parameter(Mandatory=$false)]
    [string]$AppId,

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$(Join-Path (Split-Path -Parent $PSCommandPath) 'output')",

    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,

    [Parameter(Mandatory=$false)]
    [string]$EmailTo = "gurmeet.kohli@newvision-software.com",

    [Parameter(Mandatory=$false)]
    [string]$EmailFrom,

    [switch]$SkipHtml
)

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Installing module: $Name"
        Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
    }
    Import-Module $Name -Force -ErrorAction Stop
}

function Connect-MgGraphCustom {
    if ($AuthMode -eq 'AppOnly') {
        if (-not $AppId -or -not $CertificateThumbprint) {
            throw "AppOnly requires -AppId and -CertificateThumbprint."
        }
        Connect-MgGraph -ClientId $AppId -CertificateThumbprint $CertificateThumbprint -TenantId $TenantId -NoWelcome
    } else {
        Connect-MgGraph -TenantId $TenantId -Scopes "User.Read.All", "AuditLog.Read.All", "Mail.Send" -NoWelcome
    }
}

function Export-IfAny {
    param(
        [Parameter(Mandatory=$true)][object]$Data,
        [Parameter(Mandatory=$true)][string]$Path
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($null -ne $Data) {
        $arr = @()
        if ($Data -is [System.Collections.IEnumerable]) { $arr = $Data } else { $arr = @($Data) }
        if ($arr.Count -gt 0) {
            $arr | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Host "Saved: $Path"
        } else {
            Write-Verbose "No rows for $Path"
        }
    }
}

function Get-InactiveUsers {
    param([int]$DaysInactive)
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    Write-Verbose "Getting users inactive since: $($cutoffDate.ToString('yyyy-MM-dd'))"
    
    # Get all users with sign-in activity
    try {
        $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,SignInActivity" -ErrorAction Stop
        Write-Verbose "Retrieved $($users.Count) users from Entra ID"
        
        $inactiveUsers = @()
        $activeUsers = @()
        $neverSignedIn = @()
        
        foreach ($user in $users) {
            $userInfo = [PSCustomObject]@{
                Id = $user.Id
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                AccountEnabled = $user.AccountEnabled
                CreatedDateTime = $user.CreatedDateTime
                LastSignInDateTime = $null
                LastNonInteractiveSignInDateTime = $null
                DaysSinceLastSignIn = $null
                Status = ""
            }
            
            if ($user.SignInActivity) {
                $userInfo.LastSignInDateTime = $user.SignInActivity.LastSignInDateTime
                $userInfo.LastNonInteractiveSignInDateTime = $user.SignInActivity.LastNonInteractiveSignInDateTime
                
                # Use the most recent sign-in date
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
                if ($user.SignInActivity.LastNonInteractiveSignInDateTime -and 
                    ($null -eq $lastSignIn -or $user.SignInActivity.LastNonInteractiveSignInDateTime -gt $lastSignIn)) {
                    $lastSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
                }
                
                if ($lastSignIn) {
                    $daysSince = (Get-Date) - [DateTime]$lastSignIn
                    $userInfo.DaysSinceLastSignIn = [math]::Round($daysSince.TotalDays)
                    
                    if ($daysSince.TotalDays -gt $DaysInactive) {
                        $userInfo.Status = "Inactive"
                        $inactiveUsers += $userInfo
                    } else {
                        $userInfo.Status = "Active"
                        $activeUsers += $userInfo
                    }
                } else {
                    $userInfo.Status = "Never Signed In"
                    $neverSignedIn += $userInfo
                }
            } else {
                $userInfo.Status = "Never Signed In"
                $neverSignedIn += $userInfo
            }
        }
        
        return @{
            InactiveUsers = $inactiveUsers
            ActiveUsers = $activeUsers
            NeverSignedIn = $neverSignedIn
            AllUsers = $users
        }
    }
    catch {
        Write-Error "Failed to retrieve users: $_"
        throw
    }
}

function Send-EmailReport {
    param(
        [string]$To,
        [string]$From,
        [string]$Subject,
        [string]$Body,
        [string[]]$AttachmentPaths
    )
    
    try {
        if (-not $From) {
            # Try to get the current user's email for sending
            $currentUser = Get-MgContext
            if ($currentUser.Account) {
                $From = $currentUser.Account
            } else {
                throw "Email sender address not specified and cannot determine from current context"
            }
        }
        
        $message = @{
            Subject = $Subject
            Body = @{
                ContentType = "HTML"
                Content = $Body
            }
            ToRecipients = @(
                @{
                    EmailAddress = @{
                        Address = $To
                    }
                }
            )
        }
        
        # Add attachments if provided
        if ($AttachmentPaths) {
            $attachments = @()
            foreach ($path in $AttachmentPaths) {
                if (Test-Path $path) {
                    $fileName = Split-Path $path -Leaf
                    $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
                    $attachments += @{
                        "@odata.type" = "#microsoft.graph.fileAttachment"
                        Name = $fileName
                        ContentBytes = $content
                    }
                }
            }
            if ($attachments.Count -gt 0) {
                $message.Attachments = $attachments
            }
        }
        
        Send-MgUserMail -UserId $From -Message $message
        Write-Host "Email sent successfully to $To"
    }
    catch {
        Write-Error "Failed to send email: $_"
        throw
    }
}

# Main execution
$ErrorActionPreference = 'Stop'

try {
    # Ensure required modules
    Ensure-Module -Name Microsoft.Graph.Authentication
    Ensure-Module -Name Microsoft.Graph.Users
    Ensure-Module -Name Microsoft.Graph.Mail
    
    if (-not (Test-Path $OutputPath)) { 
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null 
    }
    
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraphCustom
    
    # Get tenant information
    $orgInfo = Get-MgOrganization | Select-Object -First 1
    $tenantName = $orgInfo.DisplayName
    
    Write-Host "Connected to tenant: $tenantName"
    Write-Host "Analyzing user activity for the last $DaysInactive days..."
    
    # Get inactive users
    $userReport = Get-InactiveUsers -DaysInactive $DaysInactive
    
    # Export reports
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $inactiveUsersPath = Join-Path $OutputPath "InactiveUsers_$timestamp.csv"
    $allUsersPath = Join-Path $OutputPath "AllUsersActivity_$timestamp.csv"
    
    # Combine all users for the complete report
    $allUsersReport = @()
    $allUsersReport += $userReport.InactiveUsers
    $allUsersReport += $userReport.ActiveUsers
    $allUsersReport += $userReport.NeverSignedIn
    
    Export-IfAny -Data $userReport.InactiveUsers -Path $inactiveUsersPath
    Export-IfAny -Data $allUsersReport -Path $allUsersPath
    
    # Generate summary
    $inactiveCount = $userReport.InactiveUsers.Count
    $activeCount = $userReport.ActiveUsers.Count
    $neverSignedInCount = $userReport.NeverSignedIn.Count
    $totalUsers = $inactiveCount + $activeCount + $neverSignedInCount
    $enabledInactiveUsers = ($userReport.InactiveUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    
    # Build summary (Markdown)
    $md = @()
    $md += "# Entra ID Inactive Users Report"
    $md += ""
    $md += "**Tenant:** $tenantName"
    $md += "**Tenant ID:** $TenantId"
    $md += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
    $md += "**Inactive Period:** $DaysInactive days"
    $md += ""
    $md += "## Summary"
    $md += ""
    $md += "| Category | Count | Percentage |"
    $md += "|----------|-------|------------|"
    $md += "| Total Users | $totalUsers | 100% |"
    $md += "| Active Users (within $DaysInactive days) | $activeCount | $([math]::Round(($activeCount / $totalUsers) * 100, 1))% |"
    $md += "| Inactive Users ($DaysInactive+ days) | $inactiveCount | $([math]::Round(($inactiveCount / $totalUsers) * 100, 1))% |"
    $md += "| Enabled Inactive Users | $enabledInactiveUsers | $([math]::Round(($enabledInactiveUsers / $totalUsers) * 100, 1))% |"
    $md += "| Never Signed In | $neverSignedInCount | $([math]::Round(($neverSignedInCount / $totalUsers) * 100, 1))% |"
    $md += ""
    
    if ($inactiveCount -gt 0) {
        $md += "## Top 10 Longest Inactive Users (Enabled Accounts)"
        $md += ""
        $topInactive = $userReport.InactiveUsers | 
            Where-Object { $_.AccountEnabled -eq $true -and $_.DaysSinceLastSignIn -ne $null } | 
            Sort-Object DaysSinceLastSignIn -Descending | 
            Select-Object -First 10
        
        if ($topInactive) {
            $md += "| User | Days Inactive | Last Sign In |"
            $md += "|------|---------------|--------------|"
            foreach ($user in $topInactive) {
                $lastSignIn = if ($user.LastSignInDateTime) { 
                    ([DateTime]$user.LastSignInDateTime).ToString('yyyy-MM-dd') 
                } else { "N/A" }
                $md += "| $($user.UserPrincipalName) | $($user.DaysSinceLastSignIn) | $lastSignIn |"
            }
        }
    }
    
    $md += ""
    $md += "## Recommendations"
    $md += ""
    if ($enabledInactiveUsers -gt 0) {
        $md += "- Review $enabledInactiveUsers enabled but inactive user accounts"
        $md += "- Consider disabling unused accounts to improve security posture"
    }
    if ($neverSignedInCount -gt 0) {
        $md += "- Review $neverSignedInCount accounts that have never signed in"
        $md += "- Consider removing accounts that were created but never used"
    }
    $md += "- Implement regular access reviews for user accounts"
    $md += "- Set up automated alerting for long-term inactive accounts"
    
    # Save summary
    $summaryPath = Join-Path $OutputPath "InactiveUsersSummary_$timestamp.md"
    $md -join "`r`n" | Out-File -FilePath $summaryPath -Encoding UTF8
    Write-Host "Saved: $summaryPath"
    
    # Generate HTML version
    if (-not $SkipHtml) {
        $htmlContent = ($md -join "`r`n") -replace "`r`n", "<br/>" -replace "\| (.*) \|", "<tr><td>$1</td></tr>" -replace "\|.*\|", "<table>" -replace "<tr><td>.*</td></tr>", "</table>"
        # Simple markdown to HTML conversion
        $htmlContent = $htmlContent -replace "^# (.*)", "<h1>$1</h1>" -replace "^## (.*)", "<h2>$1</h2>" -replace "^\*\*(.*)\*\*", "<strong>$1</strong>"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra ID Inactive Users Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        h1 { color: #0078d7; }
        h2 { color: #106ebe; margin-top: 30px; }
    </style>
</head>
<body>
    $htmlContent
</body>
</html>
"@
        
        $htmlPath = Join-Path $OutputPath "InactiveUsersSummary_$timestamp.html"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "Saved: $htmlPath"
    }
    
    # Send email if requested
    if ($SendEmail) {
        Write-Host "Sending email report..."
        $emailSubject = "Entra ID Inactive Users Report - $tenantName - $(Get-Date -Format 'yyyy-MM-dd')"
        $emailBody = ($md -join "<br/>") -replace "\*\*(.*?)\*\*", "<strong>$1</strong>"
        
        $attachments = @($inactiveUsersPath, $summaryPath)
        if (-not $SkipHtml) {
            $attachments += $htmlPath
        }
        
        Send-EmailReport -To $EmailTo -From $EmailFrom -Subject $emailSubject -Body $emailBody -AttachmentPaths $attachments
    }
    
    Write-Host ""
    Write-Host "Report completed successfully!" -ForegroundColor Green
    Write-Host "Summary: $inactiveCount inactive users out of $totalUsers total users ($enabledInactiveUsers enabled inactive accounts)" -ForegroundColor Yellow
    Write-Host "Output directory: $OutputPath" -ForegroundColor Cyan
}
catch {
    Write-Error "Script execution failed: $_"
    throw
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore errors during disconnect
    }
}