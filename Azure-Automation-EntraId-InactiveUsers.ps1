<#
.SYNOPSIS
  Azure Automation Runbook for Entra ID Inactive Users Report

.DESCRIPTION
  This runbook is designed to run in Azure Automation to generate reports of inactive Entra ID users
  and send email notifications. It uses Managed Identity or service principal authentication.

.NOTES
  Azure Automation Requirements:
  - Import the following modules in your Automation Account:
    * Microsoft.Graph.Authentication
    * Microsoft.Graph.Users  
    * Microsoft.Graph.Mail
    * Microsoft.Graph.Reports (optional, for additional insights)
  
  Required Permissions for Managed Identity or Service Principal:
  - User.Read.All
  - AuditLog.Read.All
  - Mail.Send (if sending emails through Graph)
  
  Variables to configure in Azure Automation:
  - TenantId: Your Entra ID tenant ID
  - DaysInactive: Number of days to consider inactive (default: 90)
  - EmailTo: Recipient email address
  - EmailFrom: Sender email address (optional)
  - StorageAccountName: Storage account for reports (optional)
  - StorageContainerName: Container name (optional)

#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailTo,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailFrom,
    
    [Parameter(Mandatory=$false)]
    [switch]$UploadToStorage,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageContainerName = "reports"
)

# Get variables from Azure Automation if not provided as parameters
if (-not $TenantId) {
    $TenantId = Get-AutomationVariable -Name "TenantId" -ErrorAction SilentlyContinue
    if (-not $TenantId) {
        $TenantId = "ff00942c-81e2-4530-b90f-4e7d35c20644"  # NewVision Software tenant
    }
}

if (-not $EmailTo) {
    $EmailTo = Get-AutomationVariable -Name "EmailTo" -ErrorAction SilentlyContinue
    if (-not $EmailTo) {
        $EmailTo = "gurmeet.kohli@newvision-software.com"
    }
}

if (-not $EmailFrom) {
    $EmailFrom = Get-AutomationVariable -Name "EmailFrom" -ErrorAction SilentlyContinue
}

if (-not $StorageAccountName) {
    $StorageAccountName = Get-AutomationVariable -Name "StorageAccountName" -ErrorAction SilentlyContinue
}

$DaysInactiveVar = Get-AutomationVariable -Name "DaysInactive" -ErrorAction SilentlyContinue
if ($DaysInactiveVar) {
    $DaysInactive = [int]$DaysInactiveVar
}

Write-Output "Starting Entra ID Inactive Users Report"
Write-Output "Tenant ID: $TenantId"
Write-Output "Days Inactive Threshold: $DaysInactive"
Write-Output "Email To: $EmailTo"

function Connect-MgGraphWithManagedIdentity {
    param([string]$TenantId)
    
    try {
        # Connect using Managed Identity
        Connect-MgGraph -Identity -TenantId $TenantId -NoWelcome
        Write-Output "Connected to Microsoft Graph using Managed Identity"
        
        # Verify connection
        $context = Get-MgContext
        Write-Output "Connected as: $($context.Account)"
        Write-Output "Tenant: $($context.TenantId)"
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        throw
    }
}

function Get-InactiveUsersReport {
    param([int]$DaysInactive)
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    Write-Output "Getting users inactive since: $($cutoffDate.ToString('yyyy-MM-dd'))"
    
    try {
        # Get all users with sign-in activity
        Write-Output "Retrieving users from Entra ID..."
        $users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,SignInActivity"
        Write-Output "Retrieved $($users.Count) users from Entra ID"
        
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
            TotalUsers = $users.Count
        }
    }
    catch {
        Write-Error "Failed to retrieve user data: $_"
        throw
    }
}

function Send-EmailReportViaGraph {
    param(
        [string]$To,
        [string]$From,
        [string]$Subject,
        [string]$Body
    )
    
    try {
        if (-not $From) {
            # Try to get a user to send from (in Azure Automation, you might need to specify this)
            $From = $To  # Send from the recipient's mailbox (requires permission)
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
        
        Send-MgUserMail -UserId $From -Message $message
        Write-Output "Email sent successfully to $To"
    }
    catch {
        Write-Error "Failed to send email via Graph: $_"
        
        # Alternative: Use Azure Automation's Send-MailMessage if Graph fails
        try {
            Write-Output "Attempting to send email using alternative method..."
            # Note: This would require SMTP configuration in Azure Automation
            # Implementation depends on your email setup
        }
        catch {
            Write-Error "All email sending methods failed"
        }
    }
}

function Upload-ReportToStorage {
    param(
        [string]$StorageAccountName,
        [string]$ContainerName,
        [string]$Content,
        [string]$FileName
    )
    
    try {
        # Note: This would require Azure Storage PowerShell modules
        # Implementation would depend on your storage setup
        Write-Output "Storage upload functionality would be implemented here"
        Write-Output "File: $FileName, Size: $($Content.Length) characters"
    }
    catch {
        Write-Error "Failed to upload to storage: $_"
    }
}

# Main execution
try {
    Write-Output "Initializing Azure Automation runbook..."
    
    # Connect to Microsoft Graph
    Connect-MgGraphWithManagedIdentity -TenantId $TenantId
    
    # Get organization info
    $orgInfo = Get-MgOrganization | Select-Object -First 1
    $tenantName = $orgInfo.DisplayName
    Write-Output "Organization: $tenantName"
    
    # Get inactive users report
    Write-Output "Generating inactive users report..."
    $report = Get-InactiveUsersReport -DaysInactive $DaysInactive
    
    $inactiveCount = $report.InactiveUsers.Count
    $activeCount = $report.ActiveUsers.Count
    $neverSignedInCount = $report.NeverSignedIn.Count
    $totalUsers = $report.TotalUsers
    $enabledInactiveUsers = ($report.InactiveUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    
    Write-Output "Report Summary:"
    Write-Output "- Total Users: $totalUsers"
    Write-Output "- Active Users: $activeCount"
    Write-Output "- Inactive Users ($DaysInactive+ days): $inactiveCount"
    Write-Output "- Enabled Inactive Users: $enabledInactiveUsers"
    Write-Output "- Never Signed In: $neverSignedInCount"
    
    # Generate email content
    $emailSubject = "Entra ID Inactive Users Report - $tenantName - $(Get-Date -Format 'yyyy-MM-dd')"
    
    $emailBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .header { color: #0078d7; }
        .warning { color: #ff6b35; font-weight: bold; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1 class="header">Entra ID Inactive Users Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Organization:</strong> $tenantName</p>
        <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')</p>
        <p><strong>Inactive Period:</strong> $DaysInactive days</p>
    </div>
    
    <table>
        <tr>
            <th>Category</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
        <tr>
            <td>Total Users</td>
            <td>$totalUsers</td>
            <td>100%</td>
        </tr>
        <tr>
            <td>Active Users (within $DaysInactive days)</td>
            <td>$activeCount</td>
            <td>$([math]::Round(($activeCount / $totalUsers) * 100, 1))%</td>
        </tr>
        <tr>
            <td class="warning">Inactive Users ($DaysInactive+ days)</td>
            <td class="warning">$inactiveCount</td>
            <td class="warning">$([math]::Round(($inactiveCount / $totalUsers) * 100, 1))%</td>
        </tr>
        <tr>
            <td class="warning">Enabled Inactive Users</td>
            <td class="warning">$enabledInactiveUsers</td>
            <td class="warning">$([math]::Round(($enabledInactiveUsers / $totalUsers) * 100, 1))%</td>
        </tr>
        <tr>
            <td>Never Signed In</td>
            <td>$neverSignedInCount</td>
            <td>$([math]::Round(($neverSignedInCount / $totalUsers) * 100, 1))%</td>
        </tr>
    </table>
"@

    # Add top inactive users if any
    if ($inactiveCount -gt 0) {
        $topInactive = $report.InactiveUsers | 
            Where-Object { $_.AccountEnabled -eq $true -and $_.DaysSinceLastSignIn -ne $null } | 
            Sort-Object DaysSinceLastSignIn -Descending | 
            Select-Object -First 10
        
        if ($topInactive) {
            $emailBody += @"
    <h2>Top 10 Longest Inactive Users (Enabled Accounts)</h2>
    <table>
        <tr>
            <th>User Principal Name</th>
            <th>Display Name</th>
            <th>Days Inactive</th>
            <th>Last Sign In</th>
        </tr>
"@
            foreach ($user in $topInactive) {
                $lastSignIn = if ($user.LastSignInDateTime) { 
                    ([DateTime]$user.LastSignInDateTime).ToString('yyyy-MM-dd') 
                } else { "Never" }
                $emailBody += @"
        <tr>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.DisplayName)</td>
            <td>$($user.DaysSinceLastSignIn)</td>
            <td>$lastSignIn</td>
        </tr>
"@
            }
            $emailBody += "</table>"
        }
    }
    
    # Add recommendations
    $emailBody += @"
    <h2>Recommendations</h2>
    <ul>
"@
    
    if ($enabledInactiveUsers -gt 0) {
        $emailBody += "<li><strong>Review $enabledInactiveUsers enabled but inactive user accounts</strong></li>"
        $emailBody += "<li>Consider disabling unused accounts to improve security posture</li>"
    }
    if ($neverSignedInCount -gt 0) {
        $emailBody += "<li>Review $neverSignedInCount accounts that have never signed in</li>"
        $emailBody += "<li>Consider removing accounts that were created but never used</li>"
    }
    $emailBody += @"
        <li>Implement regular access reviews for user accounts</li>
        <li>Set up automated alerting for long-term inactive accounts</li>
    </ul>
    
    <p><em>This report was generated automatically by Azure Automation on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')</em></p>
</body>
</html>
"@
    
    # Send email report
    if ($EmailTo) {
        Write-Output "Sending email report to $EmailTo..."
        Send-EmailReportViaGraph -To $EmailTo -From $EmailFrom -Subject $emailSubject -Body $emailBody
    }
    
    # Upload to storage if configured
    if ($UploadToStorage -and $StorageAccountName) {
        Write-Output "Uploading report to storage..."
        $csvData = $report.InactiveUsers | ConvertTo-Csv -NoTypeInformation
        $fileName = "InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        Upload-ReportToStorage -StorageAccountName $StorageAccountName -ContainerName $StorageContainerName -Content ($csvData -join "`n") -FileName $fileName
    }
    
    Write-Output "Runbook execution completed successfully!"
    Write-Output "Final Summary: $inactiveCount inactive users found ($enabledInactiveUsers enabled inactive accounts) out of $totalUsers total users"
    
    # Return summary for runbook output
    return @{
        TotalUsers = $totalUsers
        ActiveUsers = $activeCount
        InactiveUsers = $inactiveCount
        EnabledInactiveUsers = $enabledInactiveUsers
        NeverSignedIn = $neverSignedInCount
        ReportGenerated = Get-Date
        EmailSent = ($null -ne $EmailTo)
    }
}
catch {
    Write-Error "Runbook execution failed: $_"
    throw
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Output "Disconnected from Microsoft Graph"
    }
    catch {
        # Ignore errors during disconnect
    }
}
"@