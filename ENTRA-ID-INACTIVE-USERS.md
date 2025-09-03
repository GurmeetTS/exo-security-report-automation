# Entra ID Inactive Users Report

This repository now includes scripts to generate reports for inactive users in Microsoft Entra ID (Azure AD). The scripts are designed to work both locally and in Azure Automation environments.

## Overview

The Entra ID inactive users scripts identify users who haven't signed in for a specified period (default: 90 days) and generate comprehensive reports with recommendations for improving security posture.

## Files

- **`Get-EntraIdInactiveUsers.ps1`** - Main script for local/manual execution
- **`Azure-Automation-EntraId-InactiveUsers.ps1`** - Optimized runbook for Azure Automation

## Features

- ✅ **User Activity Analysis**: Identifies users inactive for 90+ days (configurable)
- ✅ **Multiple Authentication Modes**: Interactive and app-only (certificate) authentication  
- ✅ **Comprehensive Reporting**: CSV exports and HTML/Markdown summaries
- ✅ **Email Notifications**: Automated email reports via Microsoft Graph
- ✅ **Azure Automation Ready**: Optimized runbook with Managed Identity support
- ✅ **Security Recommendations**: Actionable insights for access management

## Prerequisites

### Local Execution
- PowerShell 7.x or Windows PowerShell 5.1
- Microsoft Graph PowerShell modules:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -Scope CurrentUser
  Install-Module Microsoft.Graph.Mail -Scope CurrentUser
  ```

### Azure Automation
- Azure Automation Account with Managed Identity enabled
- Required modules imported in Automation Account:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Mail`

## Required Permissions

### For App Registration (App-Only Authentication)
- **Application Permissions**:
  - `User.Read.All` - Read all users' profiles and sign-in activity
  - `AuditLog.Read.All` - Read audit logs and sign-in reports
  - `Mail.Send` - Send emails (if using email functionality)

### For Managed Identity (Azure Automation)
Grant the same permissions to the Automation Account's Managed Identity.

## Configuration

### Tenant Information
- **Tenant ID**: `ff00942c-81e2-4530-b90f-4e7d35c20644`
- **Primary Domain**: `newvision-software.com`
- **Organization**: NewVision Software Pvt.Ltd.

## Usage Examples

### 1. Local Interactive Execution
```powershell
# Basic usage with interactive authentication
.\Get-EntraIdInactiveUsers.ps1 -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644"

# With email report
.\Get-EntraIdInactiveUsers.ps1 `
    -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" `
    -SendEmail `
    -EmailTo "gurmeet.kohli@newvision-software.com"
```

### 2. App-Only Authentication (Certificate)
```powershell
.\Get-EntraIdInactiveUsers.ps1 `
    -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" `
    -AuthMode AppOnly `
    -AppId "<your-app-id>" `
    -CertificateThumbprint "<cert-thumbprint>" `
    -SendEmail `
    -EmailTo "gurmeet.kohli@newvision-software.com"
```

### 3. Custom Inactive Period
```powershell
# Check for users inactive for 60 days instead of 90
.\Get-EntraIdInactiveUsers.ps1 `
    -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" `
    -DaysInactive 60
```

## Azure Automation Setup

### 1. Create Automation Account
1. Create an Azure Automation Account
2. Enable **Managed Identity** (System-assigned)
3. Import required PowerShell modules

### 2. Grant Permissions to Managed Identity
```powershell
# Connect to Azure AD PowerShell
Connect-AzureAD

# Get the Managed Identity
$managedIdentity = Get-AzureADServicePrincipal -Filter "displayName eq '<AutomationAccountName>'"

# Get Microsoft Graph Service Principal
$graphSP = Get-AzureADServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Grant User.Read.All permission
$userReadRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "User.Read.All"}
New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $userReadRole.Id

# Grant AuditLog.Read.All permission
$auditLogRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "AuditLog.Read.All"}
New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $auditLogRole.Id

# Grant Mail.Send permission (if using email)
$mailSendRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "Mail.Send"}
New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $mailSendRole.Id
```

### 3. Create Runbook
1. In your Automation Account, go to **Runbooks** → **Create a runbook**
2. Choose **PowerShell** as the runbook type
3. Copy the content of `Azure-Automation-EntraId-InactiveUsers.ps1`
4. Publish the runbook

### 4. Configure Variables (Optional)
Set these variables in **Automation Account** → **Variables**:
- `TenantId`: Your tenant ID (default: ff00942c-81e2-4530-b90f-4e7d35c20644)
- `EmailTo`: Recipient email (default: gurmeet.kohli@newvision-software.com)
- `DaysInactive`: Inactive threshold in days (default: 90)
- `EmailFrom`: Sender email address (optional)

### 5. Schedule the Runbook
1. Go to **Runbooks** → Select your runbook → **Schedules**
2. **Add a schedule**
3. Configure frequency (e.g., weekly, monthly)

## Report Output

### Files Generated
- `InactiveUsers_YYYYMMDD_HHMMSS.csv` - List of inactive users
- `AllUsersActivity_YYYYMMDD_HHMMSS.csv` - Complete user activity report
- `InactiveUsersSummary_YYYYMMDD_HHMMSS.md` - Markdown summary
- `InactiveUsersSummary_YYYYMMDD_HHMMSS.html` - HTML summary

### Email Report Content
- **Summary statistics** (total, active, inactive, never signed in users)
- **Top 10 longest inactive users** (enabled accounts only)
- **Security recommendations**
- **Professional HTML formatting**

## Sample Report Output

```
Entra ID Inactive Users Report
Organization: NewVision Software Pvt.Ltd.
Generated: 2024-01-15 10:30:00 +00:00
Inactive Period: 90 days

Summary:
- Total Users: 150
- Active Users: 120 (80%)
- Inactive Users (90+ days): 25 (16.7%)
- Enabled Inactive Users: 15 (10%)
- Never Signed In: 5 (3.3%)

Recommendations:
- Review 15 enabled but inactive user accounts
- Consider disabling unused accounts to improve security posture
- Implement regular access reviews for user accounts
```

## Security Considerations

1. **Least Privilege**: Grant only necessary permissions to service principals
2. **Regular Reviews**: Schedule reports to run regularly (weekly/monthly)
3. **Access Reviews**: Use report data to conduct user access reviews
4. **Account Cleanup**: Disable or remove unused accounts promptly
5. **Monitoring**: Set up alerts for accounts inactive beyond thresholds

## Troubleshooting

### Common Issues

1. **Permission Errors**
   - Ensure Managed Identity has required Graph API permissions
   - Check that permissions are **Application** type, not **Delegated**

2. **Module Import Errors in Azure Automation**
   - Import modules in correct order: Authentication → Users → Mail
   - Use compatible module versions

3. **Email Sending Failures**
   - Verify Mail.Send permission is granted
   - Check that EmailFrom address has proper mailbox permissions

4. **Sign-in Activity Data Missing**
   - Requires Entra ID Premium P1/P2 for full sign-in activity data
   - Free tier has limited sign-in activity retention

### Getting Help

For issues specific to NewVision Software Pvt.Ltd. tenant:
- Contact: gurmeet.kohli@newvision-software.com
- Tenant ID: ff00942c-81e2-4530-b90f-4e7d35c20644

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.