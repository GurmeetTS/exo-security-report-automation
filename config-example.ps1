# Example Configuration for NewVision Software Pvt.Ltd.
# Copy this file and update with your specific values

# =============================================================================
# ENTRA ID CONFIGURATION
# =============================================================================

# Tenant Information
$TenantId = "ff00942c-81e2-4530-b90f-4e7d35c20644"
$PrimaryDomain = "newvision-software.com"
$OrganizationName = "NewVision Software Pvt.Ltd."

# Report Configuration  
$DaysInactive = 90                                    # Days to consider user inactive
$EmailTo = "gurmeet.kohli@newvision-software.com"    # Report recipient
$EmailFrom = ""                                       # Leave empty for auto-detection

# Output Configuration
$OutputPath = ".\output"                              # Local output directory
$SkipHtml = $false                                    # Set to $true to skip HTML generation

# =============================================================================
# AUTHENTICATION CONFIGURATION
# =============================================================================

# Interactive Authentication (for manual runs)
$AuthMode = "Interactive"

# App-Only Authentication (for automation)
# $AuthMode = "AppOnly"
# $AppId = "your-app-registration-id"
# $CertificateThumbprint = "your-certificate-thumbprint"

# =============================================================================
# AZURE AUTOMATION VARIABLES
# =============================================================================
# When using Azure Automation, create these variables in your Automation Account:
#
# Variable Name         | Value
# ---------------------|----------------------------------------
# TenantId             | ff00942c-81e2-4530-b90f-4e7d35c20644
# EmailTo              | gurmeet.kohli@newvision-software.com
# DaysInactive         | 90
# EmailFrom            | (optional)
# StorageAccountName   | (optional, for report storage)

# =============================================================================
# SAMPLE USAGE COMMANDS
# =============================================================================

# Basic interactive run
# .\Get-EntraIdInactiveUsers.ps1 -TenantId $TenantId

# Interactive run with email
# .\Get-EntraIdInactiveUsers.ps1 -TenantId $TenantId -SendEmail -EmailTo $EmailTo

# App-only authentication with email
# .\Get-EntraIdInactiveUsers.ps1 -TenantId $TenantId -AuthMode AppOnly -AppId $AppId -CertificateThumbprint $CertificateThumbprint -SendEmail -EmailTo $EmailTo

# Custom inactive period (60 days instead of 90)
# .\Get-EntraIdInactiveUsers.ps1 -TenantId $TenantId -DaysInactive 60 -SendEmail -EmailTo $EmailTo

# =============================================================================
# REQUIRED PERMISSIONS FOR APP REGISTRATION
# =============================================================================
# When creating an app registration for app-only authentication, grant these Application permissions:
#
# Microsoft Graph:
# - User.Read.All          (Read all users' profiles and sign-in activity)
# - AuditLog.Read.All      (Read audit logs and sign-in reports)  
# - Mail.Send              (Send emails - optional, only if using email functionality)
#
# These permissions require admin consent.

# =============================================================================
# AZURE AUTOMATION MANAGED IDENTITY PERMISSIONS
# =============================================================================
# Grant the same Microsoft Graph Application permissions to your 
# Automation Account's Managed Identity using PowerShell:
#
# Connect-AzureAD
# $managedIdentity = Get-AzureADServicePrincipal -Filter "displayName eq 'YourAutomationAccountName'"
# $graphSP = Get-AzureADServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
# 
# # Grant User.Read.All
# $userReadRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "User.Read.All"}
# New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $userReadRole.Id
# 
# # Grant AuditLog.Read.All  
# $auditLogRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "AuditLog.Read.All"}
# New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $auditLogRole.Id
# 
# # Grant Mail.Send (optional)
# $mailSendRole = $graphSP.AppRoles | Where-Object {$_.Value -eq "Mail.Send"}  
# New-AzureADServiceAppRoleAssignment -ObjectId $managedIdentity.ObjectId -PrincipalId $managedIdentity.ObjectId -ResourceId $graphSP.ObjectId -Id $mailSendRole.Id