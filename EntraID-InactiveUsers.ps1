<#
.SYNOPSIS
  Entra ID Inactive Users Report Automation

.DESCRIPTION
  Generates a CSV report of users in Entra ID who have been inactive for more than 90 days.
  Supports interactive and app-only (certificate) authentication for Azure Automation scenarios.

.PARAMETER TenantId
  The Entra ID tenant ID (required for app-only authentication)

.PARAMETER AuthMode
  Authentication mode: Interactive or AppOnly. Default is Interactive.

.PARAMETER AppId
  Application ID for app-only authentication (required when AuthMode is AppOnly)

.PARAMETER CertificateThumbprint
  Certificate thumbprint for app-only authentication (required when AuthMode is AppOnly)

.PARAMETER InactiveDays
  Number of days to consider a user inactive. Default is 90 days.

.PARAMETER OutputPath
  Path where the CSV report will be saved. Default is .\output relative to script location.

.PARAMETER IncludeDisabledUsers
  Include disabled users in the report. Default is false (only enabled users).

.EXAMPLE
  .\EntraID-InactiveUsers.ps1 -TenantId "contoso.onmicrosoft.com" -OutputPath .\output

.EXAMPLE
  .\EntraID-InactiveUsers.ps1 -TenantId "contoso.onmicrosoft.com" -AuthMode AppOnly -AppId <appId> -CertificateThumbprint <thumb> -OutputPath .\output

.EXAMPLE
  .\EntraID-InactiveUsers.ps1 -TenantId "contoso.onmicrosoft.com" -InactiveDays 60 -IncludeDisabledUsers

.NOTES
  Requires Microsoft Graph PowerShell module and appropriate permissions:
  - User.Read.All (to read user profiles)
  - AuditLog.Read.All (to read sign-in logs)
  
  For app-only authentication, the app registration needs:
  - Application permissions: User.Read.All, AuditLog.Read.All
  - Admin consent granted
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
  [int]$InactiveDays = 90,

  [Parameter(Mandatory=$false)]
  [string]$OutputPath = "$(Join-Path (Split-Path -Parent $PSCommandPath) 'output')",

  [Parameter(Mandatory=$false)]
  [switch]$IncludeDisabledUsers
)

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Verbose "Installing module: $Name"
    Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
  }
  Import-Module $Name -Force -ErrorAction Stop
}

function Connect-MgGraphAuth {
  if ($AuthMode -eq 'AppOnly') {
    if (-not $AppId -or -not $CertificateThumbprint) {
      throw "AppOnly requires -AppId and -CertificateThumbprint."
    }
    Write-Host "Connecting to Microsoft Graph with app-only authentication..."
    Connect-MgGraph -ClientId $AppId -CertificateThumbprint $CertificateThumbprint -TenantId $TenantId -NoWelcome
  } else {
    Write-Host "Connecting to Microsoft Graph with interactive authentication..."
    Connect-MgGraph -TenantId $TenantId -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome
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
      Write-Host "Saved: $Path ($($arr.Count) records)"
      return $arr.Count
    } else {
      Write-Verbose "No rows for $Path"
      return 0
    }
  }
  return 0
}

# Main script execution
$ErrorActionPreference = 'Stop'

try {
  Write-Host "Starting Entra ID Inactive Users Report..."
  Write-Host "Parameters:"
  Write-Host "  - Tenant ID: $TenantId"
  Write-Host "  - Auth Mode: $AuthMode"
  Write-Host "  - Inactive Days: $InactiveDays"
  Write-Host "  - Include Disabled Users: $IncludeDisabledUsers"
  Write-Host "  - Output Path: $OutputPath"
  Write-Host ""

  # Ensure required modules are available
  Write-Host "Checking required PowerShell modules..."
  Ensure-Module -Name Microsoft.Graph.Authentication
  Ensure-Module -Name Microsoft.Graph.Users
  Ensure-Module -Name Microsoft.Graph.Reports

  # Create output directory if it doesn't exist
  if (-not (Test-Path $OutputPath)) { 
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null 
    Write-Host "Created output directory: $OutputPath"
  }

  # Connect to Microsoft Graph
  Connect-MgGraphAuth

  # Verify connection
  $context = Get-MgContext
  if (-not $context) {
    throw "Failed to connect to Microsoft Graph"
  }
  Write-Host "Successfully connected to Microsoft Graph (Tenant: $($context.TenantId))"

  # Calculate the cutoff date for inactive users
  $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
  Write-Host "Looking for users inactive since: $($cutoffDate.ToString('yyyy-MM-dd'))"

  # Get all users with sign-in activity
  Write-Host "Retrieving user accounts and sign-in activity..."
  
  # Base filter for user query
  $userFilter = if ($IncludeDisabledUsers) {
    "userType eq 'Member'"
  } else {
    "userType eq 'Member' and accountEnabled eq true"
  }

  # Get users with required properties
  $users = Get-MgUser -Filter $userFilter -Property Id, DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime, UserType, Department, JobTitle -All
  Write-Host "Found $($users.Count) users to analyze"

  # Initialize results array
  $inactiveUsers = @()
  $processedCount = 0
  $batchSize = 100

  Write-Host "Analyzing user sign-in activity (this may take several minutes for large tenants)..."

  foreach ($user in $users) {
    $processedCount++
    
    # Show progress every 100 users
    if ($processedCount % $batchSize -eq 0) {
      Write-Host "Processed $processedCount/$($users.Count) users..."
    }

    try {
      # Get the user's sign-in logs (last 30 days of available data)
      # Note: Sign-in logs have limited retention (typically 30 days for most tenants)
      $signIns = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1 -Sort "createdDateTime desc" -ErrorAction SilentlyContinue
      
      $lastSignIn = $null
      $lastSignInDate = $null
      $daysSinceLastSignIn = $null
      $isInactive = $false

      if ($signIns -and $signIns.Count -gt 0) {
        $lastSignIn = $signIns[0]
        $lastSignInDate = $lastSignIn.CreatedDateTime
        $daysSinceLastSignIn = (New-TimeSpan -Start $lastSignInDate -End (Get-Date)).Days
        $isInactive = $daysSinceLastSignIn -gt $InactiveDays
      } else {
        # No sign-in logs found - could mean never signed in or data beyond retention
        # Check if user was created more than InactiveDays ago
        if ($user.CreatedDateTime) {
          $daysSinceCreation = (New-TimeSpan -Start $user.CreatedDateTime -End (Get-Date)).Days
          if ($daysSinceCreation -gt $InactiveDays) {
            $isInactive = $true
            $daysSinceLastSignIn = $daysSinceCreation
            $lastSignInDate = "Never (or beyond retention period)"
          }
        } else {
          # Treat as inactive if we can't determine sign-in history
          $isInactive = $true
          $daysSinceLastSignIn = "Unknown"
          $lastSignInDate = "Never (or beyond retention period)"
        }
      }

      # Add to inactive users list if criteria met
      if ($isInactive) {
        $inactiveUser = [PSCustomObject]@{
          DisplayName = $user.DisplayName
          UserPrincipalName = $user.UserPrincipalName
          AccountEnabled = $user.AccountEnabled
          UserType = $user.UserType
          Department = $user.Department
          JobTitle = $user.JobTitle
          CreatedDateTime = $user.CreatedDateTime
          LastSignInDate = $lastSignInDate
          DaysSinceLastSignIn = $daysSinceLastSignIn
          InactiveDays = $InactiveDays
          UserId = $user.Id
        }
        $inactiveUsers += $inactiveUser
      }
    }
    catch {
      Write-Warning "Error processing user $($user.UserPrincipalName): $($_.Exception.Message)"
    }
  }

  Write-Host "Analysis complete. Found $($inactiveUsers.Count) inactive users."

  # Export results
  $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
  $reportPath = Join-Path $OutputPath "InactiveUsers_${InactiveDays}days_$timestamp.csv"
  $recordCount = Export-IfAny -Data $inactiveUsers -Path $reportPath

  # Create summary report
  $summaryPath = Join-Path $OutputPath "InactiveUsers_Summary_$timestamp.txt"
  $summary = @(
    "Entra ID Inactive Users Report Summary",
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')",
    "Tenant ID: $TenantId",
    "",
    "Parameters:",
    "  - Inactive threshold: $InactiveDays days",
    "  - Include disabled users: $IncludeDisabledUsers",
    "",
    "Results:",
    "  - Total users analyzed: $($users.Count)",
    "  - Inactive users found: $recordCount",
    "  - Percentage inactive: $(if ($users.Count -gt 0) { [math]::Round(($recordCount / $users.Count) * 100, 2) } else { 0 })%",
    "",
    "Note: Sign-in logs have limited retention (typically 30 days).",
    "Users with no recent sign-in data are evaluated based on account creation date.",
    "",
    "Output file: $reportPath"
  )
  
  $summary -join "`r`n" | Out-File -FilePath $summaryPath -Encoding UTF8
  Write-Host "Summary saved: $summaryPath"

  Write-Host ""
  Write-Host "Report completed successfully!" -ForegroundColor Green
  Write-Host "Inactive users found: $recordCount" -ForegroundColor Yellow
  Write-Host "Report location: $reportPath" -ForegroundColor Cyan

}
catch {
  Write-Error "Script failed: $($_.Exception.Message)"
  Write-Error $_.ScriptStackTrace
  exit 1
}
finally {
  # Disconnect from Microsoft Graph
  try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disconnected from Microsoft Graph"
  }
  catch {
    # Ignore disconnect errors
  }
}