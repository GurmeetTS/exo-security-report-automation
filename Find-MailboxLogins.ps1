<#
.SYNOPSIS
  Audits mailbox login events for a pre-defined list of mailboxes in Exchange Online.

.DESCRIPTION
  This script connects to Exchange Online and uses the Search-MailboxAuditLog cmdlet
  to find login events for a hardcoded list of mailboxes. The results are exported to a CSV file.
  The script is pre-configured for the 'newvision-software.com' organization.

.PARAMETER AuthMode
  The authentication mode. Can be 'Interactive' or 'AppOnly'. Defaults to 'Interactive'.

.PARAMETER AppId
  The Application ID for app-only authentication.

.PARAMETER CertificateThumbprint
  The certificate thumbprint for app-only authentication.

.PARAMETER OutputPath
  The directory where the CSV report will be saved.

.EXAMPLE
  .\Find-MailboxLogins.ps1 -OutputPath .\output

.EXAMPLE
  .\Find-MailboxLogins.ps1 -AuthMode AppOnly -AppId <appId> -CertificateThumbprint <thumb> -OutputPath .\output
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [ValidateSet('Interactive','AppOnly')]
  [string]$AuthMode = 'Interactive',

  [Parameter(Mandatory=$false)]
  [string]$AppId,

  [Parameter(Mandatory=$false)]
  [string]$CertificateThumbprint,

  [Parameter(Mandatory=$false)]
  [string]$OutputPath = ".\output"
)

# --- Configuration ---
$Mailboxes = @(
    "notification@newvision-software.com",
    "finance_team@newvision-software.com",
    "newvision.accountspayable@newvision-software.com",
    "nv_ads@newvision-software.com",
    "analytics.testing@newvision-software.com",
    "deloitte_pmo@newvision-software.com",
    "trainings@newvision-software.com",
    "Adobe@newvision-software.com",
    "legal@newvision-software.com",
    "NVLeadershipdevelopment@newvision-software.com"
)
$Organization = "newvision-software.com"
# ---------------------

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Verbose "Installing module: $Name"
    Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
  }
  Import-Module $Name -Force -ErrorAction Stop
}

function Connect-ExO {
  if ($AuthMode -eq 'AppOnly') {
    if (-not $AppId -or -not $CertificateThumbprint) {
      throw "AppOnly requires -AppId and -CertificateThumbprint."
    }
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ShowBanner:$false
  } else {
    Connect-ExchangeOnline -Organization $Organization -ShowBanner:$false -UseRPSSecurityContext
  }
}

# Main
$ErrorActionPreference = 'Stop'
Ensure-Module -Name ExchangeOnlineManagement

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

try {
  Connect-ExO
  Write-Host "Successfully connected to Exchange Online."

  $allLogins = @()
  $startDate = (Get-Date).AddDays(-90)
  $endDate = Get-Date

  foreach ($mailbox in $Mailboxes) {
    Write-Host "Auditing mailbox: $mailbox"
    $logins = Search-MailboxAuditLog -Identity $mailbox -LogonTypes Owner, Delegate, Admin -ShowDetails -StartDate $startDate -EndDate $endDate
    $allLogins += $logins | Select-Object @{Name='Mailbox';Expression={$mailbox}},*
  }

  if ($allLogins.Count -gt 0) {
    $csvPath = Join-Path $OutputPath "MailboxLogins.csv"
    $allLogins | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Successfully exported login report to: $csvPath"
  } else {
    Write-Host "No login events found for the specified mailboxes in the last 90 days."
  }
}
catch {
  Write-Error $_
}
finally {
  Write-Host "Disconnecting from Exchange Online."
  Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
