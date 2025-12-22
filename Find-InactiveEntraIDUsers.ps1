<#
.SYNOPSIS
  Finds inactive Entra ID users.

.DESCRIPTION
  Retrieves a list of users who have not signed in for a specified number of days.
  Requires the Microsoft.Graph.Users module.

.EXAMPLE
  .\Find-InactiveEntraIDUsers.ps1 -InactiveDays 90 -OutputPath .\output

#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$Organization,

  [Parameter(Mandatory=$false)]
  [ValidateSet('Interactive','AppOnly')]
  [string]$AuthMode = 'Interactive',

  [Parameter(Mandatory=$false)]
  [string]$AppId,

  [Parameter(Mandatory=$false)]
  [string]$CertificateThumbprint,

  [Parameter(Mandatory=$true)]
  [int]$InactiveDays,

  [Parameter(Mandatory=$false)]
  [string]$OutputPath = "$(Join-Path (Split-Path -Parent $PSCommandPath) '.\output')"
)

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Write-Verbose "Installing module: $Name"
    Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
  }
  Import-Module $Name -Force -ErrorAction Stop
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
      Write-Host "No inactive users found."
    }
  }
}

function Connect-Graph {
  if ($AuthMode -eq 'AppOnly') {
    if (-not $AppId -or -not $CertificateThumbprint -or -not $Organization) {
      throw "AppOnly requires -AppId, -CertificateThumbprint, and -Organization."
    }
    Connect-MgGraph -AppId $AppId -CertificateThumbprint $CertificateThumbprint -TenantId $Organization
  } else {
    $scopes = "User.Read.All", "AuditLog.Read.All", "Directory.Read.All"
    if ($Organization) {
        Connect-MgGraph -TenantId $Organization -Scopes $scopes
    } else {
        Connect-MgGraph -Scopes $scopes
    }
  }
}

# Main
$ErrorActionPreference = 'Stop'
Ensure-Module -Name Microsoft.Graph.Authentication
Ensure-Module -Name Microsoft.Graph.Users
Ensure-Module -Name Microsoft.Graph.Identity.DirectoryManagement

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

try {
  Connect-Graph

  Write-Host "Building license SKU lookup table..."
  $skuLookup = @{}
  Get-MgSubscribedSku -All | ForEach-Object { $skuLookup[$_.SkuId] = $_.SkuPartNumber }

  Write-Host "Finding users inactive for more than $InactiveDays days..."
  $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
  $inactiveUsers = Get-MgUser -All -Filter "userType eq 'Member' and accountEnabled eq true" -Property "displayName,userPrincipalName,signInActivity,userType,accountEnabled,assignedLicenses,department" | Where-Object {
    $_.SignInActivity.LastSignInDateTime -eq $null -or $_.SignInActivity.LastSignInDateTime -lt $cutoffDate
  } | Select-Object UserPrincipalName, DisplayName, Department, @{Name="LastSignInDateTime"; Expression={$_.SignInActivity.LastSignInDateTime}}, @{Name="Licenses"; Expression={($_.AssignedLicenses.SkuId | ForEach-Object { $skuLookup[$_] }) -join '; '}}

  $fileName = "InactiveUsers-$($Organization)_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
  $filePath = Join-Path $OutputPath $fileName
  Export-IfAny -Data $inactiveUsers -Path $filePath
}
catch {
  Write-Error $_
}
finally {
  Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
