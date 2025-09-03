<#
.SYNOPSIS
    Install Required PowerShell Modules for Security Report Automation

.DESCRIPTION
    This script installs all required PowerShell modules for both Exchange Online 
    and Entra ID security reporting automation.

.PARAMETER Scope
    Installation scope: CurrentUser or AllUsers (default: CurrentUser)

.PARAMETER Force
    Force reinstallation of modules even if they already exist

.EXAMPLE
    .\Install-Modules.ps1

.EXAMPLE  
    .\Install-Modules.ps1 -Scope AllUsers -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('CurrentUser','AllUsers')]
    [string]$Scope = 'CurrentUser',
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

Write-Host "Installing PowerShell modules for Security Report Automation..." -ForegroundColor Green
Write-Host "Scope: $Scope" -ForegroundColor Cyan

# Set PowerShell Gallery as trusted
Write-Host "`nConfiguring PowerShell Gallery..." -ForegroundColor Yellow
if (-not (Get-PSRepository -Name PSGallery | Where-Object {$_.InstallationPolicy -eq 'Trusted'})) {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Write-Host "✓ PowerShell Gallery set as trusted" -ForegroundColor Green
}

# Exchange Online Modules
Write-Host "`nInstalling Exchange Online modules..." -ForegroundColor Yellow
$exchangeModules = @(
    'ExchangeOnlineManagement'
)

foreach ($module in $exchangeModules) {
    try {
        if ($Force -or -not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module..." -ForegroundColor Cyan
            Install-Module -Name $module -Scope $Scope -Force:$Force -AllowClobber
            Write-Host "✓ $module installed successfully" -ForegroundColor Green
        } else {
            Write-Host "✓ $module already installed" -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Failed to install $module : $_"
    }
}

# Microsoft Graph Modules for Entra ID
Write-Host "`nInstalling Microsoft Graph modules..." -ForegroundColor Yellow
$graphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Mail',
    'Microsoft.Graph.Reports'  # Optional, for additional insights
)

foreach ($module in $graphModules) {
    try {
        if ($Force -or -not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing $module..." -ForegroundColor Cyan
            Install-Module -Name $module -Scope $Scope -Force:$Force -AllowClobber
            Write-Host "✓ $module installed successfully" -ForegroundColor Green
        } else {
            Write-Host "✓ $module already installed" -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Failed to install $module : $_"
    }
}

# Verify installations
Write-Host "`nVerifying module installations..." -ForegroundColor Yellow

$allModules = $exchangeModules + $graphModules
$installed = @()
$failed = @()

foreach ($module in $allModules) {
    $moduleInfo = Get-Module -ListAvailable -Name $module | Select-Object -First 1
    if ($moduleInfo) {
        $installed += "$module (v$($moduleInfo.Version))"
        Write-Host "✓ $module v$($moduleInfo.Version)" -ForegroundColor Green
    } else {
        $failed += $module
        Write-Host "✗ $module - NOT FOUND" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "INSTALLATION SUMMARY" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

Write-Host "`nSuccessfully installed modules:" -ForegroundColor Green
$installed | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor Green }

if ($failed.Count -gt 0) {
    Write-Host "`nFailed to install:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  ✗ $_" -ForegroundColor Red }
    Write-Host "`nPlease check your internet connection and permissions." -ForegroundColor Yellow
} else {
    Write-Host "`n🎉 All modules installed successfully!" -ForegroundColor Green
    Write-Host "`nYou can now run the security report scripts:" -ForegroundColor Cyan
    Write-Host "  • Exchange Online: .\ExO-SecurityReport.ps1" -ForegroundColor White
    Write-Host "  • Entra ID Users:  .\Get-EntraIdInactiveUsers.ps1" -ForegroundColor White
    Write-Host "  • Azure Automation: .\Azure-Automation-EntraId-InactiveUsers.ps1" -ForegroundColor White
}

Write-Host "`nFor help and examples, see:" -ForegroundColor Cyan
Write-Host "  • README.md" -ForegroundColor White
Write-Host "  • ENTRA-ID-INACTIVE-USERS.md" -ForegroundColor White
Write-Host "  • config-example.ps1" -ForegroundColor White