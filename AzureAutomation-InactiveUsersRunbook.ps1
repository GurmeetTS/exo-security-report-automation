# Azure Automation Runbook Example for Entra ID Inactive Users Report
# This runbook demonstrates how to use the EntraID-InactiveUsers.ps1 script in Azure Automation

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId = (Get-AutomationVariable -Name "TenantId"),
    
    [Parameter(Mandatory=$false)]
    [string]$AppId = (Get-AutomationVariable -Name "AppId"),
    
    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint = (Get-AutomationVariable -Name "CertificateThumbprint"),
    
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeDisabledUsers = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName = (Get-AutomationVariable -Name "StorageAccountName"),
    
    [Parameter(Mandatory=$false)]
    [string]$StorageContainerName = (Get-AutomationVariable -Name "StorageContainerName")
)

# Import required modules (these should be imported in the Azure Automation Account)
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users  
Import-Module Microsoft.Graph.Reports
Import-Module Az.Storage

try {
    Write-Output "Starting Azure Automation runbook for Entra ID Inactive Users Report"
    Write-Output "Tenant ID: $TenantId"
    Write-Output "Inactive Days Threshold: $InactiveDays"
    Write-Output "Include Disabled Users: $IncludeDisabledUsers"
    
    # Set temporary output path
    $outputPath = $env:TEMP
    if (-not $outputPath) { $outputPath = "/tmp" }
    
    # Execute the inactive users script using app-only authentication
    & "$PSScriptRoot\EntraID-InactiveUsers.ps1" `
        -TenantId $TenantId `
        -AuthMode AppOnly `
        -AppId $AppId `
        -CertificateThumbprint $CertificateThumbprint `
        -InactiveDays $InactiveDays `
        -OutputPath $outputPath `
        -IncludeDisabledUsers:$IncludeDisabledUsers `
        -Verbose
    
    # Upload results to Azure Storage (optional)
    if ($StorageAccountName -and $StorageContainerName) {
        Write-Output "Uploading results to Azure Storage..."
        
        # Get storage account context using managed identity
        $ctx = (Get-AzStorageAccount -ResourceGroupName (Get-AutomationVariable -Name "ResourceGroupName") -Name $StorageAccountName).Context
        
        # Upload CSV files
        $csvFiles = Get-ChildItem -Path $outputPath -Filter "InactiveUsers_*.csv"
        foreach ($file in $csvFiles) {
            $blobName = "inactive-users-reports/$($file.Name)"
            Set-AzStorageBlobContent -File $file.FullName -Container $StorageContainerName -Blob $blobName -Context $ctx -Force
            Write-Output "Uploaded: $blobName"
        }
        
        # Upload summary files
        $summaryFiles = Get-ChildItem -Path $outputPath -Filter "InactiveUsers_Summary_*.txt"
        foreach ($file in $summaryFiles) {
            $blobName = "inactive-users-reports/$($file.Name)"
            Set-AzStorageBlobContent -File $file.FullName -Container $StorageContainerName -Blob $blobName -Context $ctx -Force
            Write-Output "Uploaded: $blobName"
        }
    }
    
    Write-Output "Runbook completed successfully"
}
catch {
    Write-Error "Runbook failed: $($_.Exception.Message)"
    throw
}
finally {
    # Clean up temporary files
    if (Test-Path $outputPath) {
        Get-ChildItem -Path $outputPath -Filter "InactiveUsers_*" | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}