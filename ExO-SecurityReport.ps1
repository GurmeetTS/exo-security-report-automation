<#
.SYNOPSIS
  Exchange Online Security Report Automation

.DESCRIPTION
  Generates CSVs and a Markdown/HTML summary for key Exchange Online security configuration areas.
  Supports interactive and app-only (certificate) authentication.

.EXAMPLE
  .\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath .\output

.EXAMPLE
  .\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -AuthMode AppOnly -AppId <appId> -CertificateThumbprint <thumb> -OutputPath .\output

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Organization,

  [Parameter(Mandatory=$false)]
  [ValidateSet('Interactive','AppOnly')]
  [string]$AuthMode = 'Interactive',

  [Parameter(Mandatory=$false)]
  [string]$AppId,

  [Parameter(Mandatory=$false)]
  [string]$CertificateThumbprint,

  [Parameter(Mandatory=$false)]
  [string]$OutputPath = "$(Join-Path (Split-Path -Parent $PSCommandPath) '..\output')",

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

function Connect-ExO {
  if ($AuthMode -eq 'AppOnly') {
    if (-not $AppId -or -not $CertificateThumbprint) {
      throw "AppOnly requires -AppId and -CertificateThumbprint."
    }
    Connect-ExchangeOnline -AppId $AppId -CertificateThumbprint $CertificateThumbprint -Organization $Organization -ShowBanner:$false
  } else {
    Connect-ExchangeOnline -Organization $Organization -ShowBanner:$false
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

function Get-IfCmdlet {
  param([string]$Name)
  if (Get-Command -Name $Name -ErrorAction SilentlyContinue) {
    return Invoke-Expression $Name
  } else {
    Write-Verbose "Cmdlet not found: $Name (skipping)"
    return @()
  }
}

# Main
$ErrorActionPreference = 'Stop'
Ensure-Module -Name ExchangeOnlineManagement

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

try {
  Connect-ExO

  # Organization & auth policies
  $orgCfg = Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled,SCLJunkThreshold,AuditDisabled,DisplaySenderNameForExternalMessages,IsPlusAddressingEnabled,OutlookExternalTagsEnabled,DefaultAuthenticationPolicy
  Export-IfAny -Data $orgCfg -Path (Join-Path $OutputPath "OrgConfig.csv")

  $authPolicies = Get-AuthenticationPolicy | Select-Object Name,Default,AllowBasicAuthActiveSync,AllowBasicAuthImap,AllowBasicAuthSmtp,AllowBasicAuthPop,AllowBasicAuthWebServices,AllowBasicAuthAutodiscover,AllowBasicAuthOutlookService,AllowBasicAuthPowerShell
  Export-IfAny -Data $authPolicies -Path (Join-Path $OutputPath "AuthPolicies.csv")

  # Anti-spam & malware
  $hcfp = Get-HostedContentFilterPolicy | Select-Object Name,BulkThreshold,SpamAction,HighConfidenceSpamAction,PhishSpamAction,InlineSafetyTipsEnabled,MarkAsSpamBulkMail
  Export-IfAny -Data $hcfp -Path (Join-Path $OutputPath "AntiSpamPolicies.csv")

  $hcfr = Get-HostedContentFilterRule | Select-Object Name,Priority,Enabled,SentTo,ExceptIfSentTo,RecipientDomainIs
  Export-IfAny -Data $hcfr -Path (Join-Path $OutputPath "AntiSpamRules.csv")

  $mfp = Get-MalwareFilterPolicy | Select-Object Name,Action,EnableInternalSenderNotifications,EnableExternalSenderNotifications,EnableRecipientNotifications,AdminDisplayName
  Export-IfAny -Data $mfp -Path (Join-Path $OutputPath "MalwarePolicies.csv")

  $mfr = Get-MalwareFilterRule | Select-Object Name,Priority,Enabled,SentTo,ExceptIfSentTo,RecipientDomainIs
  Export-IfAny -Data $mfr -Path (Join-Path $OutputPath "MalwareRules.csv")

  # Advanced protection (if available)
  $slp = @()
  if (Get-Command Get-SafeLinksPolicy -ErrorAction SilentlyContinue) {
    $slp = Get-SafeLinksPolicy | Select-Object Name,EnableSafeLinksForEmail,ScanUrls,TrackClicks,EnableForInternalSenders
    Export-IfAny -Data $slp -Path (Join-Path $OutputPath "SafeLinksPolicies.csv")
  }
  $slr = @()
  if (Get-Command Get-SafeLinksRule -ErrorAction SilentlyContinue) {
    $slr = Get-SafeLinksRule | Select-Object Name,Priority,Enabled,RecipientDomainIs,SentTo,ExceptIfRecipientDomainIs
    Export-IfAny -Data $slr -Path (Join-Path $OutputPath "SafeLinksRules.csv")
  }

  $sap = @()
  if (Get-Command Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue) {
    $sap = Get-SafeAttachmentPolicy | Select-Object Name,Action,Enable,Sensitivity
    Export-IfAny -Data $sap -Path (Join-Path $OutputPath "SafeAttachmentsPolicies.csv")
  }
  $sar = @()
  if (Get-Command Get-SafeAttachmentRule -ErrorAction SilentlyContinue) {
    $sar = Get-SafeAttachmentRule | Select-Object Name,Priority,Enabled,RecipientDomainIs,SentTo
    Export-IfAny -Data $sar -Path (Join-Path $OutputPath "SafeAttachmentsRules.csv")
  }

  # Transport rules
  $tr = Get-TransportRule | Select-Object Name,Priority,Mode,State,Comments,CreatedBy,LastModifiedTime
  Export-IfAny -Data $tr -Path (Join-Path $OutputPath "TransportRules.csv")

  # Accepted domains & DKIM
  $domains = Get-AcceptedDomain | Select-Object DomainName,DomainType,Default,InitialDomain
  Export-IfAny -Data $domains -Path (Join-Path $OutputPath "AcceptedDomains.csv")

  $dkim = @()
  if (Get-Command Get-DkimSigningConfig -ErrorAction SilentlyContinue) {
    $dkim = Get-DkimSigningConfig | Select-Object Domain,Enabled,KeySize,RotateOnDate,RotateOnImport
    Export-IfAny -Data $dkim -Path (Join-Path $OutputPath "DkimConfigs.csv")
  }

  # Remote domains (auto-forwarding stance)
  $rd = Get-RemoteDomain | Select-Object DomainName,AutoForwardEnabled,AllowedOOFType,TrustedMailOutboundEnabled
  Export-IfAny -Data $rd -Path (Join-Path $OutputPath "RemoteDomains.csv")

  # External tagging (try cmdlet if exists)
  $externalTag = @()
  if (Get-Command Get-ExternalInOutlook -ErrorAction SilentlyContinue) {
    $externalTag = Get-ExternalInOutlook | Select-Object Identity,Enabled
  }

  # Build summary (Markdown)
  $md = @()
  $md += "# Exchange Online Security Summary"
  $md += ""
  $md += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
  $md += ""
  $md += "## Authentication"
  $defaultAuth = $orgCfg.DefaultAuthenticationPolicy
  $basicOpen = ($authPolicies | ForEach-Object {
    $_.psobject.Properties.Name | Out-Null
    [PSCustomObject]@{
      Name = $_.Name
      AnyBasicAllowed = @(
        $_.AllowBasicAuthActiveSync,
        $_.AllowBasicAuthImap,
        $_.AllowBasicAuthSmtp,
        $_.AllowBasicAuthPop,
        $_.AllowBasicAuthWebServices,
        $_.AllowBasicAuthAutodiscover,
        $_.AllowBasicAuthOutlookService,
        $_.AllowBasicAuthPowerShell
      ) -contains $true
    }
  }) | Where-Object { $_.AnyBasicAllowed -eq $true }
  $md += "- Default Authentication Policy: **$defaultAuth**"
  $md += "- Policies allowing any Basic Auth: **$($basicOpen.Count)**"

  $md += ""
  $md += "## Anti-Spam & Anti-Malware"
  $md += "- Content filter policies: **$($hcfp.Count)**"
  $md += "- Malware filter policies: **$($mfp.Count)**"

  if ($slp -and $slp.Count -gt 0) {
    $md += ""
    $md += "## Defender for O365 (Advanced Threat Protection)"
    $md += "- Safe Links policies: **$($slp.Count)**"
    $md += "- Safe Attachments policies: **$($sap.Count)**"
  }

  $md += ""
  $md += "## Transport Rules"
  $md += "- Total transport rules: **$($tr.Count)**"

  $md += ""
  $md += "## Domains & DKIM"
  $enabledDkim = ($dkim | Where-Object {$_.Enabled -eq $true}).Count
  $md += "- Accepted domains: **$($domains.Count)**"
  if ($dkim) { $md += "- DKIM enabled domains: **$enabledDkim**" }

  $md += ""
  $md += "## Auto-forwarding stance"
  $fwdAllowed = ($rd | Where-Object {$_.AutoForwardEnabled -eq $true}).Count
  $md += "- Remote domains allowing auto-forward: **$fwdAllowed**"

  if ($externalTag) {
    $md += ""
    $md += "## External Tagging"
    $extEnabled = ($externalTag | Where-Object {$_.Enabled -eq $true}).Count -gt 0
    $md += "- External sender tag enabled: **$extEnabled**"
  }

  $mdPath = Join-Path $OutputPath "SecuritySummary.md"
  $md -join "`r`n" | Out-File -FilePath $mdPath -Encoding UTF8
  Write-Host "Saved: $mdPath"

  if (-not $SkipHtml) {
    $html = Get-Content $mdPath -Raw | ConvertTo-Html -Title "Exchange Online Security Summary"
    $htmlPath = Join-Path $OutputPath "SecuritySummary.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "Saved: $htmlPath"
  }

}
catch {
  Write-Error $_
}
finally {
  Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
