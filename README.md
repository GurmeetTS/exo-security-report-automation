# Security Report Automation Suite

Automate comprehensive security reports for **Exchange Online** and **Entra ID (Azure AD)** using **PowerShell** with optional **app-only** authentication. Output includes CSVs and Markdown/HTML summaries you can share with stakeholders.

## 📊 Available Reports

### 1. Exchange Online Security Report
Automate a comprehensive **Exchange Online security posture** report using **PowerShell** (Exchange Online PowerShell module) with optional **app-only** authentication.

### 2. Entra ID Inactive Users Report ✨ NEW
Generate reports of **inactive users in Entra ID** who haven't signed in for 90+ days. Perfect for **Azure Automation** with email notifications to improve security posture.

## ✨ What Exchange Online report captures
- **Authentication & legacy protocols**: Authentication Policies, Basic Auth blocks
- **Organization hygiene**: Org config highlights, SCL junk threshold, external tagging (if enabled)
- **Anti-spam & anti-malware**: Hosted Content Filter (EOP), Malware Filter policies & rules
- **Advanced protection** *(if licensed)*: Safe Links & Safe Attachments policies & rules
- **Transport rules (mail flow)**: Names, mode, priorities, conditions
- **Domains & DKIM**: Accepted domains and DKIM configs
- **Auto-forwarding stance**: Remote Domains (auto-forward enablement)
- **Summary**: One-page Markdown + HTML roll‑up

> **Note**: The script is defensive—if a cmdlet is unavailable in your tenant/licensing, it skips gracefully and logs a note.

## ✨ What Entra ID report captures
- **User Activity Analysis**: Users inactive for 90+ days (configurable)
- **Account Status**: Enabled vs disabled accounts with activity data  
- **Sign-in History**: Last interactive and non-interactive sign-in dates
- **Security Insights**: Never signed-in accounts and long-term inactive users
- **Email Reports**: Automated notifications with actionable recommendations
- **Azure Automation**: Ready-to-use runbook with Managed Identity support

> **Note**: Requires **Entra ID Premium P1/P2** for complete sign-in activity data. Free tier has limited retention.

---

## 🧰 Prerequisites

### Exchange Online Reports
- PowerShell 7.x or Windows PowerShell 5.1
- Exchange Online PowerShell module:  
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- For **app-only** auth (optional, recommended for automation):
  - App registration with **Application permission**: `Exchange.ManageAsApp`
  - A certificate (thumbprint on the runner/host), and **Application Access Policy** if you want to scope access

### Entra ID Reports
- PowerShell 7.x or Windows PowerShell 5.1
- Microsoft Graph PowerShell modules:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -Scope CurrentUser  
  Install-Module Microsoft.Graph.Mail -Scope CurrentUser
  ```
- For **app-only** auth (recommended for automation):
  - App registration with **Application permissions**: `User.Read.All`, `AuditLog.Read.All`, `Mail.Send`
  - A certificate or client secret for authentication

---

## 🚀 Quick Start

### Exchange Online Security Report (interactive sign-in)

```powershell
# Clone or download this repo
cd .\exo-security-report-automation

# Run Exchange Online report interactively
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath .\output
```

### Entra ID Inactive Users Report (interactive sign-in)

```powershell
# Run Entra ID inactive users report
.\Get-EntraIdInactiveUsers.ps1 -TenantId "your-tenant-id"

# With email notification
.\Get-EntraIdInactiveUsers.ps1 -TenantId "your-tenant-id" -SendEmail -EmailTo "admin@yourcompany.com"
```

Outputs will be in `./output` (CSVs + `SecuritySummary.md` + `SecuritySummary.html`).

---

## 🔒 App-only (certificate) authentication

### Exchange Online
1) Register an app and grant **Application** API permission: `Exchange.ManageAsApp`  
2) Upload a certificate to the app. Install the same cert on the machine that runs the job.  
3) (Optional) Add an **Application Access Policy** to scope mailbox access.  
4) Run:
```powershell
$AppId = "<your-app-id>"
$Thumb = "<your-cert-thumbprint>"
$Org   = "contoso.onmicrosoft.com"

.\ExO-SecurityReport.ps1 -Organization $Org -AuthMode AppOnly -AppId $AppId -CertificateThumbprint $Thumb -OutputPath .\output
```

### Entra ID  
1) Register an app and grant **Application** API permissions: `User.Read.All`, `AuditLog.Read.All`, `Mail.Send`
2) Upload a certificate to the app. Install the same cert on the machine that runs the job.
3) Run:
```powershell
$AppId = "<your-app-id>"
$Thumb = "<your-cert-thumbprint>"
$TenantId = "your-tenant-id"

.\Get-EntraIdInactiveUsers.ps1 -TenantId $TenantId -AuthMode AppOnly -AppId $AppId -CertificateThumbprint $Thumb -SendEmail -EmailTo "admin@yourcompany.com"
```

---

## 📅 Schedule it

### Option A: **Azure Automation**

#### Exchange Online Reports
- Import `ExchangeOnlineManagement` module in your Automation Account
- Create a **Run As / Managed Identity**? For EXO app-only, import your **certificate** as an Automation certificate asset
- Create a **PowerShell Runbook**, paste the script, configure variables (AppId, Thumbprint, Org), and **schedule** (e.g., weekly)

#### Entra ID Reports ⭐ **RECOMMENDED FOR INACTIVE USERS**
- Import Microsoft Graph modules (`Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Mail`) in your Automation Account
- Enable **Managed Identity** on your Automation Account
- Grant Microsoft Graph permissions to the Managed Identity (`User.Read.All`, `AuditLog.Read.All`, `Mail.Send`)
- Create a **PowerShell Runbook** using `Azure-Automation-EntraId-InactiveUsers.ps1`
- Configure variables: `TenantId`, `EmailTo`, `DaysInactive` (optional)
- **Schedule** the runbook (e.g., weekly/monthly)

**For NewVision Software Pvt.Ltd.:**
```powershell
# Example Azure Automation variables:
TenantId = "ff00942c-81e2-4530-b90f-4e7d35c20644"
EmailTo = "gurmeet.kohli@newvision-software.com"  
DaysInactive = 90
```

### Option B: **GitHub Actions** (sample workflow included)
Store these repository **secrets**:
- `EXO_APP_ID`
- `EXO_ORG`
- `EXO_CERT_PFX_BASE64` (base64-encoded PFX content)
- `EXO_CERT_PASSWORD` (PFX password)

The sample workflow imports the cert, runs the script, and uploads artifacts.

---

## 🗂 Output

### Exchange Online Security Report
- `AntiSpamPolicies.csv`
- `AntiSpamRules.csv`
- `MalwarePolicies.csv`
- `MalwareRules.csv`
- `SafeLinksPolicies.csv` *(if available)*
- `SafeLinksRules.csv` *(if available)*
- `SafeAttachmentsPolicies.csv` *(if available)*
- `SafeAttachmentsRules.csv` *(if available)*
- `TransportRules.csv`
- `AcceptedDomains.csv`
- `DkimConfigs.csv`
- `RemoteDomains.csv`
- `AuthPolicies.csv`
- `OrgConfig.csv`
- `SecuritySummary.md`
- `SecuritySummary.html`

### Entra ID Inactive Users Report
- `InactiveUsers_YYYYMMDD_HHMMSS.csv` - List of users inactive 90+ days
- `AllUsersActivity_YYYYMMDD_HHMMSS.csv` - Complete user activity report
- `InactiveUsersSummary_YYYYMMDD_HHMMSS.md` - Markdown summary with recommendations
- `InactiveUsersSummary_YYYYMMDD_HHMMSS.html` - HTML summary for easy sharing
- **Email Report** - Professional HTML email with summary and top inactive users

---

## 🧪 Test locally

### Exchange Online
```powershell
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath .\output -WhatIf:$false
Start "" .\output
```

### Entra ID Inactive Users  
```powershell
# Test with NewVision Software tenant
.\Get-EntraIdInactiveUsers.ps1 -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" -OutputPath .\output
Start "" .\output

# Test Azure Automation runbook locally (simulate)
.\Azure-Automation-EntraId-InactiveUsers.ps1 -TenantId "ff00942c-81e2-4530-b90f-4e7d35c20644" -EmailTo "gurmeet.kohli@newvision-software.com"
```

---

## 🪪 License

[MIT](./LICENSE)

---

## 🙌 Credits & Contributions

PRs welcome! Add new checks (e.g., connectors, quarantine policies, outbound spam prefs), improve the summary, or wire up Teams/Email notifications.

### Recent Additions
- ✅ **Entra ID Inactive Users Report** - Complete solution for identifying and reporting on inactive user accounts
- ✅ **Azure Automation Integration** - Ready-to-use runbook with Managed Identity support  
- ✅ **Email Automation** - Professional HTML email reports with actionable insights

### Roadmap Ideas
- Conditional Access policy reporting
- Multi-tenant support  
- Teams notifications
- Power BI dashboard integration
- Integration with Azure Sentinel
