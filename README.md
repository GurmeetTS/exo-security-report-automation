# Microsoft 365 Security Report Automation

Automate comprehensive security reports for **Microsoft 365** services using **PowerShell** with optional **app-only** authentication. Includes Exchange Online security posture and Entra ID inactive users reporting.

## 📊 Available Reports

### 1. Exchange Online Security Report (`ExO-SecurityReport.ps1`)
Automate a comprehensive **Exchange Online security posture** report using **PowerShell** (Exchange Online PowerShell module) with optional **app-only** authentication. Output includes CSVs and a Markdown/HTML summary you can share with stakeholders.

### 2. Entra ID Inactive Users Report (`EntraID-InactiveUsers.ps1`)
Generate reports of users in **Entra ID** who have been inactive for more than a specified number of days (default: 90 days). Perfect for identifying unused accounts and maintaining security hygiene.

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

## ✨ What Entra ID Inactive Users report captures
- **User account status**: Enabled/disabled users with last sign-in dates
- **Inactive period analysis**: Users who haven't signed in for X days (configurable, default 90 days)
- **Account details**: Display name, UPN, department, job title, creation date
- **Comprehensive coverage**: Supports both enabled and disabled user accounts
- **Export formats**: CSV reports with summary statistics
- **Azure Automation ready**: Designed for unattended execution in Azure Automation

> **Note**: Sign-in logs have limited retention (typically 30 days). Users with no recent sign-in data are evaluated based on account creation date.

---

## 🧰 Prerequisites

### Exchange Online Security Report
- PowerShell 7.x or Windows PowerShell 5.1
- Exchange Online PowerShell module:  
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- For **app-only** auth (optional, recommended for automation):
  - App registration with **Application permission**: `Exchange.ManageAsApp`
  - A certificate (thumbprint on the runner/host), and **Application Access Policy** if you want to scope access

### Entra ID Inactive Users Report
- PowerShell 7.x or Windows PowerShell 5.1
- Microsoft Graph PowerShell modules:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -Scope CurrentUser
  Install-Module Microsoft.Graph.Reports -Scope CurrentUser
  ```
- For **app-only** auth (recommended for automation):
  - App registration with **Application permissions**: `User.Read.All`, `AuditLog.Read.All`
  - A certificate (thumbprint on the runner/host)
  - Admin consent granted for the application permissions

---

## 🚀 Quick Start

### Exchange Online Security Report (interactive sign-in)

```powershell
# Clone or download this repo
cd .\Microsoft-365-Security-Automation\

# Run Exchange Online security report interactively
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath .\output
```

### Entra ID Inactive Users Report (interactive sign-in)

```powershell
# Run Entra ID inactive users report interactively
.\EntraID-InactiveUsers.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\output

# Custom inactive period (60 days) and include disabled users
.\EntraID-InactiveUsers.ps1 -TenantId contoso.onmicrosoft.com -InactiveDays 60 -IncludeDisabledUsers -OutputPath .\output
```

Outputs will be in `./output` directory with timestamped CSV files and summary reports.

---

## 🔒 App-only (certificate) authentication

### Exchange Online Security Report
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

### Entra ID Inactive Users Report
1) Register an app and grant **Application** API permissions: `User.Read.All`, `AuditLog.Read.All`
2) Grant admin consent for the application permissions
3) Upload a certificate to the app. Install the same cert on the machine that runs the job.
4) Run:
```powershell
$AppId = "<your-app-id>"
$Thumb = "<your-cert-thumbprint>"
$TenantId = "contoso.onmicrosoft.com"

.\EntraID-InactiveUsers.ps1 -TenantId $TenantId -AuthMode AppOnly -AppId $AppId -CertificateThumbprint $Thumb -OutputPath .\output
```

---

## 📅 Schedule it

### Option A: **Azure Automation**

#### Exchange Online Security Reports
- Import `ExchangeOnlineManagement` module in your Automation Account
- Create a **Run As / Managed Identity**? For EXO app-only, import your **certificate** as an Automation certificate asset
- Create a **PowerShell Runbook**, paste the script, configure variables (AppId, Thumbprint, Org), and **schedule** (e.g., weekly)

#### Entra ID Inactive Users Reports  
- Import required modules in your Automation Account:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Reports`
- For app-only authentication, import your **certificate** as an Automation certificate asset
- Use the provided example runbook: `AzureAutomation-InactiveUsersRunbook.ps1`
- Configure Automation Variables:
  - `TenantId`: Your Entra ID tenant ID
  - `AppId`: Your app registration ID
  - `CertificateThumbprint`: Certificate thumbprint
  - Optional: Storage account variables for automated report upload
- **Schedule** the runbook (e.g., monthly for inactive user reports)

### Option B: **GitHub Actions** (sample workflow included)
Store these repository **secrets**:
- `EXO_APP_ID`
- `EXO_ORG`
- `EXO_CERT_PFX_BASE64` (base64-encoded PFX content)
- `EXO_CERT_PASSWORD` (PFX password)

The sample workflow imports the cert, runs the script, and uploads artifacts.

---

## 🗂 Output

### Exchange Online Security Report Output
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

### Entra ID Inactive Users Report Output
- `InactiveUsers_[X]days_[timestamp].csv` - Detailed list of inactive users
- `InactiveUsers_Summary_[timestamp].txt` - Summary statistics and report metadata

Each inactive users CSV contains:
- DisplayName, UserPrincipalName, AccountEnabled
- UserType, Department, JobTitle
- CreatedDateTime, LastSignInDate, DaysSinceLastSignIn
- InactiveDays threshold used, UserId

---

## 🧪 Test locally

### Exchange Online Security Report
```powershell
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath .\output
Start "" .\output
```

### Entra ID Inactive Users Report
```powershell
.\EntraID-InactiveUsers.ps1 -TenantId contoso.onmicrosoft.com -OutputPath .\output -Verbose
Start "" .\output
```

---

## 🪪 License

[MIT](./LICENSE)

---

## 🙌 Credits & Contributions

PRs welcome! Add new checks (e.g., connectors, quarantine policies, outbound spam prefs, conditional access policies, privileged access reviews), improve the summary, or wire up Teams/Email notifications.
