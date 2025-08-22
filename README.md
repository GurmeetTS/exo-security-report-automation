# Exchange Online Security Report Automation

Automate a comprehensive **Exchange Online security posture** report using **PowerShell** (Exchange Online PowerShell module) with optional **app-only** authentication. Output includes CSVs and a Markdown/HTML summary you can share with stakeholders.

## ✨ What it captures
- **Authentication & legacy protocols**: Authentication Policies, Basic Auth blocks
- **Organization hygiene**: Org config highlights, SCL junk threshold, external tagging (if enabled)
- **Anti-spam & anti-malware**: Hosted Content Filter (EOP), Malware Filter policies & rules
- **Advanced protection** *(if licensed)*: Safe Links & Safe Attachments policies & rules
- **Transport rules (mail flow)**: Names, mode, priorities, conditions
- **Domains & DKIM**: Accepted domains and DKIM configs
- **Auto-forwarding stance**: Remote Domains (auto-forward enablement)
- **Summary**: One-page Markdown + HTML roll‑up

> **Note**: The script is defensive—if a cmdlet is unavailable in your tenant/licensing, it skips gracefully and logs a note.

---

## 🧰 Prerequisites

- PowerShell 7.x or Windows PowerShell 5.1
- Exchange Online PowerShell module:  
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- For **app-only** auth (optional, recommended for automation):
  - App registration with **Application permission**: `Exchange.ManageAsApp`
  - A certificate (thumbprint on the runner/host), and **Application Access Policy** if you want to scope access

---

## 🚀 Quick Start (interactive sign-in)

```powershell
# Clone or download this repo
cd .\ExO-Security-Report-Automation\scripts

# Run interactively
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath ..\output
```

Outputs will be in `./output` (CSVs + `SecuritySummary.md` + `SecuritySummary.html`).

---

## 🔒 App-only (certificate) authentication

1) Register an app and grant **Application** API permission: `Exchange.ManageAsApp`  
2) Upload a certificate to the app. Install the same cert on the machine that runs the job.  
3) (Optional) Add an **Application Access Policy** to scope mailbox access.  
4) Run:
```powershell
$AppId = "<your-app-id>"
$Thumb = "<your-cert-thumbprint>"
$Org   = "contoso.onmicrosoft.com"

.\ExO-SecurityReport.ps1 -Organization $Org -AuthMode AppOnly -AppId $AppId -CertificateThumbprint $Thumb -OutputPath ..\output
```

---

## 📅 Schedule it

### Option A: **Azure Automation**
- Import `ExchangeOnlineManagement` module in your Automation Account
- Create a **Run As / Managed Identity**? For EXO app-only, import your **certificate** as an Automation certificate asset
- Create a **PowerShell Runbook**, paste the script, configure variables (AppId, Thumbprint, Org), and **schedule** (e.g., weekly)

### Option B: **GitHub Actions** (sample workflow included)
Store these repository **secrets**:
- `EXO_APP_ID`
- `EXO_ORG`
- `EXO_CERT_PFX_BASE64` (base64-encoded PFX content)
- `EXO_CERT_PASSWORD` (PFX password)

The sample workflow imports the cert, runs the script, and uploads artifacts.

---

## 🗂 Output

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

---

## 🧪 Test locally

```powershell
.\ExO-SecurityReport.ps1 -Organization contoso.onmicrosoft.com -OutputPath ..\output -WhatIf:$false
Start "" .\..\output
```

---

## 🪪 License

[MIT](./LICENSE)

---

## 🙌 Credits & Contributions

PRs welcome! Add new checks (e.g., connectors, quarantine policies, outbound spam prefs), improve the summary, or wire up Teams/Email notifications.
