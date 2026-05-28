# Falcon Cloud Risk Report — Setup & Usage Guide

Script: `cloud_risks_report_pdf.py`

Generates a PDF combining open high-severity cloud risks, Cloud IOA detections, and unmanaged running VMs from CrowdStrike Falcon Cloud Security.

---

## 1. Install Python

Requires **Python 3.8 or later**.

### macOS

```bash
# Option A — Homebrew (recommended)
brew install python

# Option B — download the installer
# https://www.python.org/downloads/macos/
```

Verify the installation:

```bash
python3 --version
```

### Windows

1. Download the installer from **https://www.python.org/downloads/windows/**
2. Run the installer and check **"Add Python to PATH"** before clicking Install
3. Verify in a new terminal:

```powershell
python --version
```

### Linux (Debian / Ubuntu)

```bash
sudo apt update && sudo apt install python3 python3-pip -y
python3 --version
```

---

## 2. Set Up a Virtual Environment

A virtual environment keeps the dependencies isolated from your system Python.

```bash
# Create the environment
python -m venv .venv
```

Activate it:

| Platform | Command |
|---|---|
| macOS / Linux | `source .venv/bin/activate` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |

You will see `(.venv)` in your prompt when it is active. You need to re-activate each time you open a new terminal.

---

## 3. Install Dependencies

With the virtual environment active:

```bash
pip install crowdstrike-falconpy python-dotenv fpdf2
```

| Package | Purpose |
|---|---|
| `crowdstrike-falconpy` | FalconPy SDK — wraps the CrowdStrike Falcon APIs |
| `python-dotenv` | Loads credentials from a `.env` file |
| `fpdf2` | PDF generation library |

---

## 4. Configure API Credentials

### 4a. Create a Falcon API Client

1. Log in to the Falcon console
2. Navigate to **Support & Resources → API Clients and Keys**
3. Click **Add new API client**
4. Give it a descriptive name (e.g. `Cloud Risk Report`)
5. Under **Scope**, enable the following permissions:

| Scope | Access | Used For |
|---|---|---|
| **CSPM Registration** | Read | Fetching open high-severity cloud risks |
| **Cloud Security Assets** | Read | Fetching unmanaged running VMs |
| **Alerts** | Read | Fetching Cloud IOA detections |

6. Click **Add** and copy the **Client ID** and **Client Secret** — the secret is shown only once

### 4b. Create a `.env` File

In the root of this repository:

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```ini
FALCON_CLIENT_ID=your_client_id_here
FALCON_CLIENT_SECRET=your_client_secret_here

# Optional — only needed for non-US-1 clouds
# FALCON_BASE_URL=https://api.laggar.gcw.crowdstrike.com   # US-GOV-1
# FALCON_BASE_URL=https://api.eu-1.crowdstrike.com         # EU-1
# FALCON_BASE_URL=https://api.us-2.crowdstrike.com         # US-2
```

> **Note:** `.env` is listed in `.gitignore`. Never commit credentials to source control.

---

## 5. Run the Script

With the virtual environment active:

```bash
python cloud_risks_report_pdf.py
```

The script will print progress as it fetches each data set, then write `falcon_cloud_security_report.pdf` to the current directory:

```
Fetching risks:  status:'Open'+severity:'High'
  Found 42 risk(s).

Fetching cloud IOAs...
  Found 6 Cloud IOA(s).

Fetching VMs:    managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'
  Found 7 asset(s) for AWS.
Fetching VMs:    managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'
  Found 0 asset(s) for Azure.
Fetching VMs:    managed_by:'Unmanaged'+cloud_provider:'gcp'+instance_state:'running'
  Found 0 asset(s) for GCP.

PDF written to falcon_cloud_security_report.pdf
```

---

## 6. PDF Output

The PDF contains four sections:

| Section | Content |
|---|---|
| **Cover** | Report title, counts for risks / IOAs / VMs per cloud, generation timestamp |
| **Open High Severity Risks** | One card per finding: rule name, description, severity, asset, account, region, category, first/last seen, risk factors with remediation steps |
| **Cloud IOA Detections** | One card per detection: display name, description, severity, cloud provider/account/region, service, MITRE tactic and technique, user, event name, status, timestamp |
| **Unmanaged Running VMs** | Table per cloud provider listing resource ID and account ID for each unmanaged, running instance |

---

## 7. Customizing Filters

Open `cloud_risks_report_pdf.py` and edit the constants near the top of the file.

**Risk filter** (line 8):

```python
RISKS_FILTER = "status:'Open'+severity:'High'"
```

Common modifications:

| Goal | Filter |
|---|---|
| Include medium severity | `"status:'Open'+severity:'High,Medium'"` |
| Single cloud provider | `"status:'Open'+severity:'High'+cloud_provider:'aws'"` |

**VM filters** (lines 9–13):

```python
VM_FILTERS = [
    ("AWS",   "managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'"),
    ("Azure", "managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'"),
    ("GCP",   "managed_by:'Unmanaged'+cloud_provider:'gcp'+instance_state:'running'"),
]
```

You can remove providers you don't use or add additional FQL terms (e.g. `+account_id:'123456789'`).

---

## 8. Troubleshooting

### Authentication errors (401)

- Confirm **Client ID** and **Client Secret** are correct in `.env`
- Confirm the API client has all three required scopes enabled (CSPM Registration, Cloud Security Assets, Alerts)
- If your tenant is not on US-1, set `FALCON_BASE_URL` in `.env`

### Zero risks returned

- Verify your environment has open, high-severity findings in Falcon Cloud Security
- Check that the API client has **CSPM Registration: Read** scope

### Zero Cloud IOAs returned

- Cloud IOAs require CloudTrail-based IOA coverage to be enabled in your Falcon tenant
- Verify the API client has **Alerts: Read** scope

### Zero VMs returned

- FQL values are case-sensitive. The filters use lowercase provider names (`aws`, `azure`, `gcp`) and `Unmanaged` with a capital U — these match the values the platform stores
- Verify the API client has **Cloud Security Assets: Read** scope

### `ModuleNotFoundError: No module named 'falconpy'` (or `fpdf`)

The virtual environment is not active, or dependencies were installed in a different environment. Activate the virtual environment and re-run:

```bash
pip install crowdstrike-falconpy python-dotenv fpdf2
```

### PDF output is empty or missing sections

Each section falls back gracefully if no data is found — an empty section will show a "No records found" message rather than crashing. Check the terminal output for the fetch counts to confirm what data was returned.
