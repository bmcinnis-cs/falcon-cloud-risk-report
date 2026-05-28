# Falcon Cloud Risk Report

> Automated PDF report combining open high-severity risks, Cloud IOA detections, and unmanaged running VMs from [CrowdStrike Falcon Cloud Security](https://www.crowdstrike.com/platform/cloud-security/) using the [FalconPy SDK](https://github.com/CrowdStrike/falconpy).

---

## What It Produces

A single PDF (`falcon_cloud_security_report.pdf`) with four sections:

| Section | Description |
|---|---|
| Cover page | Summary counts for risks, IOAs, and unmanaged VMs per cloud |
| Open High Severity Risks | One card per finding — rule name, description, asset, account, region, risk factors with remediation steps |
| Cloud IOA Detections | One card per detection — event name, description, severity, tactic/technique, user, region, timestamp |
| Unmanaged Running VMs | Table of unmanaged, running VMs across AWS, Azure, and GCP |

---

## Prerequisites

- Python 3.8+
- CrowdStrike Falcon API client with the following scopes:

| Scope | Access |
|---|---|
| **CSPM Registration** | Read |
| **Cloud Security Assets** | Read |
| **Alerts** | Read |

See [docs/setup_guide.md](docs/setup_guide.md) for full step-by-step instructions.

---

## Quick Start

**1. Clone the repo**

```bash
git clone https://github.com/bmcinnis-cs/falcon-cloud-risk-report.git
cd falcon-cloud-risk-report
```

**2. Create and activate a virtual environment**

```bash
python -m venv .venv
```

| Platform | Activation command |
|---|---|
| macOS / Linux | `source .venv/bin/activate` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |

You'll see `(.venv)` in your terminal prompt once active. Re-activate each time you open a new terminal.

**3. Install dependencies**

```bash
pip install crowdstrike-falconpy python-dotenv fpdf2
```

**4. Configure credentials**

```bash
cp .env.example .env
```

Edit `.env` and fill in your Client ID and Secret:

```ini
FALCON_CLIENT_ID=your_client_id_here
FALCON_CLIENT_SECRET=your_client_secret_here
```

**5. Run**

```bash
python cloud_risks_report_pdf.py
```

The script prints progress to the terminal and writes `falcon_cloud_security_report.pdf` in the current directory.

---

## Output

```
Fetching risks:  status:'Open'+severity:'High'
  Found 42 risk(s).

Fetching cloud IOAs...
  Found 6 Cloud IOA(s).

Fetching VMs:    managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'
  Found 7 asset(s) for AWS.
...
PDF written to falcon_cloud_security_report.pdf
```

---

## Documentation

Full setup and troubleshooting guide: [docs/setup_guide.md](docs/setup_guide.md)
