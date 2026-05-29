# Falcon Cloud Risk Report

> Automated PDF report combining open cloud risks, Cloud IOA detections, and unmanaged running VMs from [CrowdStrike Falcon Cloud Security](https://www.crowdstrike.com/platform/cloud-security/) using the [FalconPy SDK](https://github.com/CrowdStrike/falconpy).

---

## What It Produces

A single PDF with a cover page and up to four content sections — each togglable at runtime:

| Section | Content |
|---|---|
| **Cover page** | Active filter summary and counts for each included section |
| **Cloud Risks** | Rule name, description, asset, account, region, and risk factors with remediation steps |
| **Cloud IOA Detections** | Event name, description, severity, MITRE tactic/technique, user, region, and timestamp |
| **Unmanaged Running VMs** | Table of unmanaged, running VMs scoped to your selected cloud providers |
| **AI Package Risks** | AI-related container packages with Critical CVEs — CVE ID, description, and recommended version bump fix |

---

## Prerequisites

- Python 3.8+
- CrowdStrike Falcon API credentials with the following scopes:

| Scope | Permission |
|---|---|
| CSPM Registration | Read |
| Cloud Security Assets | Read |
| Alerts | Read |
| Falcon Container Image | Read |

> The **Falcon Container Image** scope is only required when the AI Package Risks section is enabled.

---

## Quick Start

**1. Clone and enter the repo**

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

**3. Install dependencies**

```bash
pip install crowdstrike-falconpy python-dotenv fpdf2
```

**4. Configure credentials**

```bash
cp .env.example .env
```

Edit `.env` with your Falcon API credentials:

```ini
FALCON_CLIENT_ID=your_client_id_here
FALCON_CLIENT_SECRET=your_client_secret_here
```

**5. Run**

```bash
# Default run — all sections, High severity, Open status
python cloud_risks_report_pdf.py

# Interactive mode — prompted for all options before fetching
python cloud_risks_report_pdf.py -i
```

---

## Interactive Mode

Pass `-i` or `--interactive` to configure the report before any API calls are made. You will be stepped through each category — press **Enter** to accept the default shown in brackets.

```
Falcon Cloud Security Report -- Configuration
Press Enter to accept defaults.

  Sections
  Include Cloud Risks (Y/n):
  Include Cloud IOA Detections (Y/n):
  Include Unmanaged VMs (Y/n):
  Include AI Package Risks (Critical CVEs) (Y/n):

  Risk Filters
  Available severities: Critical, High, Medium, Low, Informational
  Severity (comma-separated) [High]:
  Status (Open / Closed / All) [Open]:
  Cloud provider (aws / azure / gcp / all) [all]:

  Cloud IOA Filters
  IOA severity filter (comma-separated, or all) [all]:

  VM Filters
  Available providers: AWS, Azure, GCP
  VM providers (comma-separated) [AWS,Azure,GCP]:

  Output
  Output filename [falcon_cloud_security_report.pdf]:
```

### Available options

| Prompt | Options | Default |
|---|---|---|
| Include Cloud Risks | `y` / `n` | `y` |
| Include Cloud IOA Detections | `y` / `n` | `y` |
| Include Unmanaged VMs | `y` / `n` | `y` |
| Include AI Package Risks | `y` / `n` | `y` (interactive) / `n` (default) |
| Severity | `Critical`, `High`, `Medium`, `Low`, `Informational` (comma-separated) | `High` |
| Status | `Open`, `Closed`, `All` | `Open` |
| Cloud provider (risks) | `aws`, `azure`, `gcp`, `all` | `all` |
| IOA severity filter | Any of the severities above, or `all` | `all` |
| VM providers | `AWS`, `Azure`, `GCP` (comma-separated) | `AWS,Azure,GCP` |
| Output filename | Any valid filename ending in `.pdf` | `falcon_cloud_security_report.pdf` |

Sections excluded from the configuration are skipped entirely — no API calls are made for them and they do not appear in the PDF.

---

## Non-Interactive Defaults

Running without `-i` uses these defaults and behaves the same as before interactive mode was added:

| Setting | Default value |
|---|---|
| Sections | Risks, IOAs, VMs included; AI Packages excluded |
| Severity | High |
| Status | Open |
| Cloud provider | All |
| VM providers | AWS, Azure, GCP |
| Output file | `falcon_cloud_security_report.pdf` |

---

## Documentation

Full setup and troubleshooting guide: [docs/setup_guide.md](docs/setup_guide.md)
