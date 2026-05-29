# Falcon Cloud Risk Report

> Automated PDF report combining open cloud risks, Cloud IOA detections, AI service misconfigurations, and unmanaged running VMs from [CrowdStrike Falcon Cloud Security](https://www.crowdstrike.com/platform/cloud-security/) using the [FalconPy SDK](https://github.com/CrowdStrike/falconpy).

---

## What It Produces

A single PDF with a cover page and up to five content sections — each togglable at runtime:

| Section | Content |
|---|---|
| **Cover page** | Active filter summary and counts for each included section |
| **Cloud Risks** | Rule name, description, asset, account, region, and risk factors with remediation steps |
| **Cloud IOA Detections** | Event name, description, severity, MITRE tactic/technique, user, region, and timestamp |
| **AI Package Risks** | AI-related container packages with Critical CVEs — CVE ID, description, and recommended version bump fix |
| **AI Cloud Services IOMs** | Active misconfigurations on AI service resources (SageMaker, Bedrock, Vertex AI, Azure ML, Azure OpenAI) with remediation guidance |
| **Unmanaged Running VMs** | Table of unmanaged, running VMs scoped to your selected cloud providers |

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
| Cloud Security Detections | Read |

> **Falcon Container Image** is only required when the AI Package Risks section is enabled.  
> **Cloud Security Detections** is only required when the AI Cloud Services IOMs section is enabled.

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
# Default run — Risks, IOAs, and VMs; High severity; Open status
python cloud_risks_report_pdf.py

# Interactive mode — prompted for all options before fetching
python cloud_risks_report_pdf.py -i

# Debug mode — prints HTTP status and error details for each API call
python cloud_risks_report_pdf.py -d

# Combine flags
python cloud_risks_report_pdf.py -i -d
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
  Include AI Cloud Services IOMs (Y/n):

  Risk Filters
  Available severities: Critical, High, Medium, Low, Informational
  Severity (comma-separated) [High]:
  Status (Open / Closed / all) [Open]:
  Cloud provider (aws / azure / gcp / all) [all]:

  Cloud IOA Filters
  IOA severity filter (comma-separated, or all) [all]:

  AI Package Filters
  Package severity filter (comma-separated, or all) [Critical]:

  VM Filters
  Available providers: AWS, Azure, GCP
  VM providers (comma-separated) [AWS,Azure,GCP]:

  Output
  Output filename [falcon_cloud_security_report.pdf]:
  Save as new defaults (y/N):
```

### Available options

| Prompt | Options | Default |
|---|---|---|
| Include Cloud Risks | `y` / `n` | `y` |
| Include Cloud IOA Detections | `y` / `n` | `y` |
| Include Unmanaged VMs | `y` / `n` | `y` |
| Include AI Package Risks | `y` / `n` | `y` (interactive) / `n` (non-interactive) |
| Include AI Cloud Services IOMs | `y` / `n` | `y` (interactive) / `n` (non-interactive) |
| Severity | `Critical`, `High`, `Medium`, `Low`, `Informational` (comma-separated) | `High` |
| Status | `Open`, `Closed`, `all` | `Open` |
| Cloud provider (risks) | `aws`, `azure`, `gcp`, `all` | `all` |
| IOA severity filter | Any of the severities above, or `all` | `all` |
| Package severity filter | Any of the severities above, or `all` | `Critical` |
| VM providers | `AWS`, `Azure`, `GCP` (comma-separated) | `AWS,Azure,GCP` |
| Output filename | Any valid filename ending in `.pdf` | `falcon_cloud_security_report.pdf` |
| Save as new defaults | `y` / `n` | `n` |

Sections excluded from the configuration are skipped entirely — no API calls are made for them and they do not appear in the PDF.

### Saving defaults

Answering `y` at the **Save as new defaults** prompt writes your choices to `.report_defaults.json` in the script directory. On subsequent runs — interactive or not — those saved values replace the hardcoded defaults. The output filename is never saved, since it typically changes between runs.

To reset to factory defaults, delete `.report_defaults.json`.

---

## Non-Interactive Defaults

Running without `-i` uses these defaults:

| Setting | Default value |
|---|---|
| Sections | Risks, IOAs, VMs included; AI Packages and AI IOMs excluded |
| Severity | High |
| Status | Open |
| Cloud provider | all |
| VM providers | AWS, Azure, GCP |
| Output file | `falcon_cloud_security_report.pdf` |

If `.report_defaults.json` exists (created via **Save as new defaults**), those values are used instead.

---

## AI Cloud Services IOMs

The **AI Cloud Services IOMs** section surfaces active Indicators of Misconfiguration on AI service resources across all three cloud providers:

| Provider | Services covered |
|---|---|
| AWS | SageMaker (notebook instances, endpoints, domains), Bedrock (custom models, agents, guardrails) |
| GCP | Vertex AI (Workbench, Colab Enterprise runtime templates) |
| Azure | Machine Learning workspaces and compute, OpenAI / Cognitive Services |

Each finding shows the misconfigured resource, cloud account, region, severity, and the remediation steps from the IOM rule. Only `non-compliant` evaluations are included.

---

## Debug Mode

Pass `-d` or `--debug` to print the HTTP status code and error body for every API call as the script runs. Use this when a section returns no results unexpectedly or when troubleshooting credential scope issues.

```bash
python cloud_risks_report_pdf.py -i -d
```

Debug output is written to stdout and does not affect the PDF.

---

## Documentation

Full setup and troubleshooting guide: [docs/setup_guide.md](docs/setup_guide.md)
