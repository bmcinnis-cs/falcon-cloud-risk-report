# Falcon Cloud Risk Report

> Automated PDF report combining cloud risks, IOA detections, cloud applications, AI package CVEs, cloud service misconfigurations, and unmanaged running VMs from [CrowdStrike Falcon Cloud Security](https://www.crowdstrike.com/platform/cloud-security/) using the [FalconPy SDK](https://github.com/CrowdStrike/falconpy).

---

## What It Produces

A single PDF with a cover page, a clickable table of contents, and four logical sections — each togglable at runtime:

| Section | Subsections |
|---|---|
| **Cloud Infrastructure** | **Cloud IOA Detections** · Event name, severity, MITRE tactic/technique, user, region, timestamp<br>**Cloud Risks** · Rule name, description, asset, account, region, risk factors, remediation<br>**Cloud Service IOMs** · Active misconfigurations with remediation steps, cloud console deep-links, and Falcon links |
| **Cloud Applications** | **Cloud Applications** · App name, deployment type, technologies, account, region, vulnerability count, ExPRT ratings<br>**Risky Container Images** · Per-image CVE layer breakdown — layer command, CVE ID, CVSS, package, exploit/fix flags, Falcon deep-link |
| **Shadow AI** | **AI Services** · IOMs scoped to AI cloud services (SageMaker, Bedrock, Vertex AI, etc.)<br>**AI Package Risks** · AI-related container packages with CVEs — CVE ID, description, fix version, affected images |
| **Unmanaged VMs** | **Unmanaged Virtual Machines** · Table of unmanaged, running VMs scoped to selected cloud providers |

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

> **Falcon Container Image** is required for both the AI Package Risks and Risky Images sections.  
> **Cloud Security Detections** is only required when the Cloud Service IOMs section is enabled.

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

Pass `-i` or `--interactive` to configure the report before any API calls are made. You will be stepped through each of the four sections — press **Enter** to accept the default shown in `[ ]`.

> The IOM severity prompt only appears when at least one category is selected.

### Saving defaults

Answering `y` at the **Save as new defaults** prompt writes your choices to `.report_defaults.json` in the script directory. On subsequent runs — interactive or not — those saved values replace the hardcoded defaults. The output filename is never saved.

To reset to factory defaults, delete `.report_defaults.json`.

---

## Non-Interactive Defaults

Running without `-i` uses these defaults (or saved defaults from `.report_defaults.json`):

| Setting | Default value |
|---|---|
| Sections | Cloud IOAs, Risks, VMs included; Cloud IOMs, Cloud Apps, Risky Images, AI Services, AI Packages excluded |
| Risk severity | High |
| Risk status | Open |
| Risk cloud provider | all |
| VM providers | AWS, Azure, GCP |
| IOM categories | none (section skipped) |
| IOM severity | all |
| Output file | `falcon_cloud_security_report.pdf` |

---

## Cloud Service IOMs

The **Cloud Service IOMs** section surfaces active Indicators of Misconfiguration across your cloud environment, filtered by service category and severity. Only `non-compliant` evaluations are included.

### Categories

| Category | Resource types covered |
|---|---|
| `compute` | EC2 instances, volumes, images, snapshots, EIPs, Auto Scaling, GCP Compute instances and disks |
| `networking` | Security groups, VPCs, subnets, network ACLs, route tables, load balancers, GCP networks and firewalls |
| `iam` | AWS IAM roles, users, policies, groups; GCP IAM |
| `storage` | S3 buckets, GCP Storage, Artifact Registry |
| `database` | RDS, Athena, Glue |
| `containers` | ECR, EKS, ECS, GCP GKE |
| `serverless` | Lambda, EventBridge, GCP Pub/Sub |
| `ai` | SageMaker, Bedrock, GCP Vertex AI, Azure Machine Learning, Azure Cognitive Services |
| `secrets` | KMS, Secrets Manager, GCP Secret Manager |
| `account` | AWS Account, CloudFormation, CloudTrail, CloudWatch Logs, AWS Organizations |
| `all` | All of the above |

Use comma-separated values to combine categories — for example, `iam, compute` returns misconfigurations across both service groups.

### Severity filter

An optional severity filter reduces results to `Critical`, `High`, `Medium`, `Low`, or any combination. Leave it as `all` to include every severity.

Filtering by severity is applied client-side after fetching entity details. For broad category selections (e.g. `compute, iam, storage`) this can still involve fetching thousands of entity IDs — the script parallelises the detail fetches across 8 threads to keep wall time manageable.

### Links in the PDF

Each IOM card in the PDF includes two clickable links:

- **Console** — a direct deep-link to the specific resource in the AWS console, GCP console, or Azure portal. For AWS, the link resolves to the exact resource (e.g. an EC2 instance, IAM role by name, S3 bucket, RDS instance). For IAM resources where the resource ID is an ARN, the leaf name is extracted automatically.
- **Falcon** — a direct link to the finding in the Falcon CSPM console, pre-filtered by severity and rule ID.

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
