import os
import sys
import json
import argparse
import textwrap
import html
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from datetime import datetime, timezone
from dotenv import load_dotenv
from falconpy import OAuth2, CloudSecurity, CloudSecurityAssets, Alerts, ContainerPackages, ContainerImages, ContainerVulnerabilities, CloudSecurityDetections
from fpdf import FPDF, XPos, YPos

VM_FILTERS = [
    ("AWS",   "active:'true'+cloud_provider:'aws'+resource_type_name:'EC2 Instance'+managed_by:'Unmanaged'"),
    ("Azure", "active:'true'+cloud_provider:'azure'+resource_type_name:'Virtual Machine'+managed_by:'Unmanaged'"),
    ("GCP",   "active:'true'+cloud_provider:'gcp'+resource_type_name:'Compute Instance'+managed_by:'Unmanaged'"),
]

def ensure_timestamped_filename(filename):
    """Append YYYYMMDD_HHMMSS to a filename before the extension if not already present."""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"falcon_cloud_security_report_{timestamp}.pdf"

    if re.search(r'_\d{8}_\d{6}', filename):
        return filename

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if filename.lower().endswith('.pdf'):
        base, ext = filename[:-4], filename[-4:]
        return f"{base}_{timestamp}{ext}"
    return f"{filename}_{timestamp}.pdf"

OUTPUT_FILE    = "falcon_cloud_security_report.pdf"
DEFAULTS_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".report_defaults.json")

VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
VALID_PROVIDERS  = ["aws", "azure", "gcp"]
SEVERITY_MAP     = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Resource-type substrings (lowercase) in IOM entity IDs (pipe-segment 4),
# grouped into logical categories. Matching uses substring containment so a
# single entry like "aws::iam" covers all AWS::IAM::* resource types.
IOM_CATEGORIES = {
    "compute": [
        "aws::ec2::instance",
        "aws::ec2::volume",
        "aws::ec2::image",
        "aws::ec2::snapshot",
        "aws::ec2::eip",
        "aws::autoscaling",
        "compute.googleapis.com/instance",
        "compute.googleapis.com/disk",
        "compute.googleapis.com/instancegroupmanager",
    ],
    "networking": [
        "aws::ec2::securitygroup",
        "aws::ec2::vpc",
        "aws::ec2::subnet",
        "aws::ec2::networkacl",
        "aws::ec2::routetable",
        "aws::elasticloadbalancing",
        "compute.googleapis.com/network",
        "compute.googleapis.com/subnetwork",
        "compute.googleapis.com/firewall",
    ],
    "iam": [
        "aws::iam",
        "iam.googleapis.com",
    ],
    "storage": [
        "aws::s3",
        "storage.googleapis.com/bucket",
        "artifactregistry.googleapis.com/repository",
    ],
    "database": [
        "aws::rds",
        "aws::athena",
        "aws::glue::datacatalog",
    ],
    "containers": [
        "aws::ecr",
        "aws::eks",
        "aws::ecs",
        "container.googleapis.com",
    ],
    "serverless": [
        "aws::lambda",
        "aws::eventbridge",
        "pubsub.googleapis.com",
    ],
    "ai": [
        "aws::sagemaker",
        "aws::bedrock",
        "aiplatform.googleapis.com",
        "microsoft.machinelearningservices",
        "microsoft.cognitiveservices",
    ],
    "secrets": [
        "aws::kms",
        "aws::secretsmanager",
        "secretmanager.googleapis.com",
    ],
    "account": [
        "aws::account",
        "aws::cloudformation",
        "aws::cloudtrail",
        "aws::logs::loggroup",
        "aws::organizations",
        "cloudresourcemanager.googleapis.com",
        "logging.googleapis.com",
    ],
}
VALID_IOM_CATEGORIES = sorted(IOM_CATEGORIES.keys()) + ["all"]

# PDF colors (R, G, B)
CS_RED     = (227, 24,  55)
DARK       = (20,  20,  20)
MID_GRAY   = (80,  80,  80)
LIGHT_GRAY = (230, 230, 230)
WHITE      = (255, 255, 255)
AMBER      = (200, 130, 0)
SECTION_BG = (245, 245, 245)
LINK_BLUE  = (0,   102, 204)

# ANSI terminal colors (256-color palette)
T_RESET    = "\033[0m"
T_BOLD     = "\033[1m"
T_DIM      = "\033[2m"
T_BRAND    = "\033[38;5;203m"   # salmon-red  (CrowdStrike brand)
T_HEADER   = "\033[38;5;215m"   # warm amber
T_ACCENT   = "\033[38;5;86m"    # mint green
T_LABEL    = "\033[38;5;110m"   # periwinkle
T_VALUE    = "\033[38;5;255m"   # near-white
T_MUTED    = "\033[38;5;242m"   # slate gray
T_HINT     = "\033[38;5;68m"    # steel blue
T_SUCCESS  = "\033[38;5;120m"   # soft green
T_WARN     = "\033[38;5;220m"   # golden yellow
T_CRITICAL = "\033[38;5;196m"
T_HIGH     = "\033[38;5;208m"
T_MEDIUM   = "\033[38;5;226m"
T_LOW      = "\033[38;5;117m"
T_INFO_SEV = "\033[38;5;244m"
# Backwards-compat aliases
T_RED    = T_CRITICAL
T_YELLOW = T_WARN
T_CYAN   = T_ACCENT
T_WHITE  = T_VALUE
T_GRAY   = T_MUTED

DEBUG = False


def dbg(msg):
    if DEBUG:
        print(f"{T_GRAY}[debug] {msg}{T_RESET}")


def dbg_response(label, r):
    if not DEBUG:
        return
    status = r.get("status_code", "?")
    color = T_YELLOW if status != 200 else T_GRAY
    print(f"{color}[debug] {label}  →  HTTP {status}{T_RESET}")
    if status != 200:
        print(f"{T_RED}[debug]   errors: {r.get('body', {}).get('errors')}{T_RESET}")
        print(f"{T_RED}[debug]   body:   {str(r.get('body', ''))[:400]}{T_RESET}")


# --- Interactive configuration ---

def t_severity(sev):
    col = {"critical": T_CRITICAL, "high": T_HIGH, "medium": T_MEDIUM,
           "low": T_LOW, "informational": T_INFO_SEV}.get((sev or "").lower(), T_VALUE)
    return f"{T_BOLD}{col}{sev}{T_RESET}"


def _banner(title, count=None):
    W = 64
    count_str = f"  {T_SUCCESS}{count}{T_RESET}{T_HEADER}" if count is not None else ""
    print(f"\n{T_BOLD}{T_HEADER}{'━' * W}{T_RESET}")
    print(f"{T_BOLD}{T_HEADER}  {title}{count_str}{T_RESET}")
    print(f"{T_BOLD}{T_HEADER}{'━' * W}{T_RESET}")


def _prompt(label, default=""):
    display_default = f"  {T_MUTED}[{T_HEADER}{default}{T_MUTED}]{T_RESET}" if default else ""
    try:
        val = input(f"  {T_LABEL}{label}{display_default}{T_RESET}  {T_VALUE}").strip()
        print(T_RESET, end="", flush=True)
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _prompt_yn(label, default=True):
    hint = "Y/n" if default else "y/N"
    raw = _prompt(label, hint)
    if not raw or raw == hint:
        return default
    return raw.lower().startswith("y")


def interactive_config():
    W = 58
    print(f"\n{T_BOLD}{T_BRAND}  {'─' * W}{T_RESET}")
    print(f"{T_BOLD}{T_BRAND}  Falcon Cloud Security  ·  Report Configuration{T_RESET}")
    print(f"{T_MUTED}  Press Enter to accept the default shown in [ ]{T_RESET}")
    print(f"{T_BOLD}{T_BRAND}  {'─' * W}{T_RESET}\n")

    config = {}

    # ── Section 1: Cloud Infrastructure ─────────────────────────────────────────
    print(f"  {T_BOLD}{T_HEADER}▸ Section 1 — Cloud Infrastructure{T_RESET}")
    config["include_ioas"]  = _prompt_yn("Include Cloud IOA Detections", default=True)
    config["include_risks"] = _prompt_yn("Include Cloud Risks", default=True)

    _include_ioms = _prompt_yn("Include Cloud Service IOMs", default=False)
    print()

    if config["include_ioas"]:
        print(f"  {T_BOLD}{T_HEADER}▸ Cloud IOA Filters{T_RESET}")
        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ioa_sev_raw = _prompt("IOA severity (comma-separated, or all)", "all")
        if not ioa_sev_raw.strip() or ioa_sev_raw.strip().lower() == "all":
            config["ioa_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ioa_sev_raw.split(",") if s.strip()]
            config["ioa_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
        print()

    if config["include_risks"]:
        print(f"  {T_BOLD}{T_HEADER}▸ Risk Filters{T_RESET}")
        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}{T_RESET}")
        sev_raw = _prompt("Severity (comma-separated)", "High")
        sevs = [s.strip().capitalize() for s in sev_raw.split(",") if s.strip()]
        config["severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["High"]

        print(f"  {T_HINT}Available statuses: Open, Closed, all{T_RESET}")
        status_raw = _prompt("Status", "Open")
        status_val = status_raw.strip().capitalize() if status_raw.strip() else "Open"
        config["status"] = status_val if status_val in ("Open", "Closed") else "all"

        print(f"  {T_HINT}Available providers: {', '.join(VALID_PROVIDERS)}, all{T_RESET}")
        prov_raw = _prompt("Cloud provider", "all")
        config["risk_provider"] = prov_raw.strip().lower() if prov_raw.strip().lower() in VALID_PROVIDERS else "all"
        print()

    if _include_ioms:
        print(f"  {T_BOLD}{T_HEADER}▸ Cloud IOM Filters{T_RESET}")
        print(f"  {T_HINT}Available categories: {', '.join(VALID_IOM_CATEGORIES)}{T_RESET}")
        iom_raw = _prompt("IOM categories (comma-separated, or all)", "all")
        iom_val = iom_raw.strip().lower()
        if not iom_val or iom_val == "all":
            config["iom_categories"] = ["all"]
        else:
            cats = [c.strip() for c in iom_val.split(",") if c.strip()]
            config["iom_categories"] = [c for c in cats if c in IOM_CATEGORIES] or ["all"]

        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        iom_sev_raw = _prompt("IOM severity (comma-separated, or all)", "all")
        if not iom_sev_raw.strip() or iom_sev_raw.strip().lower() == "all":
            config["iom_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in iom_sev_raw.split(",") if s.strip()]
            config["iom_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
        print()
    else:
        config["iom_categories"] = []
        config["iom_severities"] = []

    # ── Section 2: Cloud Apps ─────────────────────────────────────────────────
    print(f"  {T_BOLD}{T_HEADER}▸ Section 2 — Cloud Apps{T_RESET}")
    config["include_cloud_apps"]   = _prompt_yn("Include Cloud Applications", default=True)
    config["include_risky_images"] = _prompt_yn("Include Risky Container Images", default=True)
    print()

    if config["include_cloud_apps"]:
        print(f"  {T_BOLD}{T_HEADER}▸ Cloud Applications Filters{T_RESET}")
        ca_max_raw = _prompt("Max applications to include", "50")
        try:
            config["cloud_apps_max"] = max(1, int(ca_max_raw.strip()))
        except (ValueError, TypeError):
            config["cloud_apps_max"] = 50
        print()

    if config["include_risky_images"]:
        print(f"  {T_BOLD}{T_HEADER}▸ Risky Images Filters{T_RESET}")
        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ri_sev_raw = _prompt("CVE severity (comma-separated, or all)", "Critical")
        if not ri_sev_raw.strip() or ri_sev_raw.strip().lower() == "all":
            config["risky_images_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ri_sev_raw.split(",") if s.strip()]
            config["risky_images_severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["Critical"]
        ri_max_raw = _prompt("Max images to include", "10")
        try:
            config["risky_images_max"] = max(1, int(ri_max_raw.strip()))
        except (ValueError, TypeError):
            config["risky_images_max"] = 10
        print()

    # ── Section 3: Shadow AI ──────────────────────────────────────────────────
    print(f"  {T_BOLD}{T_HEADER}▸ Section 3 — Shadow AI{T_RESET}")
    config["include_ai_services"]  = _prompt_yn("Include AI Services (cloud IOMs — AI category)", default=True)
    config["include_ai_packages"]  = _prompt_yn("Include AI Package Risks", default=True)
    print()

    if config["include_ai_services"]:
        print(f"  {T_BOLD}{T_HEADER}▸ AI Services Filters{T_RESET}")
        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ai_svc_sev_raw = _prompt("AI Services severity (comma-separated, or all)", "all")
        if not ai_svc_sev_raw.strip() or ai_svc_sev_raw.strip().lower() == "all":
            config["ai_services_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ai_svc_sev_raw.split(",") if s.strip()]
            config["ai_services_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
        print()

    if config["include_ai_packages"]:
        print(f"  {T_BOLD}{T_HEADER}▸ AI Package Filters{T_RESET}")
        print(f"  {T_HINT}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ai_sev_raw = _prompt("Package severity (comma-separated, or all)", "Critical")
        if not ai_sev_raw.strip() or ai_sev_raw.strip().lower() == "all":
            config["ai_package_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ai_sev_raw.split(",") if s.strip()]
            config["ai_package_severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["Critical"]
        print()

    # ── Section 4: Unmanaged VMs ──────────────────────────────────────────────
    print(f"  {T_BOLD}{T_HEADER}▸ Section 4 — Unmanaged VMs{T_RESET}")
    config["include_vms"] = _prompt_yn("Include Unmanaged Virtual Machines", default=True)
    print()

    if config["include_vms"]:
        print(f"  {T_BOLD}{T_HEADER}▸ VM Filters{T_RESET}")
        print(f"  {T_HINT}Available providers: AWS, Azure, GCP{T_RESET}")
        vm_prov_raw = _prompt("VM providers (comma-separated)", "AWS,Azure,GCP")
        _norm = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
        vm_provs = [p.strip() for p in vm_prov_raw.split(",") if p.strip()]
        config["vm_providers"] = [_norm[p.lower()] for p in vm_provs if p.lower() in _norm] or ["AWS", "Azure", "GCP"]
        print()

    # ── Output ────────────────────────────────────────────────────────────────
    print(f"  {T_BOLD}{T_HEADER}▸ Output{T_RESET}")
    config["output_file"] = ensure_timestamped_filename(_prompt("Output filename", OUTPUT_FILE))
    print()

    merged = {**_default_config(), **config}

    if _prompt_yn("Save as new defaults", default=False):
        _save_defaults(merged)
        print(f"  {T_MUTED}Defaults saved to {DEFAULTS_FILE}{T_RESET}\n")

    return merged


def _default_config():
    hardcoded = {
        "include_risks":          True,
        "include_ioas":           True,
        "include_vms":            True,
        "include_ai_packages":    False,
        "include_risky_images":   False,
        "include_cloud_apps":     False,
        "include_ai_services":    False,
        "iom_categories":         [],
        "iom_severities":         [],
        "ai_package_severities":  ["Critical"],
        "risky_images_severities": ["Critical"],
        "risky_images_max":       10,
        "cloud_apps_max":         50,
        "ai_services_severities": [],
        "severities":             ["High"],
        "status":                 "Open",
        "risk_provider":          "all",
        "ioa_severities":         [],
        "vm_providers":           ["AWS", "Azure", "GCP"],
        "output_file":            OUTPUT_FILE,
    }
    if os.path.exists(DEFAULTS_FILE):
        try:
            with open(DEFAULTS_FILE) as f:
                saved = json.load(f)
            if not isinstance(saved, dict):
                raise ValueError("defaults file is not a JSON object")
            saved = _sanitize_saved_config(saved)
            return {**hardcoded, **saved}
        except (OSError, PermissionError) as exc:
            print(f"{T_YELLOW}Warning: could not read {DEFAULTS_FILE}: {exc}{T_RESET}", file=sys.stderr)
        except Exception as exc:
            print(f"{T_YELLOW}Warning: ignoring malformed {DEFAULTS_FILE}: {exc}{T_RESET}", file=sys.stderr)
    return hardcoded


def _sanitize_saved_config(cfg):
    """Normalize and drop invalid values from a loaded .report_defaults.json."""
    out = {}
    bool_keys = ("include_risks", "include_ioas", "include_vms", "include_ai_packages",
                 "include_risky_images", "include_cloud_apps", "include_ai_services")
    for k in bool_keys:
        if k in cfg:
            out[k] = bool(cfg[k])
    # Backward compat: old files may have include_ai_ioms; convert to iom_categories
    if "include_ai_ioms" in cfg and "iom_categories" not in cfg:
        out["iom_categories"] = ["ai"] if cfg["include_ai_ioms"] else []
    if "iom_categories" in cfg:
        cats = cfg["iom_categories"]
        if isinstance(cats, list):
            out["iom_categories"] = [c for c in cats if c in IOM_CATEGORIES or c == "all"]
    if "iom_severities" in cfg:
        out["iom_severities"] = [s for s in cfg["iom_severities"] if s in VALID_SEVERITIES]
    if "severities" in cfg:
        out["severities"] = [s for s in cfg["severities"] if s in VALID_SEVERITIES] or ["High"]
    if "status" in cfg:
        val = str(cfg["status"]).capitalize()
        out["status"] = val if val in ("Open", "Closed") else "all"
    if "risk_provider" in cfg:
        prov = str(cfg["risk_provider"]).lower()
        out["risk_provider"] = prov if prov in VALID_PROVIDERS else "all"
    if "ioa_severities" in cfg:
        out["ioa_severities"] = [s for s in cfg["ioa_severities"] if s in VALID_SEVERITIES]
    if "ai_package_severities" in cfg:
        out["ai_package_severities"] = [s for s in cfg["ai_package_severities"] if s in VALID_SEVERITIES] or ["Critical"]
    if "risky_images_severities" in cfg:
        out["risky_images_severities"] = [s for s in cfg["risky_images_severities"] if s in VALID_SEVERITIES] or ["Critical"]
    if "risky_images_max" in cfg:
        try:
            out["risky_images_max"] = max(1, int(cfg["risky_images_max"]))
        except (TypeError, ValueError):
            pass
    if "cloud_apps_max" in cfg:
        try:
            out["cloud_apps_max"] = max(1, int(cfg["cloud_apps_max"]))
        except (TypeError, ValueError):
            pass
    if "ai_services_severities" in cfg:
        out["ai_services_severities"] = [s for s in cfg["ai_services_severities"] if s in VALID_SEVERITIES]
    valid_vm = {"AWS", "Azure", "GCP"}
    if "vm_providers" in cfg:
        out["vm_providers"] = [p for p in cfg["vm_providers"] if p in valid_vm] or ["AWS", "Azure", "GCP"]
    return out


def _save_defaults(config):
    # output_file is intentionally excluded — it's a per-run setting, not a persistent preference
    to_save = {k: v for k, v in config.items() if k != "output_file"}
    try:
        with open(DEFAULTS_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except OSError as exc:
        print(f"{T_YELLOW}Warning: could not save defaults to {DEFAULTS_FILE}: {exc}{T_RESET}", file=sys.stderr)


def build_filters(config):
    sevs = config.get("severities", ["High"])
    if len(sevs) == 1:
        sev_filter = f"severity:'{sevs[0]}'"
    else:
        joined = ",".join(f"'{s}'" for s in sevs)
        sev_filter = f"severity:[{joined}]"

    status = config.get("status", "Open")
    risks_filter = sev_filter if status.lower() == "all" else f"status:'{status}'+{sev_filter}"

    provider = config.get("risk_provider", "all")
    if provider != "all":
        risks_filter += f"+cloud_provider:'{provider}'"

    # Use exact Asset Explorer VM filters
    vm_providers = config.get("vm_providers", ["AWS", "Azure", "GCP"])
    vm_filters = [(p, f) for p, f in VM_FILTERS if p in vm_providers]

    return risks_filter, vm_filters


def _filter_desc(config):
    parts = []
    if config.get("include_risks"):
        sevs = config.get("severities", ["High"])
        status = config.get("status", "Open")
        prov = config.get("risk_provider", "all")
        parts.append(f"Risks: {', '.join(sevs)} severity / {status} status" +
                     (f" / {prov.upper()}" if prov != "all" else ""))
    if config.get("include_ioas"):
        ioa_sevs = config.get("ioa_severities", [])
        parts.append("IOAs: " + (", ".join(ioa_sevs) if ioa_sevs else "all severities"))
    if config.get("include_vms"):
        vm_provs = config.get("vm_providers", ["AWS", "Azure", "GCP"])
        parts.append(f"VMs: {', '.join(vm_provs)}")
    if config.get("include_ai_packages"):
        ai_sevs = config.get("ai_package_severities", ["Critical"])
        parts.append("AI Packages: " + (", ".join(ai_sevs) if ai_sevs else "all severities"))
    iom_cats = config.get("iom_categories", [])
    if iom_cats:
        label = "all categories" if "all" in iom_cats else ", ".join(iom_cats)
        iom_sevs = config.get("iom_severities", [])
        sev_label = ", ".join(iom_sevs) if iom_sevs else "all severities"
        parts.append(f"IOMs: {label} / {sev_label}")
    return "  |  ".join(parts)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def now_utc_detailed():
    """Returns a more detailed timestamp for report generation"""
    return datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M:%S UTC")


def sanitize(text):
    if not text:
        return ""
    replacements = {
        "—": "--", "–": "-", "‒": "-",
        "‘": "'",  "’": "'", "“": '"', "”": '"',
        "•": "*",  "…": "...", " ": " ",
    }
    for char, sub in replacements.items():
        text = text.replace(char, sub)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _strip_html(text):
    """Convert HTML-tagged API text to clean plain text.

    Handles <br> → newline, strips all other tags, unescapes HTML entities.
    <a href="url">label</a> keeps the label; if label differs from url, appends
    the url in parentheses so the destination is still visible in the PDF.
    """
    if not text:
        return text

    # <br> variants → newline
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)

    # <a href="url">label</a>: keep label; append url when it adds information
    def _repl_anchor(m):
        href  = (m.group(1) or "").strip()
        label = (m.group(2) or "").strip()
        if label and href and label != href:
            return f"{label} ({href})"
        return label or href

    text = re.sub(
        r'<a\s[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        _repl_anchor,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Strip remaining tags
    text = re.sub(r'<[^>]+>', '', text)

    # Unescape HTML entities (&amp; → &, &lt; → <, &#39; → ', etc.)
    text = html.unescape(text)

    return text


# --- Data fetching ---

def fetch_all_risks(sdk, filter_str):
    risks = []
    offset = 0
    while True:
        r = sdk.combined_cloud_risks(limit=1000, offset=offset, filter=filter_str)
        if r["status_code"] != 200:
            raise RuntimeError(f"combined_cloud_risks failed: {r['body'].get('errors')}")
        batch = r["body"].get("resources") or []
        risks.extend(batch)
        if not batch:
            break
        total = r["body"].get("meta", {}).get("pagination", {}).get("total")
        offset += len(batch)
        if total is not None and offset >= total:
            break
    return risks


def fetch_cloud_ioas(sdk, ioa_severities=None):
    fql = "type:'cloud-ioa'"
    if ioa_severities:
        if len(ioa_severities) == 1:
            fql += f"+severity_name:'{ioa_severities[0]}'"
        else:
            joined = ",".join(f"'{s}'" for s in ioa_severities)
            fql += f"+severity_name:[{joined}]"

    ids = []
    after = None
    while True:
        params = {"limit": 1000, "filter": fql}
        if after:
            params["after"] = after
        r = sdk.query_alerts_v2(**params)
        if r["status_code"] != 200:
            raise RuntimeError(f"query_alerts_v2 failed: {r['body'].get('errors')}")
        batch = r["body"].get("resources") or []
        ids.extend(batch)
        after = r["body"].get("meta", {}).get("pagination", {}).get("after")
        if not batch or not after:
            break

    ioas = []
    for i in range(0, len(ids), 1000):
        r = sdk.get_alerts_v2(composite_ids=ids[i:i + 1000])
        if r["status_code"] != 200:
            raise RuntimeError(f"get_alerts_v2 failed: {r['body'].get('errors')}")
        ioas.extend(r["body"].get("resources") or [])
    return ioas


def fetch_unmanaged_vms(sdk, filter_str):
    ids = []
    after = None
    while True:
        params = {"limit": 1000, "filter": filter_str}
        if after:
            params["after"] = after
        r = sdk.query_assets(**params)
        if r["status_code"] != 200:
            raise RuntimeError(f"query_assets failed: {r['body'].get('errors')}")
        batch = r["body"].get("resources") or []
        ids.extend(batch)
        after = r["body"].get("meta", {}).get("pagination", {}).get("after")
        if not batch or not after:
            break

    assets = []
    for i in range(0, len(ids), 100):
        r = sdk.get_assets(ids=ids[i:i + 100])
        if r["status_code"] != 200:
            raise RuntimeError(f"get_assets failed: {r['body'].get('errors')}")
        assets.extend(r["body"].get("resources") or [])
    return assets


def _image_label(img):
    reg  = (img.get("registry")   or "").strip()
    repo = (img.get("repository") or "").strip()
    tag  = (img.get("tag")        or "latest").strip()
    return f"{reg}/{repo}:{tag}" if reg else f"{repo}:{tag}"


def fetch_images_for_package(ci, package_name_version):
    """Return a deduplicated list of image labels containing this package."""
    images = []
    seen_labels = set()
    offset = 0
    limit = 100
    while True:
        r = ci.ReadCombinedImagesExport(
            filter=f"package_name_version:'{package_name_version}'",
            limit=limit,
            offset=offset,
        )
        if r["status_code"] != 200:
            dbg_response("ReadCombinedImagesExport", r)
            break
        batch = r["body"].get("resources") or []
        for img in batch:
            label = _image_label(img)
            if label not in seen_labels:
                seen_labels.add(label)
                images.append(label)
        if len(batch) < limit:
            break
        offset += len(batch)
    return images


def fetch_ai_critical_packages(sdk, ci, severities):
    target = {s.lower() for s in severities} if severities else None
    packages = []
    after = None
    while True:
        params = {"filter": "ai_related:'true'", "limit": 200}
        if after:
            params["after"] = after
        r = sdk.ReadPackagesCombined(**params)
        if r["status_code"] != 200:
            raise RuntimeError(f"ReadPackagesCombined failed: {r['body'].get('errors')}")
        batch = r["body"].get("resources") or []
        packages.extend(batch)
        after = r["body"].get("meta", {}).get("pagination", {}).get("after")
        if not batch or not after:
            break

    result = []
    for pkg in packages:
        matched = [v for v in (pkg.get("vulnerabilities") or [])
                   if target is None or v.get("severity", "").lower() in target]
        if matched:
            images = fetch_images_for_package(ci, pkg["package_name_version"])
            result.append({
                "package_name_version":    pkg.get("package_name_version", "N/A"),
                "type":                    pkg.get("type", "N/A"),
                "all_images":              pkg.get("all_images", 0),
                "running_images":          pkg.get("running_images", 0),
                "images":                  images,
                "critical_vulnerabilities": matched,
            })
    return result


def _falcon_image_url(img, severities=None):
    """Build Falcon console deep-link for the image vulnerability/layer view."""
    image_id = img.get("image_id", "")
    digest   = img.get("image_digest", "")
    registry = img.get("registry", "")
    repo     = img.get("repository", "")
    tag      = img.get("tag", "")
    if not image_id or not digest:
        return ""
    api_base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
    if api_base == "https://api.crowdstrike.com":
        console = "https://falcon.crowdstrike.com"
    else:
        m = re.search(r"https://api\.([^/]+)\.crowdstrike\.com", api_base)
        console = f"https://{m.group(1)}.falcon.crowdstrike.com" if m else "https://falcon.crowdstrike.com"
    sevs = severities or ["Critical"]
    sev_parts = "+".join(f"severity:'{s}'" for s in sevs)
    return (
        f"{console}/cloud-security/cwpp/image-details/known-issues/vulnerabilities-critical-and-high"
        f"?digest={quote(digest, safe='')}"
        f"&filter={quote(sev_parts, safe='')}"
        f"&id={quote(image_id, safe='')}"
        f"&informativeTab=details"
        f"&registry={quote(registry, safe='')}"
        f"&repository={quote(repo, safe='')}"
        f"&tag={quote(tag, safe='')}"
    )


def fetch_risky_images(ci, cv, severities=None, max_images=10):
    """Fetch images with the given severity CVEs and per-CVE layer details.

    Returns a list of image dicts, each with a 'layers' list grouping CVEs
    by (layer_index, layer_command).  Sorted by vulnerability_count desc.
    """
    target_sevs = severities if severities else []

    # Build FQL filter — empty severities means no severity filter
    if not target_sevs:
        img_fql = None
    elif len(target_sevs) == 1:
        img_fql = f"vulnerability_severity:'{target_sevs[0]}'"
    else:
        joined = ",".join(f"'{s}'" for s in target_sevs)
        img_fql = f"vulnerability_severity:[{joined}]"

    # CVE severity filter for ReadCombinedVulnerabilitiesDetails
    if not target_sevs:
        cve_fql = None
    elif len(target_sevs) == 1:
        cve_fql = f"severity:'{target_sevs[0]}'"
    else:
        joined = ",".join(f"'{s}'" for s in target_sevs)
        cve_fql = f"severity:[{joined}]"

    # Step 1: paginate images
    images = []
    offset = 0
    limit  = 100
    while len(images) < max_images:
        batch_limit = min(limit, max_images - len(images))
        r = ci.GetCombinedImages(filter=img_fql, limit=batch_limit, offset=offset)
        if r["status_code"] != 200:
            raise RuntimeError(f"GetCombinedImages failed: {r['body'].get('errors')}")
        batch = r["body"].get("resources") or []
        images.extend(batch)
        if len(batch) < batch_limit:
            break
        offset += len(batch)

    if not images:
        return []

    def _fetch_details(img):
        image_id = img["image_id"]

        # Get UUID via CombinedImageDetail (ReadCombinedVulnerabilitiesDetails requires UUID)
        r_det = ci.CombinedImageDetail(filter=f"image_id:'{image_id}'", limit=1)
        if r_det["status_code"] != 200 or not (r_det["body"].get("resources") or []):
            return None
        uuid = r_det["body"]["resources"][0].get("uuid", "")
        if not uuid:
            return None

        # Fetch all matching CVEs with offset pagination
        cves, offset, limit = [], 0, 100
        while True:
            kwargs = {"id": uuid, "limit": limit, "offset": offset}
            if cve_fql:
                kwargs["filter"] = cve_fql
            r_cv = cv.ReadCombinedVulnerabilitiesDetails(**kwargs)
            if r_cv["status_code"] != 200:
                break
            page = r_cv["body"].get("resources") or []
            cves.extend(page)
            if len(page) < limit:
                break
            offset += len(page)

        # Group CVEs by (layer_index, layer_command)
        layers_dict = {}
        for c in cves:
            key = (c.get("layer_index", 0), (c.get("layer_command") or "").strip())
            layers_dict.setdefault(key, []).append({
                "cve_id":               c.get("cve_id", ""),
                "severity":             c.get("severity", ""),
                "cvss_score":           str(c.get("cvss_score") or ""),
                "cps_rating":           c.get("cps_current_rating", ""),
                "package_name_version": c.get("package_name_version", ""),
                "exploited":            int(c.get("exploited_status") or 0) > 0,
                "fix_available":        bool(c.get("remediation_available")),
            })

        layers = [
            {"layer_index": k[0], "layer_command": k[1],
             "cves": sorted(v, key=lambda x: float(x["cvss_score"] or 0), reverse=True)}
            for k, v in sorted(layers_dict.items())
        ]

        return {
            "image_id":                    image_id,
            "image_digest":                img.get("image_digest", ""),
            "registry":                    img.get("registry", ""),
            "repository":                  img.get("repository", ""),
            "tag":                         img.get("tag", ""),
            "base_os":                     img.get("base_os", ""),
            "vulnerability_count":         img.get("vulnerabilities", 0),
            "layers_with_vulnerabilities": img.get("layers_with_vulnerabilities", 0),
            "packages":                    img.get("packages", 0),
            "containers":                  img.get("containers", 0),
            "falcon_url":                  _falcon_image_url(img, target_sevs),
            "layers":                      layers,
            "cve_count":                   len(cves),
        }

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_fetch_details, img): img for img in images}
        done = 0
        for future in as_completed(futures):
            done += 1
            print(f"  {T_HINT}  Fetching image details  {T_MUTED}({done}/{len(images)}){T_RESET}",
                  end="\r", flush=True)
            result = future.result()
            if result:
                results.append(result)
    print(flush=True)

    results.sort(key=lambda x: x.get("vulnerability_count", 0), reverse=True)
    return results


def fetch_cloud_apps(csa, limit=50):
    """Fetch ASPM cloud applications via CloudSecurityAssets.

    Returns list of dicts sorted by total vulnerabilities desc.
    """
    ids = []
    after = None
    while len(ids) < limit:
        params = {"filter": "resource_type_name:'Application'", "limit": min(500, limit - len(ids))}
        if after:
            params["after"] = after
        r = csa.query_assets(**params)
        if r["status_code"] != 200:
            dbg_response("query_assets (cloud apps)", r)
            break
        batch = r["body"].get("resources") or []
        ids.extend(batch)
        after = r["body"].get("meta", {}).get("pagination", {}).get("after")
        if not batch or not after:
            break

    apps = []
    for i in range(0, len(ids), 100):
        r = csa.get_assets(ids=ids[i:i + 100])
        if r["status_code"] != 200:
            dbg_response("get_assets (cloud apps)", r)
            continue
        for res in r["body"].get("resources") or []:
            cfg_raw = res.get("configuration") or "{}"
            cfg = json.loads(cfg_raw) if isinstance(cfg_raw, str) else (cfg_raw or {})
            deploy  = cfg.get("deployment") or {}
            summary = cfg.get("summary") or {}
            exprt   = summary.get("reachableVulnerabilitiesExprtRating") or {}
            techs   = cfg.get("technologies") or []
            k8s     = deploy.get("kubernetesDeployment") or {}
            apps.append({
                "name":             res.get("resource_name") or res.get("resource_id", ""),
                "account_id":       res.get("account_id", ""),
                "region":           res.get("region", ""),
                "deployment_type":  deploy.get("deploymentType", ""),
                "deployment_provider": deploy.get("deploymentProvider", ""),
                "k8s_namespace":    k8s.get("namespace", ""),
                "k8s_deployment":   k8s.get("deploymentName", ""),
                "technologies":     techs,
                "total_vulns":      summary.get("vulnerabilities", 0),
                "exprt":            exprt,
            })

    apps.sort(key=lambda x: x["total_vulns"], reverse=True)
    return apps


def fetch_ioms(csd, categories, severities=None):
    """Fetch non-compliant IOM entities for the given category list.

    categories:  list of category names from IOM_CATEGORIES, or ["all"] for no filter.
    severities:  list of severity strings to keep (e.g. ["High","Critical"]), or [] for all.
    Returns [] immediately if categories is empty.
    """
    if not categories:
        return []

    if "all" in categories:
        keywords = None  # accept every resource type
    else:
        keywords = set()
        for cat in categories:
            for kw in IOM_CATEGORIES.get(cat.lower(), []):
                keywords.add(kw.lower())

    # Step 1: scan all entity IDs; filter by resource_type (pipe-segment 4).
    # Entity ID format: cid|provider|account|region|resource_type|resource_id|rule-uuid
    matching_ids = []
    after = None
    page_num = 0
    while True:
        params = {"limit": 500, "filter": "extension_status:'Unresolved'+status:'non-compliant'"}
        if after:
            params["after"] = after
        r = csd.query_iom_entities(**params)
        dbg_response("query_iom_entities", r)
        if r["status_code"] != 200:
            raise RuntimeError(f"query_iom_entities failed: {r['body'].get('errors')}")
        page_ids = r["body"].get("resources") or []
        for eid in page_ids:
            parts = eid.split("|")
            if len(parts) >= 5:
                rt = parts[4].lower()
                if keywords is None or any(kw in rt for kw in keywords):
                    matching_ids.append(eid)
        after = r["body"].get("meta", {}).get("next")
        page_num += 1
        print(f"  {T_DIM}Scanning IOM page {page_num} ({len(matching_ids)} matches so far)...{T_RESET}",
              end="\r", flush=True)
        dbg(f"  page {page_num}: {len(page_ids)} ids, matches: {len(matching_ids)}, next={'...' if after else None}")
        if not page_ids or not after:
            break
    print(flush=True)

    dbg(f"Total IOM entity IDs matched: {len(matching_ids)}")
    if not matching_ids:
        return []

    # Step 2: fetch full entity details in parallel batches
    batches = [matching_ids[i:i + 100] for i in range(0, len(matching_ids), 100)]
    total_batches = len(batches)
    print(f"  {T_DIM}Fetching {len(matching_ids)} IOM entities in {total_batches} parallel batches...{T_RESET}",
          flush=True)

    def _fetch_batch(batch):
        r2 = csd.get_iom_entities(ids=batch)
        dbg_response("get_iom_entities", r2)
        if r2["status_code"] != 200:
            raise RuntimeError(f"get_iom_entities failed: {r2['body'].get('errors')}")
        return r2["body"].get("resources") or []

    completed = 0
    all_entities = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_fetch_batch, b): b for b in batches}
        for fut in as_completed(futures):
            try:
                all_entities.extend(fut.result())
            except Exception as exc:
                print(f"\n  {T_YELLOW}Warning: IOM batch fetch failed — {exc}{T_RESET}", flush=True)
            completed += 1
            print(f"  {T_DIM}Fetching IOM details: {completed}/{total_batches} batches done...{T_RESET}",
                  end="\r", flush=True)
    print(flush=True)

    result = []
    for e in all_entities:
        eval_data = e.get("evaluation", {})
        eval_rule = eval_data.get("rule", {})
        cloud    = e.get("cloud", {})
        resource = e.get("resource", {})
        severity = (eval_data.get("severity") or "").capitalize() or "N/A"
        result.append({
            "entity_id":         e.get("id", ""),
            "resource_id":       resource.get("resource_id", "N/A"),
            "resource_type":     resource.get("resource_type_name") or resource.get("resource_type", "N/A"),
            "resource_type_raw": resource.get("resource_type", "").lower(),
            "service":           resource.get("service", "N/A"),
            "provider":      (cloud.get("provider") or "").upper(),
            "account_id":    cloud.get("account_id", "N/A"),
            "account_name":  cloud.get("account_name", "N/A"),
            "region":        cloud.get("region", "N/A"),
            "rule_name":     eval_rule.get("name", "N/A"),
            "severity":      severity,
            "description":   _strip_html(eval_rule.get("description", "")),
            "remediation":   _strip_html(eval_rule.get("remediation", "")),
        })

    if severities:
        sev_set = {s.lower() for s in severities}
        result = [r for r in result if r["severity"].lower() in sev_set]

    return result

def t_label(text):
    return f"{T_LABEL}{text}{T_RESET}"


def print_risks(risks):
    _banner("CLOUD RISKS", len(risks))

    if not risks:
        print(f"\n  {T_WARN}No risks found matching the filter.{T_RESET}\n")
        return

    for i, risk in enumerate(risks, 1):
        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(risks)}]{T_RESET}")
        print(f"  {t_label('Rule:     ')} {T_BOLD}{T_VALUE}{risk.get('rule_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Desc:     ')} {T_VALUE}{risk.get('rule_description', 'N/A')}{T_RESET}")
        print(f"  {t_label('Severity: ')} {t_severity(risk.get('severity', 'N/A'))}")
        print(f"  {t_label('Status:   ')} {T_BOLD}{T_WARN}{risk.get('status', 'N/A')}{T_RESET}")
        print(f"  {t_label('Asset:    ')} {T_ACCENT}{risk.get('asset_name', 'N/A')}{T_MUTED} ({risk.get('asset_type', 'N/A')}){T_RESET}")
        print(f"  {t_label('Provider: ')} {T_BOLD}{T_VALUE}{(risk.get('cloud_provider') or '').upper()}{T_RESET}")
        print(f"  {t_label('Account:  ')} {T_VALUE}{risk.get('account_name', 'N/A')}{T_MUTED} ({risk.get('account_id', 'N/A')}){T_RESET}")
        print(f"  {t_label('Region:   ')} {T_VALUE}{risk.get('asset_region', 'N/A')}{T_RESET}")
        print(f"  {t_label('Category: ')} {T_VALUE}{risk.get('service_category', 'N/A')}{T_RESET}")
        print(f"  {t_label('First Seen:')} {T_MUTED}{risk.get('first_seen', 'N/A')}{T_RESET}")
        print(f"  {t_label('Last Seen: ')} {T_MUTED}{risk.get('last_seen', 'N/A')}{T_RESET}")

        risk_factors = risk.get("risk_factors") or risk.get("risk_factor") or []
        if risk_factors:
            print(f"\n  {T_BOLD}{T_ACCENT}  Risk Factors{T_RESET}")
            for factor in risk_factors:
                print(f"\n    {T_BOLD}{T_VALUE}{factor.get('insight_name', 'N/A')}{T_RESET}")
                for remediation in factor.get("remediation") or []:
                    print(f"\n      {T_BOLD}{T_WARN}{remediation.get('title', '')}{T_RESET}")
                    for line in remediation.get("content", "").splitlines():
                        for wrapped_line in textwrap.wrap(line, width=56) or [""]:
                            print(f"      {T_DIM}{T_VALUE}{wrapped_line}{T_RESET}")

        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()


def print_cloud_ioas(ioas):
    _banner("CLOUD IOA DETECTIONS", len(ioas))

    if not ioas:
        print(f"\n  {T_WARN}No Cloud IOA detections found.{T_RESET}\n")
        return

    for i, ioa in enumerate(ioas, 1):
        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(ioas)}]{T_RESET}")
        print(f"  {t_label('Name:     ')} {T_BOLD}{T_VALUE}{ioa.get('display_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Severity: ')} {t_severity(ioa.get('severity_name', 'N/A'))}")
        print(f"  {t_label('Provider: ')} {T_BOLD}{T_VALUE}{(ioa.get('cloud_provider') or '').upper()}{T_RESET}")
        print(f"  {t_label('Account:  ')} {T_VALUE}{ioa.get('cloud_account_id', 'N/A')}{T_RESET}")
        print(f"  {t_label('Region:   ')} {T_VALUE}{ioa.get('cloud_region', 'N/A')}{T_RESET}")
        print(f"  {t_label('Service:  ')} {T_VALUE}{ioa.get('service', 'N/A')}{T_RESET}")
        print(f"  {t_label('Tactic:   ')} {T_VALUE}{ioa.get('tactic', 'N/A')}{T_RESET}")
        print(f"  {t_label('Technique:')} {T_VALUE}{ioa.get('technique', 'N/A')}{T_RESET}")
        print(f"  {t_label('User:     ')} {T_VALUE}{ioa.get('user_display_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Timestamp:')} {T_MUTED}{ioa.get('timestamp', 'N/A')}{T_RESET}")
        desc = ioa.get('description', '')
        if desc:
            print(f"  {t_label('Desc:     ')} {T_VALUE}{desc[:120]}{'...' if len(desc) > 120 else ''}{T_RESET}")
        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()


def print_vms(vm_data):
    _banner("UNMANAGED RUNNING VMs")

    for provider, assets in vm_data.items():
        print(f"\n  {T_BOLD}{T_HEADER}{provider}{T_RESET}  {T_MUTED}{len(assets)} asset(s){T_RESET}")
        if not assets:
            print(f"  {T_WARN}  No assets found.{T_RESET}\n")
            continue
        print(f"  {T_MUTED}{'Resource ID':<45}  Account ID{T_RESET}")
        print(f"  {T_MUTED}{'─' * 62}{T_RESET}")
        for asset in assets:
            print(f"  {T_ACCENT}{asset.get('resource_id', 'N/A'):<45}{T_RESET}  {T_VALUE}{asset.get('account_id', 'N/A')}{T_RESET}")
        print()


def print_ai_packages(packages):
    _banner("AI PACKAGE RISKS — CRITICAL CVEs", len(packages))

    if not packages:
        print(f"\n  {T_WARN}No AI-related packages with Critical CVEs found.{T_RESET}\n")
        return

    for i, pkg in enumerate(packages, 1):
        vulns = pkg["critical_vulnerabilities"]
        images = pkg.get("images") or []
        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(packages)}]{T_RESET}")
        print(f"  {t_label('Package:  ')} {T_BOLD}{T_VALUE}{pkg['package_name_version']}{T_RESET}")
        print(f"  {t_label('Type:     ')} {T_VALUE}{pkg['type']}{T_RESET}")
        print(f"  {t_label('Images:   ')} {T_VALUE}{pkg['all_images']} total  |  {pkg['running_images']} running{T_RESET}")
        if images:
            for img_name in images:
                print(f"              {T_MUTED}{img_name}{T_RESET}")
        print(f"  {t_label('Critical: ')} {T_BOLD}{T_CRITICAL}{len(vulns)} CVE(s){T_RESET}")
        for v in vulns:
            fix = v.get("fix_resolution") or []
            fix_str = ", ".join(fix) if fix else "No fix available"
            print(f"\n    {T_BOLD}{T_CRITICAL}{v.get('cveid', 'N/A')}{T_RESET}")
            print(f"    {t_label('Fix:      ')} {T_WARN}{fix_str}{T_RESET}")
            desc = (v.get("description") or "").strip()
            if desc:
                short = desc[:160].replace("\n", " ")
                print(f"    {t_label('Desc:     ')} {T_MUTED}{short}{'...' if len(desc) > 160 else ''}{T_RESET}")
        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()


def print_risky_images(images):
    _banner("RISKY IMAGES — CVE LAYER BREAKDOWN", len(images))

    if not images:
        print(f"\n  {T_WARN}No images with matching CVEs found.{T_RESET}\n")
        return

    for i, img in enumerate(images, 1):
        label = f"{img.get('registry', '')}/{img.get('repository', '')}:{img.get('tag', '')}"
        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(images)}]  {label}{T_RESET}")
        print(f"  {t_label('OS:        ')} {T_VALUE}{img.get('base_os') or 'N/A'}{T_RESET}")
        print(f"  {t_label('CVE Count: ')} {T_BOLD}{T_CRITICAL}{img.get('cve_count', 0)}{T_RESET}")
        layers = img.get("layers") or []
        for layer in layers:
            cmd = layer["layer_command"] or "(no command)"
            print(f"\n    {T_BOLD}{T_HEADER}Layer {layer['layer_index']}:{T_RESET}  {T_MUTED}{cmd[:80]}{T_RESET}")
            for cve in layer["cves"]:
                exploit = f"  {T_CRITICAL}[EXPLOIT]{T_RESET}" if cve["exploited"] else ""
                fix = f"  {T_SUCCESS}[FIX AVAILABLE]{T_RESET}" if cve["fix_available"] else ""
                print(f"      {T_BOLD}{T_CRITICAL}{cve['cve_id']}{T_RESET}  "
                      f"{T_MUTED}CVSS {cve['cvss_score'] or 'N/A'}{T_RESET}  "
                      f"{T_VALUE}{cve.get('package_name_version', '')}{T_RESET}"
                      f"{exploit}{fix}")
        if img.get("falcon_url"):
            print(f"\n    {t_label('Falcon:    ')} {T_HINT}{img['falcon_url'][:100]}{T_RESET}")
        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()


def print_cloud_apps(apps):
    _banner("CLOUD APPLICATIONS", len(apps))

    if not apps:
        print(f"\n  {T_WARN}No cloud applications found.{T_RESET}\n")
        return

    for i, app in enumerate(apps, 1):
        techs = ", ".join(app["technologies"]) if app["technologies"] else "N/A"
        exprt = app["exprt"]
        exprt_parts = []
        for sev in ("critical", "high", "medium", "low"):
            v = exprt.get(sev, 0)
            if v:
                exprt_parts.append(f"{v} {sev.capitalize()}")
        exprt_str = "  |  ".join(exprt_parts) if exprt_parts else "None"

        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(apps)}]  {app['name']}{T_RESET}")
        print(f"  {t_label('Deployment:   ')} {T_VALUE}{app['deployment_type']}{T_RESET}")
        print(f"  {t_label('Technologies: ')} {T_VALUE}{techs}{T_RESET}")
        if app["k8s_namespace"]:
            print(f"  {t_label('Namespace:    ')} {T_MUTED}{app['k8s_namespace']}{T_RESET}")
        print(f"  {t_label('Account:      ')} {T_VALUE}{app['account_id']}{T_RESET}")
        print(f"  {t_label('Region:       ')} {T_VALUE}{app['region']}{T_RESET}")
        print(f"  {t_label('Vulns:        ')} {T_BOLD}{T_CRITICAL if app['total_vulns'] else T_MUTED}{app['total_vulns']}{T_RESET}")
        print(f"  {t_label('ExPRT:        ')} {T_WARN}{exprt_str}{T_RESET}")
        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()


def print_ai_ioms(ioms):
    _banner("AI CLOUD SERVICES — ACTIVE MISCONFIGURATIONS", len(ioms))

    if not ioms:
        print(f"\n  {T_WARN}No active AI service misconfigurations found.{T_RESET}\n")
        return

    for i, iom in enumerate(ioms, 1):
        print(f"\n  {T_BOLD}{T_VALUE}[{i} of {len(ioms)}]{T_RESET}")
        print(f"  {t_label('Resource:     ')} {T_BOLD}{T_ACCENT}{iom['resource_id']}{T_RESET}")
        print(f"  {t_label('Type:         ')} {T_VALUE}{iom['resource_type']}{T_MUTED}  [{iom.get('resource_type_raw', '')}]{T_RESET}")
        print(f"  {t_label('Service:      ')} {T_VALUE}{iom['service']}{T_RESET}")
        print(f"  {t_label('Provider:     ')} {T_BOLD}{T_VALUE}{iom['provider']}{T_RESET}")
        print(f"  {t_label('Account:      ')} {T_VALUE}{iom['account_name']}{T_MUTED} ({iom['account_id']}){T_RESET}")
        print(f"  {t_label('Region:       ')} {T_VALUE}{iom['region']}{T_RESET}")
        print(f"  {t_label('Rule:         ')} {T_BOLD}{T_VALUE}{iom['rule_name']}{T_RESET}")
        print(f"  {t_label('Severity:     ')} {t_severity(iom['severity'])}")
        if iom.get("description"):
            desc = iom["description"][:160].replace("\n", " ")
            print(f"  {t_label('Description:  ')} {T_VALUE}{desc}{T_RESET}")
        if iom.get("remediation"):
            steps = iom["remediation"].split("|\n")
            print(f"\n  {T_BOLD}{T_ACCENT}  Remediation{T_RESET}")
            for step in steps:
                step = step.strip()
                if step:
                    for wrapped in textwrap.wrap(step, width=56) or [step]:
                        print(f"    {T_MUTED}{wrapped}{T_RESET}")
        print(f"\n  {T_MUTED}{'─' * 62}{T_RESET}")
    print()

def _arn_name(rid):
    """Return the leaf name from an ARN, or rid unchanged if it isn't one.

    arn:aws:iam::123456789012:role/my-role  →  my-role
    arn:aws:iam::123456789012:policy/MyPolicy  →  MyPolicy
    """
    if rid.startswith("arn:"):
        parts = rid.split(":")
        if len(parts) >= 6:
            last = parts[-1]          # e.g. "role/my-role"
            name = last.split("/")[-1] if "/" in last else last
            return name or rid        # guard against trailing-slash ARNs
    return rid


def _falcon_iom_url(iom):
    """Build a Falcon console deep-link for the given IOM entity.

    Primary: entity_id path targets the specific entity directly.
    Filter includes resource_id so that if the path redirects to the list view,
    the list is still scoped to the exact resource rather than all rule violations.

    Entity ID format: cid|provider|account|region|resource_type|resource_id|rule-uuid
    """
    entity_id = iom.get("entity_id", "")
    if not entity_id:
        return ""

    api_base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
    if api_base == "https://api.crowdstrike.com":
        console = "https://falcon.crowdstrike.com"
    else:
        m = re.search(r"https://api\.([^/]+)\.crowdstrike\.com", api_base)
        if m:
            console = f"https://{m.group(1)}.falcon.crowdstrike.com"
        else:
            dbg(f"[_falcon_iom_url] unrecognised base URL {api_base!r}; defaulting to US-1 console")
            console = "https://falcon.crowdstrike.com"

    parts = entity_id.split("|")
    resource_id = parts[5] if len(parts) >= 6 else ""  # segment 5 = resource_id
    rule_uuid   = parts[6] if len(parts) >= 7 else ""  # segment 6 = rule UUID
    severity    = (iom.get("severity") or "high").lower()

    # Pipes encode as %7C; forward slashes in resource_id (e.g. ECR repo names) encode as %2F
    encoded_id = entity_id.replace("|", "%7C").replace("/", "%2F")

    filter_str = (
        f"extension_status:'Unresolved'"
        f"+severity:'{severity}'"
        + (f"+rule_id:'{rule_uuid}'"       if rule_uuid   else "")
        + (f"+resource_id:'{resource_id}'" if resource_id else "")
    )
    encoded_filter = quote(filter_str, safe="")

    return (
        f"{console}/cloud-security/cspm/assessment/ng-configuration"
        f"/{encoded_id}/summary"
        f"?filter={encoded_filter}&summaryTab=1&view=iom"
    )


def _console_url(iom):
    """Build a cloud console deep-link URL for the given IOM resource dict."""
    provider = (iom.get("provider") or "").upper()
    raw      = (iom.get("resource_type_raw") or "").lower()
    rid      = (iom.get("resource_id") or "").strip()
    region   = (iom.get("region") or "us-east-1").strip()
    acct     = (iom.get("account_id") or "").strip()

    if provider == "AWS":
        b = "https://console.aws.amazon.com"
        if "::ec2::instance"       in raw: return f"{b}/ec2/v2/home?region={region}#Instances:instanceId={rid}"
        if "::ec2::securitygroup"  in raw: return f"{b}/vpc/home?region={region}#securityGroups:groupId={rid}"
        if "::ec2::snapshot"       in raw: return f"{b}/ec2/v2/home?region={region}#Snapshots:snapshotId={rid}"
        if "::ec2::volume"         in raw: return f"{b}/ec2/v2/home?region={region}#Volumes:volumeId={rid}"
        if "::ec2::image"          in raw: return f"{b}/ec2/v2/home?region={region}#Images:imageId={rid}"
        if "::ec2::eip"            in raw: return f"{b}/ec2/v2/home?region={region}#Addresses:AllocationId={rid}"
        if "::autoscaling::"       in raw: return f"{b}/ec2/v2/home?region={region}#AutoScalingGroups:id={rid};view=details"
        if "::elasticloadbalancing" in raw: return f"{b}/ec2/v2/home?region={region}#LoadBalancers:search={rid};sort=loadBalancerName"
        if "::ec2::vpc"            in raw: return f"{b}/vpc/home?region={region}#vpcs:VpcId={rid}"
        if "::ec2::subnet"         in raw: return f"{b}/vpc/home?region={region}#subnets:SubnetId={rid}"
        if "::ec2::networkacl"     in raw: return f"{b}/vpc/home?region={region}#acls:AclId={rid}"
        if "::ec2::routetable"     in raw: return f"{b}/vpc/home?region={region}#RouteTables:RouteTableId={rid}"
        if "::s3::"                in raw: return f"https://s3.console.aws.amazon.com/s3/buckets/{rid}"
        if "::iam::role"           in raw: return f"{b}/iam/home#/roles/{_arn_name(rid)}"
        if "::iam::user"           in raw: return f"{b}/iam/home#/users/{_arn_name(rid)}"
        if "::iam::policy"         in raw: return f"{b}/iam/home#/policies/{rid}"
        if "::iam::group"          in raw: return f"{b}/iam/home#/groups/{_arn_name(rid)}"
        if "::iam::" in raw or raw == "aws::iam":
            # Sub-type not recognised — try to infer from the resource ID ARN
            rid_lower = rid.lower()
            if ":role/" in rid_lower:    return f"{b}/iam/home#/roles/{_arn_name(rid)}"
            if ":user/" in rid_lower:    return f"{b}/iam/home#/users/{_arn_name(rid)}"
            if ":policy/" in rid_lower:  return f"{b}/iam/home#/policies/{rid}"
            if ":group/" in rid_lower:   return f"{b}/iam/home#/groups/{_arn_name(rid)}"
            return f"{b}/iam/home"
        if "::lambda::"            in raw: return f"{b}/lambda/home?region={region}#/functions/{_arn_name(rid)}"
        if "::rds::"               in raw: return f"{b}/rds/home?region={region}#database:id={rid}"
        if "::athena::"            in raw: return f"{b}/athena/home?region={region}"
        if "::glue::"              in raw: return f"{b}/glue/home?region={region}"
        if "::ecr::repository"     in raw: return f"{b}/ecr/repositories/private/{acct}/{rid}?region={region}"
        if "::ecr::"               in raw: return f"{b}/ecr/repositories?region={region}"
        if "::eks::"               in raw: return f"{b}/eks/home?region={region}#/clusters/{rid}"
        if "::ecs::cluster"        in raw: return f"{b}/ecs/home?region={region}#/clusters/{rid}"
        if "::ecs::"               in raw: return f"{b}/ecs/home?region={region}"
        if "::eventbridge::"       in raw: return f"{b}/events/home?region={region}"
        if "::kms::"               in raw: return f"{b}/kms/home?region={region}#/kms/keys/{_arn_name(rid)}"
        if "::secretsmanager::"    in raw: return f"{b}/secretsmanager/home?region={region}#!/secret?name={_arn_name(rid)}"
        if "::sagemaker::notebookinstance" in raw: return f"{b}/sagemaker/home?region={region}#/notebook-instances/{rid}"
        if "::sagemaker::model"    in raw: return f"{b}/sagemaker/home?region={region}#/models/{rid}"
        if "::sagemaker::endpoint" in raw: return f"{b}/sagemaker/home?region={region}#/endpoints/{rid}"
        if "::sagemaker::"         in raw: return f"{b}/sagemaker/home?region={region}"
        if "::bedrock::"           in raw: return f"{b}/bedrock/home?region={region}"
        if "::cloudtrail::"        in raw: return f"{b}/cloudtrail/home?region={region}#/trails/{_arn_name(rid)}" if rid and rid != "N/A" else f"{b}/cloudtrail/home?region={region}#/trails"
        if "::cloudformation::stack" in raw: return f"{b}/cloudformation/home?region={region}#/stacks/stackinfo?stackId={rid}"
        if "::cloudformation::"    in raw: return f"{b}/cloudformation/home?region={region}"
        if "::logs::loggroup"      in raw: return f"{b}/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{quote(rid, safe='')}"
        if "::organizations::"     in raw: return f"{b}/organizations/v2/home"
        if "::account::"           in raw: return f"{b}/account/home"
        return f"{b}/console/home?region={region}"

    if provider == "GCP":
        b = "https://console.cloud.google.com"
        # rid holds the full GCP resource name: //SERVICE.googleapis.com/projects/{proj_id}/...
        # account_id holds "projects/{PROJECT_NUMBER}" (numeric); proj_id is the human-readable slug
        m_proj     = re.search(r'/projects/([^/]+)', rid)
        proj_id    = m_proj.group(1) if m_proj else acct.split("/")[-1]
        m_zone     = re.search(r'/zones/([^/]+)/', rid + "/")
        zone       = m_zone.group(1) if m_zone else ""
        m_reg      = re.search(r'/regions/([^/]+)/', rid + "/")
        rid_region = m_reg.group(1) if m_reg else ""
        m_loc      = re.search(r'/locations/([^/]+)/', rid + "/")
        loc        = m_loc.group(1) if m_loc else ""
        name       = rid.rstrip("/").split("/")[-1] if rid else ""

        # instancegroupmanager before instance; subnetwork before network;
        # nodepool/serviceaccountkey before their base types.
        if "compute.googleapis.com/instancegroupmanager" in raw:
            z = zone or rid_region
            scope = "regions" if (rid_region and not zone) else "zones"
            if z and name:
                return f"{b}/compute/instanceGroups/details/{scope}/{z}/{name}?project={proj_id}"
            return f"{b}/compute/instancegroups/list?project={proj_id}"

        if "compute.googleapis.com/instance" in raw:
            if zone and name:
                return f"{b}/compute/instancesDetail/zones/{zone}/instances/{name}?project={proj_id}"
            return f"{b}/compute/instances?project={proj_id}"

        if "compute.googleapis.com/disk" in raw:
            if zone and name:
                return f"{b}/compute/disksDetail/zones/{zone}/disks/{name}?project={proj_id}"
            return f"{b}/compute/disks?project={proj_id}"

        if "compute.googleapis.com/firewall" in raw:
            if name:
                return f"{b}/networking/firewalls/details/{name}?project={proj_id}"
            return f"{b}/networking/firewalls/list?project={proj_id}"

        if "compute.googleapis.com/subnetwork" in raw:
            r_sub = rid_region or region
            if r_sub and name:
                return f"{b}/networking/subnetworks/details/{r_sub}/{name}?project={proj_id}"
            return f"{b}/networking/subnetworks/list?project={proj_id}"

        if "compute.googleapis.com/network" in raw:
            if name:
                return f"{b}/networking/networks/details/{name}?project={proj_id}"
            return f"{b}/networking/networks/list?project={proj_id}"

        if "storage.googleapis.com" in raw:
            # rid: //storage.googleapis.com/{bucket-name} — name is the bucket
            if name:
                return f"{b}/storage/browser/{name}?project={proj_id}"
            return f"{b}/storage/browser?project={proj_id}"

        if "container.googleapis.com/nodepool" in raw:
            # rid: .../clusters/{cluster}/nodePools/{pool}
            parts_rid = rid.rstrip("/").split("/")
            pool    = parts_rid[-1] if parts_rid else name
            cluster = parts_rid[-3] if len(parts_rid) >= 3 else ""
            z = zone or rid_region or loc
            if z and cluster:
                return f"{b}/kubernetes/clusters/details/{z}/{cluster}/node-pools/{pool}?project={proj_id}"
            return f"{b}/kubernetes/list?project={proj_id}"

        if "container.googleapis.com" in raw:
            z = zone or rid_region or loc
            if z and name:
                return f"{b}/kubernetes/clusters/details/{z}/{name}?project={proj_id}"
            return f"{b}/kubernetes/list?project={proj_id}"

        if "iam.googleapis.com/serviceaccountkey" in raw:
            # rid: .../serviceAccounts/{sa_email}/keys/{key_id}
            parts_rid = rid.rstrip("/").split("/")
            sa = parts_rid[-3] if len(parts_rid) >= 3 else ""
            if sa:
                return f"{b}/iam-admin/serviceaccounts/details/{sa}/keys?project={proj_id}"
            return f"{b}/iam-admin/serviceaccounts?project={proj_id}"

        if "iam.googleapis.com/serviceaccount" in raw:
            if name:
                return f"{b}/iam-admin/serviceaccounts/details/{name}?project={proj_id}"
            return f"{b}/iam-admin/serviceaccounts?project={proj_id}"

        if "iam.googleapis.com" in raw:
            return f"{b}/iam-admin/iam?project={proj_id}"

        if "aiplatform.googleapis.com" in raw:
            return f"{b}/vertex-ai?project={proj_id}"

        if "secretmanager.googleapis.com" in raw:
            if name:
                return f"{b}/security/secret-manager/secret/{name}?project={proj_id}"
            return f"{b}/security/secret-manager?project={proj_id}"

        if "pubsub.googleapis.com" in raw:
            if name:
                return f"{b}/cloudpubsub/topic/detail/{name}?project={proj_id}"
            return f"{b}/cloudpubsub/topic/list?project={proj_id}"

        if "artifactregistry.googleapis.com" in raw:
            if loc and name:
                return f"{b}/artifacts/docker/{proj_id}/{loc}/{name}?project={proj_id}"
            return f"{b}/artifacts?project={proj_id}"

        if "logging.googleapis.com" in raw:
            return f"{b}/logs?project={proj_id}"

        if "cloudresourcemanager.googleapis.com" in raw:
            return f"{b}/home/dashboard?project={proj_id}"

        return f"{b}/home/dashboard?project={proj_id}"

    if provider in ("AZURE", "MICROSOFT"):
        if rid.startswith("/subscriptions/"):
            return f"https://portal.azure.com/#resource{rid}"
        return "https://portal.azure.com"

    return ""


def _render_toc(pdf, outline):
    W = pdf.epw
    pdf.set_y(pdf.t_margin + 6)

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*CS_RED)
    pdf.cell(0, 14, "Contents", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # Red rule under title
    pdf.set_draw_color(*CS_RED)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + W, pdf.get_y())
    pdf.ln(6)

    # Column headers
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*MID_GRAY)
    pdf.set_x(pdf.l_margin + 3)
    pdf.cell(W - 20, 7, "SECTION")
    pdf.cell(20, 7, "PAGE", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Thin rule under column headers
    pdf.set_draw_color(*LIGHT_GRAY)
    pdf.set_line_width(0.3)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + W, pdf.get_y())
    pdf.ln(4)

    for idx, section in enumerate(outline):
        link_id = pdf.add_link(page=section.page_number)
        name    = sanitize(section.name)
        pg_str  = str(section.page_number)

        # Alternating row tint
        if idx % 2 == 0:
            pdf.set_fill_color(*SECTION_BG)
            pdf.rect(pdf.l_margin, pdf.get_y(), W, 11, "F")

        # Section name (clickable)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*DARK)
        pdf.set_x(pdf.l_margin + 3)
        pdf.cell(W - 20, 11, name, link=link_id)

        # Page number (amber, right-aligned, clickable)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*AMBER)
        pdf.cell(20, 11, pg_str, align="R", link=link_id,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(3)


class FalconReport(FPDF):
    LABEL_W = 34

    def header(self):
        if self.page_no() <= 2:  # Skip cover (1) and TOC (2)
            return
        self.set_fill_color(*DARK)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*CS_RED)
        self.set_y(6)
        self.cell(0, 8, "CROWDSTRIKE FALCON CLOUD SECURITY", align="C")
        self.set_y(self.t_margin)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 8, f"Generated {now_utc()}  |  Page {self.page_no()}", align="C")

    def cover(self, risks_count=None, ioas_count=None, vm_totals=None,
              ai_packages_count=None, ioms_count=None, ioms_label="",
              risky_images_count=None, cloud_apps_count=None,
              ai_services_count=None, filter_desc=""):
        self.set_fill_color(*DARK)
        self.rect(0, 0, 210, 297, "F")
        self.set_y(80)
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(*WHITE)
        self.cell(0, 14, "Falcon Cloud Security", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Helvetica", "", 14)
        self.set_text_color(*CS_RED)
        self.cell(0, 10, "Security Report", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Add date subtitle
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 8, datetime.now(timezone.utc).strftime("%B %d, %Y"), align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(8)

        if risks_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"Cloud Risks:  {risks_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if ioas_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"Cloud IOA Detections:  {ioas_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if vm_totals:
            total_vms = sum(vm_totals.values())
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"Unmanaged Virtual Machines:  {total_vms}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            for provider, count in vm_totals.items():
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*MID_GRAY)
                self.cell(0, 5, f"({provider}: {count})", align="C",
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if ai_packages_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"AI Package Risks (Critical CVEs):  {ai_packages_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if ioms_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            label = f"Cloud Service IOMs ({ioms_label}):  {ioms_count}" if ioms_label else f"Cloud Service IOMs:  {ioms_count}"
            self.cell(0, 8, label, align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if risky_images_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"Risky Images:  {risky_images_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if cloud_apps_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"Cloud Applications:  {cloud_apps_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if ai_services_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"AI Services (IOMs):  {ai_services_count}", align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        if filter_desc:
            self.ln(6)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 6, sanitize(f"Filters: {filter_desc}"), align="C",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(10)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 7, f"Generated: {now_utc_detailed()}", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def section_header(self, title):
        if self.get_y() > self.h - self.b_margin - 20:
            self.add_page()
        self.set_fill_color(*CS_RED)
        self.rect(self.l_margin, self.get_y(), self.epw, 12, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 12, sanitize(f"  {title}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def section_group_header(self, label):
        """Full-width grey banner dividing the 4 report groups."""
        self.set_fill_color(*MID_GRAY)
        self.rect(self.l_margin, self.get_y(), self.epw, 14, "F")
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 14, sanitize(f"  {label}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

    def sub_header(self, title):
        if self.get_y() > self.h - self.b_margin - 20:
            self.add_page()
        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 8, f"  {title}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def row(self, field, value, alt=False):
        text = sanitize(str(value or "N/A"))
        self.set_font("Helvetica", "", 8)
        col_w = self.epw - self.LABEL_W
        char_w = self.get_string_width("m") or 2.5
        chars_per_line = max(1, int(col_w / char_w))
        n_lines = max(1, -(-len(text) // chars_per_line))
        row_h = n_lines * 6 + 2
        if self.get_y() + row_h > self.h - self.b_margin:
            self.add_page()

        fill_color = SECTION_BG if alt else WHITE
        self.set_fill_color(*fill_color)
        row_y = self.get_y()

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(self.l_margin, row_y)
        self.multi_cell(self.LABEL_W, 6, field, fill=True,
                        new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*DARK)
        self.set_xy(self.l_margin + self.LABEL_W, row_y)
        self.multi_cell(self.epw - self.LABEL_W, 6, text, fill=True,
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def link_row(self, field, url, alt=False):
        if not url:
            return
        col_w = self.epw - self.LABEL_W
        if self.get_y() + 8 > self.h - self.b_margin:
            self.add_page()
        fill_color = SECTION_BG if alt else WHITE
        self.set_fill_color(*fill_color)
        row_y = self.get_y()

        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*MID_GRAY)
        self.set_xy(self.l_margin, row_y)
        self.multi_cell(self.LABEL_W, 6, field, fill=True,
                        new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*LINK_BLUE)
        self.set_xy(self.l_margin + self.LABEL_W, row_y)
        display = sanitize(url[:90] + ("..." if len(url) > 90 else ""))
        self.cell(col_w, 6, display, fill=True, link=url,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(*DARK)

    def _separator(self):
        if self.get_y() + 10 > self.h - self.b_margin:
            self.add_page()
        self.set_draw_color(*LIGHT_GRAY)
        self.line(self.l_margin, self.get_y(), self.l_margin + self.epw, self.get_y())
        self.ln(8)

    def risk_card(self, i, total, risk):
        if self.get_y() > self.h - self.b_margin - 80:
            self.add_page()

        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10, sanitize(f"  [{i} of {total}]  {risk.get('rule_name', 'N/A')}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        fields = [
            ("Description", risk.get("rule_description")),
            ("Severity",    risk.get("severity")),
            ("Status",      risk.get("status")),
            ("Asset",       f"{risk.get('asset_name', 'N/A')} ({risk.get('asset_type', 'N/A')})"),
            ("Provider",    (risk.get("cloud_provider") or "").upper()),
            ("Account",     f"{risk.get('account_name', 'N/A')} ({risk.get('account_id', 'N/A')})"),
            ("Region",      risk.get("asset_region")),
            ("Category",    risk.get("service_category")),
            ("First Seen",  risk.get("first_seen")),
            ("Last Seen",   risk.get("last_seen")),
        ]
        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)
        self.ln(3)

        risk_factors = risk.get("risk_factors") or risk.get("risk_factor") or []
        if risk_factors:
            self.sub_header("Risk Factors")
            for factor in risk_factors:
                if self.get_y() > self.h - self.b_margin - 30:
                    self.add_page()
                self.set_fill_color(*LIGHT_GRAY)
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(*DARK)
                self.set_x(self.l_margin)
                self.cell(self.epw, 7, sanitize(f"  {factor.get('insight_name', 'N/A')}"),
                          fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for remediation in factor.get("remediation") or []:
                    if self.get_y() > self.h - self.b_margin - 25:
                        self.add_page()
                    self.set_font("Helvetica", "B", 8)
                    self.set_text_color(*AMBER)
                    self.set_x(self.l_margin + 4)
                    self.cell(self.epw - 4, 6, sanitize(remediation.get("title", "")),
                              new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    self.set_font("Helvetica", "", 7.5)
                    self.set_text_color(*MID_GRAY)
                    self.set_x(self.l_margin + 4)
                    self.multi_cell(self.epw - 4, 5.5, sanitize(remediation.get("content", "")),
                                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    self.ln(1)

        self._separator()

    def ioa_card(self, i, total, ioa):
        if self.get_y() > self.h - self.b_margin - 105:
            self.add_page()

        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10, sanitize(f"  [{i} of {total}]  {ioa.get('display_name', 'N/A')}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        tactic = ioa.get("tactic", "")
        tactic_id = ioa.get("tactic_id", "")
        technique = ioa.get("technique", "")
        technique_id = ioa.get("technique_id", "")
        tactic_str = f"{tactic} ({tactic_id})" if tactic_id else tactic
        technique_str = f"{technique} ({technique_id})" if technique_id else technique

        desc = ioa.get("description") or ""
        fields = [
            ("Description",  desc[:300] + ("..." if len(desc) > 300 else "")),
            ("Severity",     ioa.get("severity_name")),
            ("Provider",     (ioa.get("cloud_provider") or "").upper()),
            ("Account",      ioa.get("cloud_account_id")),
            ("Region",       ioa.get("cloud_region")),
            ("Service",      ioa.get("service")),
            ("Tactic",       tactic_str),
            ("Technique",    technique_str),
            ("User",         ioa.get("user_display_name")),
            ("Event",        ioa.get("event_name")),
            ("Status",       ioa.get("status")),
            ("Timestamp",    ioa.get("timestamp")),
        ]
        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)
        self.ln(3)

        self._separator()

    def vm_table(self, assets):
        if not assets:
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 8, "  No unmanaged virtual machines found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)
            return

        col_w = self.epw / 2

        def _table_header():
            self.set_fill_color(*DARK)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*WHITE)
            self.set_x(self.l_margin)
            self.cell(col_w, 7, "  Resource ID", fill=True)
            self.cell(col_w, 7, "  Account ID", fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        _table_header()

        for idx, asset in enumerate(assets):
            if self.get_y() + 6.5 > self.h - self.b_margin:
                self.add_page()
                _table_header()

            # Use original CloudSecurityAssets data structure
            rid = asset.get("resource_id") or asset.get("id", "N/A")
            account_id = asset.get("account_id", "N/A")

            # Truncate long resource IDs for display
            rid_display = rid if len(rid) <= 45 else rid[:42] + "..."

            self.set_fill_color(*(SECTION_BG if idx % 2 == 0 else WHITE))
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*DARK)
            self.set_x(self.l_margin)
            self.cell(col_w, 6.5, f"  {rid_display}", fill=True)
            self.cell(col_w, 6.5, f"  {account_id}", fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(4)

    def ai_package_card(self, i, total, pkg):
        if self.get_y() > self.h - self.b_margin - 70:
            self.add_page()

        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10,
                  sanitize(f"  [{i} of {total}]  {pkg['package_name_version']}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        vulns = pkg["critical_vulnerabilities"]
        fields = [
            ("Type",           pkg.get("type")),
            ("All Images",     pkg.get("all_images", 0)),
            ("Running Images", pkg.get("running_images", 0)),
            ("Critical CVEs",  len(vulns)),
        ]
        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)

        images = pkg.get("images") or []
        if images:
            self.ln(2)
            self.sub_header("Images")
            for img_name in images:
                if self.get_y() > self.h - self.b_margin - 10:
                    self.add_page()
                self.set_font("Helvetica", "", 8)
                self.set_text_color(*MID_GRAY)
                self.set_x(self.l_margin + 4)
                self.cell(self.epw - 4, 6, sanitize(img_name),
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(3)

        self.sub_header("Critical Vulnerabilities")
        for vuln in vulns:
            if self.get_y() > self.h - self.b_margin - 35:
                self.add_page()

            fix = vuln.get("fix_resolution") or []
            fix_str = ", ".join(fix) if fix else "No fix available"

            self.set_fill_color(*LIGHT_GRAY)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*DARK)
            self.set_x(self.l_margin)
            self.cell(self.epw, 7, sanitize(f"  {vuln.get('cveid', 'N/A')}"),
                      fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*AMBER)
            self.set_x(self.l_margin + 4)
            self.cell(self.epw - 4, 6, sanitize(f"Fix: {fix_str}"),
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            desc = (vuln.get("description") or "").strip()
            if desc:
                if self.get_y() > self.h - self.b_margin - 20:
                    self.add_page()
                self.set_font("Helvetica", "", 7.5)
                self.set_text_color(*MID_GRAY)
                self.set_x(self.l_margin + 4)
                self.multi_cell(self.epw - 4, 5.5,
                                sanitize(desc[:300] + ("..." if len(desc) > 300 else "")),
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

        self._separator()


    def risky_image_card(self, i, total, img):
        registry = img.get("registry", "")
        repo     = img.get("repository", "")
        tag      = img.get("tag", "")
        label    = f"{registry}/{repo}:{tag}" if registry else f"{repo}:{tag}"

        if self.get_y() > self.h - self.b_margin - 60:
            self.add_page()

        # Card header
        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10, sanitize(f"  [{i} of {total}]  {label}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        # Stats row
        fields = [
            ("Base OS",             img.get("base_os") or "N/A"),
            ("CVEs",                img.get("cve_count", 0)),
            ("Layers w/ CVEs",      img.get("layers_with_vulnerabilities", 0)),
        ]
        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)

        # Falcon deep-link
        falcon_url = img.get("falcon_url", "")
        if falcon_url:
            self.link_row("Falcon", falcon_url, alt=len(fields) % 2 == 0)

        # Layer breakdown
        layers = img.get("layers") or []
        if layers:
            self.ln(3)
            self.sub_header("CVE Layer Breakdown")

        for layer in layers:
            if self.get_y() > self.h - self.b_margin - 25:
                self.add_page()

            cmd = (layer.get("layer_command") or "").strip() or "(no command)"
            layer_label = f"Layer {layer['layer_index']}  —  {cmd}"

            self.set_fill_color(*SECTION_BG)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*DARK)
            self.set_x(self.l_margin)
            self.multi_cell(self.epw, 6, sanitize(layer_label[:120]),
                            fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(1)

            # Column headers
            W = self.epw
            col_cve  = 40
            col_cvss = 18
            col_pkg  = W - col_cve - col_cvss - 28
            col_flag = 28
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*MID_GRAY)
            self.set_x(self.l_margin + 2)
            self.cell(col_cve,  5, "CVE ID")
            self.cell(col_cvss, 5, "CVSS", align="C")
            self.cell(col_pkg,  5, "Package")
            self.cell(col_flag, 5, "Flags", align="R",
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_draw_color(*LIGHT_GRAY)
            self.set_line_width(0.2)
            self.line(self.l_margin, self.get_y(), self.l_margin + W, self.get_y())
            self.ln(1)

            for cidx, cve in enumerate(layer["cves"]):
                if self.get_y() > self.h - self.b_margin - 12:
                    self.add_page()

                if cidx % 2 == 1:
                    self.set_fill_color(*SECTION_BG)
                    self.rect(self.l_margin, self.get_y(), W, 6, "F")

                sev = (cve.get("severity") or "").lower()
                sev_color = {
                    "critical": CS_RED, "high": AMBER, "medium": (200, 180, 0)
                }.get(sev, MID_GRAY)

                self.set_font("Helvetica", "B", 7.5)
                self.set_text_color(*sev_color)
                self.set_x(self.l_margin + 2)
                self.cell(col_cve, 6, sanitize(cve.get("cve_id", "N/A")))

                self.set_font("Helvetica", "", 7.5)
                self.set_text_color(*DARK)
                self.cell(col_cvss, 6, sanitize(cve.get("cvss_score", "N/A")), align="C")

                pkg = (cve.get("package_name_version") or "").strip()
                self.cell(col_pkg, 6, sanitize(pkg[:40]))

                flags = []
                if cve.get("exploited"):      flags.append("EXPLOIT")
                if cve.get("fix_available"):  flags.append("FIX")
                flag_str = "  ".join(flags)
                self.set_font("Helvetica", "B", 7)
                self.set_text_color(*CS_RED if flags else MID_GRAY)
                self.cell(col_flag, 6, sanitize(flag_str), align="R",
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            self.ln(4)

        self._separator()


    def cloud_app_card(self, i, total, app):
        if self.get_y() > self.h - self.b_margin - 60:
            self.add_page()

        # Card header
        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10, sanitize(f"  [{i} of {total}]  {app['name']}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        techs = ", ".join(app["technologies"]) if app["technologies"] else "N/A"
        exprt = app["exprt"]
        exprt_parts = []
        for sev in ("critical", "high", "medium", "low"):
            v = exprt.get(sev, 0)
            if v:
                exprt_parts.append(f"{v} {sev.capitalize()}")
        exprt_str = "  /  ".join(exprt_parts) if exprt_parts else "None"

        fields = [
            ("Deployment Type",  app.get("deployment_type") or "N/A"),
            ("Technologies",     techs),
            ("Account",          app.get("account_id") or "N/A"),
            ("Region",           app.get("region") or "N/A"),
            ("Vulnerabilities",  app.get("total_vulns", 0)),
            ("ExPRT Ratings",    exprt_str),
        ]
        if app.get("k8s_namespace"):
            fields.insert(2, ("K8s Namespace", app["k8s_namespace"]))

        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)

        self._separator()


    def ai_iom_card(self, i, total, iom):
        if self.get_y() > self.h - self.b_margin - 80:
            self.add_page()

        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 10, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10,
                  sanitize(f"  [{i} of {total}]  {iom['resource_id']}"),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        console_url = _console_url(iom)
        fields = [
            ("Rule",          iom.get("rule_name")),
            ("Severity",      iom.get("severity")),
            ("Service",       iom.get("service")),
            ("Resource Type", iom.get("resource_type")),
            ("Provider",      iom.get("provider")),
            ("Account",       f"{iom.get('account_name', 'N/A')} ({iom.get('account_id', 'N/A')})"),
            ("Region",        iom.get("region")),
            ("Description",   iom.get("description")),
        ]
        for idx, (field, value) in enumerate(fields):
            self.row(field, value, alt=idx % 2 == 0)
        if console_url:
            self.link_row("Console", console_url, alt=len(fields) % 2 == 0)
        falcon_url = _falcon_iom_url(iom)
        if falcon_url:
            self.link_row("Falcon", falcon_url, alt=(len(fields) + (1 if console_url else 0)) % 2 == 0)
        self.ln(3)

        remediation = (iom.get("remediation") or "").strip()
        if remediation:
            if self.get_y() > self.h - self.b_margin - 40:
                self.add_page()
            self.sub_header("Remediation")
            steps = remediation.split("|\n")
            col_w = self.epw - 4
            for step in steps:
                step = step.strip()
                if not step:
                    continue
                self.set_font("Helvetica", "", 7.5)
                char_w = self.get_string_width("m") or 2.0
                chars_per_line = max(1, int(col_w / char_w))
                n_lines = max(1, -(-len(step) // chars_per_line))
                step_h = n_lines * 5.5 + 4
                if self.get_y() + step_h > self.h - self.b_margin:
                    self.add_page()
                self.set_text_color(*MID_GRAY)
                self.set_x(self.l_margin + 4)
                self.multi_cell(col_w, 5.5, sanitize(step),
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.ln(1)

        self._separator()


def build_pdf(risks, ioas, vm_data, ai_packages, ioms, risky_images, cloud_apps, ai_services, config):
    output_file = ensure_timestamped_filename(config.get("output_file", OUTPUT_FILE))
    vm_totals = {provider: len(assets) for provider, assets in vm_data.items()}
    iom_cats = config.get("iom_categories", [])
    iom_sevs = config.get("iom_severities", [])
    _iom_cat_label = "all categories" if "all" in iom_cats else ", ".join(iom_cats)
    _iom_sev_label = ", ".join(iom_sevs) if iom_sevs else "all severities"
    ioms_label = f"{_iom_cat_label} / {_iom_sev_label}"
    fdesc = _filter_desc(config)

    pdf = FalconReport(orientation="P", unit="mm", format="A4")
    pdf.set_margins(10, 22, 10)
    pdf.set_auto_page_break(auto=True, margin=20)

    pdf.add_page()
    pdf.cover(
        risks_count=len(risks)               if config.get("include_risks")         else None,
        ioas_count=len(ioas)                 if config.get("include_ioas")          else None,
        vm_totals=vm_totals                  if config.get("include_vms")           else None,
        ai_packages_count=len(ai_packages)   if config.get("include_ai_packages")   else None,
        ioms_count=len(ioms)                 if iom_cats                            else None,
        ioms_label=ioms_label                if iom_cats                            else "",
        risky_images_count=len(risky_images) if config.get("include_risky_images")  else None,
        cloud_apps_count=len(cloud_apps)     if config.get("include_cloud_apps")    else None,
        ai_services_count=len(ai_services)   if config.get("include_ai_services")   else None,
        filter_desc=fdesc,
    )

    # TOC on page 2; insert_toc_placeholder advances to page 3
    pdf.add_page()
    pdf.insert_toc_placeholder(_render_toc, pages=1)

    _first_section = [True]

    def _begin_section(title, group_label=None):
        if _first_section[0]:
            _first_section[0] = False
            if group_label:
                pdf.section_group_header(group_label)
        else:
            pdf.add_page()
            if group_label:
                pdf.section_group_header(group_label)
        pdf.start_section(title)

    # ── Section 1: Cloud Infrastructure ─────────────────────────────────────────
    _infra_group = "Section 1  —  Cloud Infrastructure"
    _infra_first = [True]

    def _infra_section(title):
        group = _infra_group if _infra_first[0] else None
        _infra_first[0] = False
        _begin_section(title, group_label=group)

    if config.get("include_ioas"):
        _infra_section(f"Cloud IOA Detections  ({len(ioas)} total)")
        pdf.section_header(f"Cloud IOA Detections  ({len(ioas)} total)")
        if not ioas:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No Cloud IOA detections found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, ioa in enumerate(ioas, 1):
                pdf.ioa_card(i, len(ioas), ioa)

    if config.get("include_risks"):
        _infra_section(f"Cloud Risks  ({len(risks)} total)")
        pdf.section_header(f"Cloud Risks  ({len(risks)} total)")
        if not risks:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No risks found matching the filter.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, risk in enumerate(risks, 1):
                pdf.risk_card(i, len(risks), risk)

    if iom_cats:
        _infra_section(f"Cloud Service IOMs  ({len(ioms)} total)")
        pdf.section_header(f"Cloud Service IOMs  ({len(ioms)} total)  -  {ioms_label}")
        if not ioms:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No active misconfigurations found for the selected categories.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, iom in enumerate(ioms, 1):
                pdf.ai_iom_card(i, len(ioms), iom)

    # ── Section 2: Cloud Apps ─────────────────────────────────────────────────
    _apps_group = "Section 2  —  Cloud Apps"
    _apps_first = [True]

    def _apps_section(title):
        group = _apps_group if _apps_first[0] else None
        _apps_first[0] = False
        _begin_section(title, group_label=group)

    if config.get("include_cloud_apps"):
        _apps_section(f"Cloud Applications  ({len(cloud_apps)} total)")
        pdf.section_header(f"Cloud Applications  ({len(cloud_apps)} total)")
        if not cloud_apps:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No cloud applications found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, app in enumerate(cloud_apps, 1):
                pdf.cloud_app_card(i, len(cloud_apps), app)

    if config.get("include_risky_images"):
        _apps_section(f"Risky Container Images  ({len(risky_images)} total)")
        pdf.section_header(f"Risky Container Images  ({len(risky_images)} total)")
        if not risky_images:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No images with matching CVEs found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, img in enumerate(risky_images, 1):
                pdf.risky_image_card(i, len(risky_images), img)

    # ── Section 3: Shadow AI ──────────────────────────────────────────────────
    _ai_group = "Section 3  —  Shadow AI"
    _ai_first = [True]

    def _ai_section(title):
        group = _ai_group if _ai_first[0] else None
        _ai_first[0] = False
        _begin_section(title, group_label=group)

    if config.get("include_ai_services"):
        _ai_section(f"AI Services — IOMs  ({len(ai_services)} total)")
        pdf.section_header(f"AI Services -- IOMs  ({len(ai_services)} total)")
        if not ai_services:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No AI service misconfigurations found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, iom in enumerate(ai_services, 1):
                pdf.ai_iom_card(i, len(ai_services), iom)

    if config.get("include_ai_packages"):
        _ai_section(f"AI Package Risks  ({len(ai_packages)} packages)")
        pdf.section_header(f"AI Package Risks -- Critical CVEs  ({len(ai_packages)} packages)")
        if not ai_packages:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No AI-related packages with Critical CVEs found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, pkg in enumerate(ai_packages, 1):
                pdf.ai_package_card(i, len(ai_packages), pkg)

    # ── Section 4: Unmanaged VMs ──────────────────────────────────────────────
    if config.get("include_vms"):
        total_vms = sum(vm_totals.values())
        _begin_section(f"Unmanaged Virtual Machines  ({total_vms} total)",
                       group_label="Section 4  —  Unmanaged VMs")
        pdf.section_header(f"Unmanaged Virtual Machines  ({total_vms} total)")
        for provider, assets in vm_data.items():
            pdf.sub_header(f"{provider}  -  {len(assets)} asset(s)")
            pdf.vm_table(assets)

    pdf.output(output_file)
    print(f"Report written to {output_file}")
    print(f"Generated at: {now_utc_detailed()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Falcon Cloud Security PDF Report")
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Prompt for report configuration (sections, filters, output filename)",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print API call status codes and error bodies for troubleshooting",
    )
    args = parser.parse_args()

    DEBUG = args.debug

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

    client_id     = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("Error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set in the environment or .env file.")

    config = interactive_config() if args.interactive else _default_config()
    risks_filter, vm_filters = build_filters(config)

    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    cs              = CloudSecurity(auth_object=auth)
    csa             = CloudSecurityAssets(auth_object=auth)
    alerts          = Alerts(auth_object=auth)
    cp              = ContainerPackages(auth_object=auth)
    ci              = ContainerImages(auth_object=auth)
    cv              = ContainerVulnerabilities(auth_object=auth)
    csd             = CloudSecurityDetections(auth_object=auth)

    risks = []
    if config["include_risks"]:
        print(f"\n{T_HINT}  Fetching risks...{T_RESET}")
        risks = fetch_all_risks(cs, risks_filter)
        print(f"{T_SUCCESS}  ✓ {len(risks)} risk(s) found.{T_RESET}\n")

    ioas = []
    if config["include_ioas"]:
        print(f"{T_HINT}  Fetching Cloud IOAs...{T_RESET}")
        ioas = fetch_cloud_ioas(alerts, config.get("ioa_severities", []))
        print(f"{T_SUCCESS}  ✓ {len(ioas)} Cloud IOA(s) found.{T_RESET}\n")

    vm_data = {}
    if config["include_vms"]:
        for provider, vm_filter in vm_filters:
            print(f"{T_HINT}  Fetching VMs  {T_MUTED}({provider}){T_RESET}")
            assets = fetch_unmanaged_vms(csa, vm_filter)
            vm_data[provider] = assets
            print(f"{T_SUCCESS}  ✓ {len(assets)} unmanaged VM(s) — {provider}.{T_RESET}")
        print()

    ai_packages = []
    if config["include_ai_packages"]:
        ai_sevs = config.get("ai_package_severities", ["Critical"])
        sev_label = ", ".join(ai_sevs) if ai_sevs else "all severities"
        print(f"{T_HINT}  Fetching AI packages  {T_MUTED}({sev_label}){T_RESET}")
        ai_packages = fetch_ai_critical_packages(cp, ci, ai_sevs)
        print(f"{T_SUCCESS}  ✓ {len(ai_packages)} AI package(s) found.{T_RESET}")

    risky_images = []
    if config.get("include_risky_images"):
        ri_sevs = config.get("risky_images_severities", ["Critical"])
        ri_max  = config.get("risky_images_max", 10)
        sev_label = ", ".join(ri_sevs) if ri_sevs else "all severities"
        print(f"{T_HINT}  Fetching risky images  {T_MUTED}({sev_label}, up to {ri_max}){T_RESET}")
        risky_images = fetch_risky_images(ci, cv, ri_sevs, ri_max)
        print(f"{T_SUCCESS}  ✓ {len(risky_images)} risky image(s) found.{T_RESET}")

    cloud_apps = []
    if config.get("include_cloud_apps"):
        ca_max = config.get("cloud_apps_max", 50)
        print(f"{T_HINT}  Fetching cloud applications  {T_MUTED}(up to {ca_max}){T_RESET}")
        cloud_apps = fetch_cloud_apps(csa, ca_max)
        print(f"{T_SUCCESS}  ✓ {len(cloud_apps)} cloud application(s) found.{T_RESET}")

    ioms = []
    iom_cats = config.get("iom_categories", [])
    if iom_cats:
        iom_sevs = config.get("iom_severities", [])
        cat_label = "all categories" if "all" in iom_cats else ", ".join(iom_cats)
        sev_label = ", ".join(iom_sevs) if iom_sevs else "all severities"
        print(f"{T_HINT}  Fetching IOMs  {T_MUTED}({cat_label} / {sev_label}){T_RESET}")
        ioms = fetch_ioms(csd, iom_cats, iom_sevs)
        print(f"{T_SUCCESS}  ✓ {len(ioms)} misconfiguration(s) found.{T_RESET}")

    ai_services = []
    if config.get("include_ai_services"):
        ai_svc_sevs = config.get("ai_services_severities", [])
        sev_label = ", ".join(ai_svc_sevs) if ai_svc_sevs else "all severities"
        print(f"{T_HINT}  Fetching AI services IOMs  {T_MUTED}({sev_label}){T_RESET}")
        ai_services = fetch_ioms(csd, ["ai"], ai_svc_sevs)
        print(f"{T_SUCCESS}  ✓ {len(ai_services)} AI service misconfiguration(s) found.{T_RESET}")

    print()
    if config["include_ioas"]:
        print_cloud_ioas(ioas)
    if config["include_risks"]:
        print_risks(risks)
    if iom_cats:
        print_ai_ioms(ioms)
    if config.get("include_cloud_apps"):
        print_cloud_apps(cloud_apps)
    if config.get("include_risky_images"):
        print_risky_images(risky_images)
    if config.get("include_ai_services"):
        print_ai_ioms(ai_services)
    if config["include_ai_packages"]:
        print_ai_packages(ai_packages)
    if config["include_vms"]:
        print_vms(vm_data)

    print(f"\n{T_HINT}  Building PDF...{T_RESET}")
    build_pdf(risks, ioas, vm_data, ai_packages, ioms, risky_images, cloud_apps, ai_services, config)
