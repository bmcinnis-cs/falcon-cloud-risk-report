import os
import sys
import json
import argparse
import textwrap
import html as _html
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
import re as _re
from datetime import datetime, timezone
from dotenv import load_dotenv
from falconpy import OAuth2, CloudSecurity, CloudSecurityAssets, Alerts, ContainerPackages, ContainerImages, CloudSecurityDetections, Hosts
from fpdf import FPDF, XPos, YPos

RISKS_FILTER = "status:'Open'+severity:'High'"
# Updated VM approach: Use CloudSecurityAssets with exact Asset Explorer filters
VM_FILTERS = [
    ("AWS",   "active:'true'+cloud_provider:'aws'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
    ("Azure", "active:'true'+cloud_provider:'azure'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
    ("GCP",   "active:'true'+cloud_provider:'gcp'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
]

def get_default_output_filename():
    """Generate a default output filename with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"falcon_cloud_security_report_{timestamp}.pdf"

def ensure_timestamped_filename(filename):
    """Ensure filename has timestamp for uniqueness"""
    if not filename:
        return get_default_output_filename()

    # Check if filename already has timestamp pattern (YYYYMMDD_HHMMSS)
    import re
    timestamp_pattern = r'_\d{8}_\d{6}'

    if re.search(timestamp_pattern, filename):
        return filename  # Already has timestamp

    # Add timestamp before .pdf extension (case-insensitive)
    if filename.lower().endswith('.pdf'):
        base_name = filename[:-4]  # Remove .pdf/.PDF
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Preserve original extension case
        extension = filename[-4:]  # Get original .pdf or .PDF
        return f"{base_name}_{timestamp}{extension}"
    else:
        # Add .pdf and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{filename}_{timestamp}.pdf"

OUTPUT_FILE    = get_default_output_filename()
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

# ANSI terminal colors
T_RESET  = "\033[0m"
T_BOLD   = "\033[1m"
T_DIM    = "\033[2m"
T_RED    = "\033[91m"
T_YELLOW = "\033[93m"
T_CYAN   = "\033[96m"
T_WHITE  = "\033[97m"
T_GRAY   = "\033[90m"

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

def _prompt(label, default=""):
    display_default = f" [{default}]" if default else ""
    try:
        val = input(f"  {T_GRAY}{label}{display_default}:{T_RESET} {T_WHITE}").strip()
        print(T_RESET, end="", flush=True)
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _prompt_yn(label, default=True):
    hint = "Y/n" if default else "y/N"
    raw = _prompt(f"{label} ({hint})", "")
    return raw.lower().startswith("y") if raw else default


def interactive_config():
    print(f"\n{T_BOLD}{T_CYAN}Falcon Cloud Security Report -- Configuration{T_RESET}")
    print(f"{T_GRAY}Press Enter to accept defaults.{T_RESET}\n")

    config = {}

    print(f"  {T_BOLD}Sections{T_RESET}")
    config["include_risks"] = _prompt_yn("Include Cloud Risks", default=True)
    config["include_ioas"]  = _prompt_yn("Include Cloud IOA Detections", default=True)
    config["include_vms"]   = _prompt_yn("Include Unmanaged Virtual Machines", default=True)
    config["include_ai_packages"] = _prompt_yn("Include AI Package Risks (Critical CVEs)", default=True)
    print()

    if config["include_risks"]:
        print(f"  {T_BOLD}Risk Filters{T_RESET}")
        print(f"  {T_GRAY}Available severities: {', '.join(VALID_SEVERITIES)}{T_RESET}")
        sev_raw = _prompt("Severity (comma-separated)", "High")
        sevs = [s.strip().capitalize() for s in sev_raw.split(",") if s.strip()]
        config["severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["High"]

        print(f"  {T_GRAY}Available statuses: Open, Closed, all{T_RESET}")
        status_raw = _prompt("Status", "Open")
        status_val = status_raw.strip().capitalize() if status_raw.strip() else "Open"
        config["status"] = status_val if status_val in ("Open", "Closed") else "all"

        print(f"  {T_GRAY}Available providers: {', '.join(VALID_PROVIDERS)}, all{T_RESET}")
        prov_raw = _prompt("Cloud provider", "all")
        prov = prov_raw.strip().lower()
        config["risk_provider"] = prov if prov in VALID_PROVIDERS else "all"
        print()

    if config["include_ioas"]:
        print(f"  {T_BOLD}Cloud IOA Filters{T_RESET}")
        print(f"  {T_GRAY}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ioa_sev_raw = _prompt("IOA severity (comma-separated, or all)", "all")
        if not ioa_sev_raw.strip() or ioa_sev_raw.strip().lower() == "all":
            config["ioa_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ioa_sev_raw.split(",") if s.strip()]
            config["ioa_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
        print()

    if config["include_ai_packages"]:
        print(f"  {T_BOLD}AI Package Filters{T_RESET}")
        print(f"  {T_GRAY}Available severities: {', '.join(VALID_SEVERITIES)}, all{T_RESET}")
        ai_sev_raw = _prompt("Package severity (comma-separated, or all)", "Critical")
        if not ai_sev_raw.strip() or ai_sev_raw.strip().lower() == "all":
            config["ai_package_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ai_sev_raw.split(",") if s.strip()]
            config["ai_package_severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["Critical"]
        print()

    if config["include_vms"]:
        print(f"  {T_BOLD}VM Filters{T_RESET}")
        print(f"  {T_GRAY}Available providers: AWS, Azure, GCP{T_RESET}")
        vm_prov_raw = _prompt("VM providers (comma-separated)", "AWS,Azure,GCP")
        _norm = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
        vm_provs = [p.strip() for p in vm_prov_raw.split(",") if p.strip()]
        config["vm_providers"] = [_norm[p.lower()] for p in vm_provs if p.lower() in _norm] or ["AWS", "Azure", "GCP"]
        print()

    print(f"  {T_BOLD}IOM Filters{T_RESET}")
    _cat_list = ", ".join(VALID_IOM_CATEGORIES)
    print(f"  {T_GRAY}Available categories: {_cat_list}{T_RESET}")
    print(f"  {T_GRAY}Enter 'none' or leave blank to skip the IOM section.{T_RESET}")
    iom_raw = _prompt("IOM categories (comma-separated, all, or none)", "none")
    iom_val = iom_raw.strip().lower()
    if not iom_val or iom_val == "none":
        config["iom_categories"] = []
    elif iom_val == "all":
        config["iom_categories"] = ["all"]
    else:
        cats = [c.strip() for c in iom_val.split(",") if c.strip()]
        config["iom_categories"] = [c for c in cats if c in IOM_CATEGORIES] or []

    if config["iom_categories"]:
        print(f"  {T_GRAY}Available severities: {', '.join(VALID_SEVERITIES)}{T_RESET}")
        iom_sev_raw = _prompt("IOM severity filter (comma-separated, or all)", "all")
        if not iom_sev_raw.strip() or iom_sev_raw.strip().lower() == "all":
            config["iom_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in iom_sev_raw.split(",") if s.strip()]
            config["iom_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
    print()

    print(f"  {T_BOLD}Output{T_RESET}")
    user_filename = _prompt("Output filename", OUTPUT_FILE)
    config["output_file"] = ensure_timestamped_filename(user_filename)
    print()

    merged = {**_default_config(), **config}

    if _prompt_yn("Save as new defaults", default=False):
        _save_defaults(merged)
        print(f"  {T_GRAY}Defaults saved to {DEFAULTS_FILE}{T_RESET}\n")

    return merged


def _default_config():
    hardcoded = {
        "include_risks":          True,
        "include_ioas":           True,
        "include_vms":            True,
        "include_ai_packages":    False,
        "iom_categories":         [],
        "iom_severities":         [],
        "ai_package_severities":  ["Critical"],
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
    bool_keys = ("include_risks", "include_ioas", "include_vms", "include_ai_packages")
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
    text = _re.sub(r'<br\s*/?>', '\n', text, flags=_re.IGNORECASE)

    # <a href="url">label</a>: keep label; append url when it adds information
    def _repl_anchor(m):
        href  = (m.group(1) or "").strip()
        label = (m.group(2) or "").strip()
        if label and href and label != href:
            return f"{label} ({href})"
        return label or href

    text = _re.sub(
        r'<a\s[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        _repl_anchor,
        text,
        flags=_re.IGNORECASE | _re.DOTALL,
    )

    # Strip remaining tags
    text = _re.sub(r'<[^>]+>', '', text)

    # Unescape HTML entities (&amp; → &, &lt; → <, &#39; → ', etc.)
    text = _html.unescape(text)

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
    """Legacy function - kept for compatibility but no longer used"""
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


def fetch_vms_without_sensor(hosts_sdk, cloud_provider):
    """
    Fetch VMs without CrowdStrike Falcon sensor for a specific cloud provider.
    Uses the Hosts API with proper service_provider field identification.

    Args:
        hosts_sdk: Hosts API SDK instance
        cloud_provider: 'aws', 'azure', or 'gcp'

    Returns:
        List of host records representing VMs without sensor
    """
    hosts = []
    offset = 0
    batch_size = 1000

    # Map cloud provider names to service_provider field values
    service_provider_mapping = {
        'aws': 'AWS',
        'azure': 'AZURE',
        'gcp': 'GCP'
    }

    target_provider = service_provider_mapping.get(cloud_provider.lower())
    if not target_provider:
        print(f"    Warning: Unknown cloud provider '{cloud_provider}'")
        return []

    print(f"    Querying hosts with service_provider:'{target_provider}'...")

    while True:
        try:
            # Use proper API filter for service provider
            r = hosts_sdk.query_devices_by_filter(
                limit=batch_size,
                offset=offset,
                filter=f"service_provider:'{target_provider}'"
            )

            if r["status_code"] != 200:
                dbg_response("query_devices_by_filter", r)
                break

            batch_ids = r["body"].get("resources") or []
            if not batch_ids:
                break

            print(f"    Processing {len(batch_ids)} {target_provider} hosts...")

            # Get detailed host information
            host_details_r = hosts_sdk.get_device_details(ids=batch_ids)
            if host_details_r["status_code"] != 200:
                dbg_response("get_device_details", host_details_r)
                offset += len(batch_ids)
                continue

            host_details = host_details_r["body"].get("resources") or []

            # Process each host
            for host in host_details:
                # Verify service_provider matches (double-check API filter worked)
                host_provider = host.get("service_provider", "").upper()
                if host_provider != target_provider:
                    continue

                # Filter for actual VMs (exclude mobile devices, containers, etc.)
                platform = host.get("platform_name", "")
                hostname = host.get("hostname", "")

                # Only include VM-like platforms, exclude mobile and container platforms
                if platform in ['Android', 'iOS', 'ChromeOS'] or '/subscriptions/' in hostname:
                    continue

                # Check sensor status based on agent_version presence and validity
                agent_version = host.get("agent_version", "")
                has_sensor = bool(agent_version and agent_version != "No Sensor")

                hosts.append({
                    'device_id': host.get('device_id'),
                    'hostname': host.get('hostname'),
                    'platform_name': host.get('platform_name'),
                    'external_ip': host.get('external_ip'),
                    'internal_ip': host.get('local_ip'),
                    'last_seen': host.get('last_seen'),
                    'sensor_version': agent_version if has_sensor else 'No Sensor',
                    'cloud_provider': cloud_provider,
                    'instance_state': 'running' if host.get('last_seen') else 'unknown',
                    'service_provider': host.get('service_provider', ''),
                    'has_sensor': has_sensor
                })

            # Update offset for pagination
            offset += len(batch_ids)

            # Check if we've processed all hosts
            meta = r["body"].get("meta", {})
            total = meta.get("total", 0)
            if offset >= total or len(batch_ids) == 0:
                break

        except Exception as e:
            print(f"    Warning: Error processing hosts batch at offset {offset}: {e}")
            offset += batch_size  # Skip this batch and continue

    print(f"    Found {len(hosts)} {target_provider} VMs")
    return hosts


def fetch_cloud_vms_comprehensive(hosts_sdk, csa_sdk, cloud_provider):
    """
    Comprehensive approach: Use Hosts API with proper service_provider field
    to accurately identify cloud VMs and their sensor status.

    This addresses the discrepancy between Asset Explorer (109 Azure VMs without sensor)
    and the original CloudSecurityAssets approach (0 VMs found).
    """
    cloud_vms = []

    # Method 1: Use Hosts API with proper service_provider filtering
    try:
        all_vms = fetch_vms_without_sensor(hosts_sdk, cloud_provider)

        # The function returns ALL VMs for the provider, now filter for sensor status
        # For the report, we want VMs WITHOUT sensor (matching Asset Explorer logic)
        vms_without_sensor = [vm for vm in all_vms if not vm.get('has_sensor', True)]

        print(f"    Total {cloud_provider.upper()} VMs: {len(all_vms)}")
        print(f"    VMs with sensor: {len(all_vms) - len(vms_without_sensor)}")
        print(f"    VMs without sensor: {len(vms_without_sensor)}")

        cloud_vms.extend(vms_without_sensor)

    except Exception as e:
        print(f"    Warning: Hosts API query failed: {e}")

    # Method 2 (Fallback): Use CloudSecurityAssets API for governance view if Hosts API fails
    if not cloud_vms:
        provider_filters = {
            'aws': "managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'",
            'azure': "managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'",
            'gcp': "managed_by:'Unmanaged'+cloud_provider:'gcp'+instance_state:'running'"
        }

        if cloud_provider in provider_filters:
            try:
                print(f"    Falling back to CloudSecurityAssets API...")
                governance_vms = fetch_unmanaged_vms(csa_sdk, provider_filters[cloud_provider])
                # Convert to standard format
                for vm in governance_vms:
                    cloud_vms.append({
                        'device_id': vm.get('id'),
                        'hostname': vm.get('asset_name') or vm.get('resource_name'),
                        'platform_name': vm.get('platform_name', cloud_provider),
                        'external_ip': vm.get('public_ip'),
                        'internal_ip': vm.get('private_ip'),
                        'last_seen': vm.get('last_seen'),
                        'sensor_version': 'Unmanaged Resource',
                        'cloud_provider': cloud_provider,
                        'instance_state': vm.get('instance_state', 'unknown'),
                        'has_sensor': False
                    })
            except Exception as e:
                print(f"    Warning: CloudSecurityAssets API query also failed: {e}")

    # Deduplicate by hostname/device_id
    seen = set()
    unique_vms = []
    for vm in cloud_vms:
        key = vm.get('hostname') or vm.get('device_id')
        if key and key not in seen:
            seen.add(key)
            unique_vms.append(vm)

    return unique_vms


def _image_label(img):
    reg  = (img.get("registry")   or "").strip()
    repo = (img.get("repository") or "").strip()
    tag  = (img.get("tag")        or "latest").strip()
    return f"{reg}/{repo}:{tag}" if reg else f"{repo}:{tag}"


def fetch_images_for_package(ci, package_name_version):
    """Return a deduplicated list of image name strings containing this package."""
    images = []
    seen_digests = set()
    after = None
    while True:
        params = {"filter": f"package_name_version:'{package_name_version}'", "limit": 100}
        if after:
            params["after"] = after
        r = ci.ReadCombinedImagesExport(**params)
        if r["status_code"] != 200:
            dbg_response("ReadCombinedImagesExport", r)
            break
        batch = r["body"].get("resources") or []
        for img in batch:
            digest = img.get("image_digest") or img.get("image_id") or _image_label(img)
            if digest not in seen_digests:
                seen_digests.add(digest)
                images.append(_image_label(img))
        after = r["body"].get("meta", {}).get("pagination", {}).get("after")
        if not batch or not after:
            break
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
        params = {"limit": 500, "filter": "extension_status:'Unresolved'"}
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
        if eval_data.get("status") != "non-compliant":
            continue
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
    return f"{T_GRAY}{text}{T_RESET}"


def print_risks(risks):
    width = 64
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}  FALCON CLOUD SECURITY -- OPEN HIGH SEVERITY RISKS{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"  {t_label('Total risks found:')} {T_BOLD}{T_WHITE}{len(risks)}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")

    if not risks:
        print(f"\n  {T_YELLOW}No risks found matching the filter.{T_RESET}\n")
        return

    for i, risk in enumerate(risks, 1):
        print(f"\n  {T_BOLD}{T_WHITE}[{i} of {len(risks)}]{T_RESET}")
        print(f"  {t_label('Rule:     ')} {T_BOLD}{T_WHITE}{risk.get('rule_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Desc:     ')} {T_WHITE}{risk.get('rule_description', 'N/A')}{T_RESET}")
        print(f"  {t_label('Severity: ')} {T_BOLD}{T_RED}{risk.get('severity', 'N/A')}{T_RESET}")
        print(f"  {t_label('Status:   ')} {T_BOLD}{T_YELLOW}{risk.get('status', 'N/A')}{T_RESET}")
        print(f"  {t_label('Asset:    ')} {T_CYAN}{risk.get('asset_name', 'N/A')}{T_GRAY} ({risk.get('asset_type', 'N/A')}){T_RESET}")
        print(f"  {t_label('Provider: ')} {T_BOLD}{T_WHITE}{(risk.get('cloud_provider') or '').upper()}{T_RESET}")
        print(f"  {t_label('Account:  ')} {T_WHITE}{risk.get('account_name', 'N/A')}{T_GRAY} ({risk.get('account_id', 'N/A')}){T_RESET}")
        print(f"  {t_label('Region:   ')} {T_WHITE}{risk.get('asset_region', 'N/A')}{T_RESET}")
        print(f"  {t_label('Category: ')} {T_WHITE}{risk.get('service_category', 'N/A')}{T_RESET}")
        print(f"  {t_label('First Seen:')} {T_DIM}{T_WHITE}{risk.get('first_seen', 'N/A')}{T_RESET}")
        print(f"  {t_label('Last Seen: ')} {T_DIM}{T_WHITE}{risk.get('last_seen', 'N/A')}{T_RESET}")

        risk_factors = risk.get("risk_factors") or risk.get("risk_factor") or []
        if risk_factors:
            print(f"\n  {T_BOLD}{T_CYAN}  Risk Factors{T_RESET}")
            for factor in risk_factors:
                print(f"\n    {T_BOLD}{T_WHITE}{factor.get('insight_name', 'N/A')}{T_RESET}")
                for remediation in factor.get("remediation") or []:
                    print(f"\n      {T_BOLD}{T_YELLOW}{remediation.get('title', '')}{T_RESET}")
                    for line in remediation.get("content", "").splitlines():
                        for wrapped_line in textwrap.wrap(line, width=56) or [""]:
                            print(f"      {T_DIM}{T_WHITE}{wrapped_line}{T_RESET}")

        print(f"\n  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
    print()


def print_cloud_ioas(ioas):
    width = 64
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}  CLOUD IOA DETECTIONS{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"  {t_label('Total IOAs found:')} {T_BOLD}{T_WHITE}{len(ioas)}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")

    if not ioas:
        print(f"\n  {T_YELLOW}No Cloud IOA detections found.{T_RESET}\n")
        return

    for i, ioa in enumerate(ioas, 1):
        print(f"\n  {T_BOLD}{T_WHITE}[{i} of {len(ioas)}]{T_RESET}")
        print(f"  {t_label('Name:     ')} {T_BOLD}{T_WHITE}{ioa.get('display_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Severity: ')} {T_BOLD}{T_RED}{ioa.get('severity_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Provider: ')} {T_BOLD}{T_WHITE}{(ioa.get('cloud_provider') or '').upper()}{T_RESET}")
        print(f"  {t_label('Account:  ')} {T_WHITE}{ioa.get('cloud_account_id', 'N/A')}{T_RESET}")
        print(f"  {t_label('Region:   ')} {T_WHITE}{ioa.get('cloud_region', 'N/A')}{T_RESET}")
        print(f"  {t_label('Service:  ')} {T_WHITE}{ioa.get('service', 'N/A')}{T_RESET}")
        tactic = ioa.get('tactic', 'N/A')
        technique = ioa.get('technique', 'N/A')
        print(f"  {t_label('Tactic:   ')} {T_WHITE}{tactic}{T_RESET}")
        print(f"  {t_label('Technique:')} {T_WHITE}{technique}{T_RESET}")
        print(f"  {t_label('User:     ')} {T_WHITE}{ioa.get('user_display_name', 'N/A')}{T_RESET}")
        print(f"  {t_label('Timestamp:')} {T_DIM}{T_WHITE}{ioa.get('timestamp', 'N/A')}{T_RESET}")
        desc = ioa.get('description', '')
        if desc:
            print(f"  {t_label('Desc:     ')} {T_WHITE}{desc[:120]}{'...' if len(desc) > 120 else ''}{T_RESET}")
        print(f"\n  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
    print()


def print_vms(vm_data):
    width = 64
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}  UNMANAGED RUNNING VMs{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}\n")

    for provider, assets in vm_data.items():
        print(f"  {T_BOLD}{T_WHITE}{provider}{T_RESET}{T_GRAY}  --  {len(assets)} asset(s){T_RESET}")
        if not assets:
            print(f"  {T_YELLOW}  No assets found.{T_RESET}\n")
            continue
        print(f"  {T_GRAY}{'Resource ID':<45}  Account ID{T_RESET}")
        print(f"  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
        for asset in assets:
            print(f"  {T_CYAN}{asset.get('resource_id', 'N/A'):<45}{T_RESET}  {T_WHITE}{asset.get('account_id', 'N/A')}{T_RESET}")
        print()


def print_ai_packages(packages):
    width = 64
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}  AI PACKAGE RISKS -- CRITICAL CVEs{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"  {t_label('Packages with Critical CVEs:')} {T_BOLD}{T_WHITE}{len(packages)}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")

    if not packages:
        print(f"\n  {T_YELLOW}No AI-related packages with Critical CVEs found.{T_RESET}\n")
        return

    for i, pkg in enumerate(packages, 1):
        vulns = pkg["critical_vulnerabilities"]
        images = pkg.get("images") or []
        print(f"\n  {T_BOLD}{T_WHITE}[{i} of {len(packages)}]{T_RESET}")
        print(f"  {t_label('Package:  ')} {T_BOLD}{T_WHITE}{pkg['package_name_version']}{T_RESET}")
        print(f"  {t_label('Type:     ')} {T_WHITE}{pkg['type']}{T_RESET}")
        print(f"  {t_label('Images:   ')} {T_WHITE}{pkg['all_images']} total  |  {pkg['running_images']} running{T_RESET}")
        if images:
            for img_name in images:
                print(f"              {T_DIM}{T_WHITE}{img_name}{T_RESET}")
        print(f"  {t_label('Critical: ')} {T_BOLD}{T_RED}{len(vulns)} CVE(s){T_RESET}")
        for v in vulns:
            fix = v.get("fix_resolution") or []
            fix_str = ", ".join(fix) if fix else "No fix available"
            print(f"\n    {T_BOLD}{T_RED}{v.get('cveid', 'N/A')}{T_RESET}")
            print(f"    {t_label('Fix:      ')} {T_YELLOW}{fix_str}{T_RESET}")
            desc = (v.get("description") or "").strip()
            if desc:
                short = desc[:160].replace("\n", " ")
                print(f"    {t_label('Desc:     ')} {T_DIM}{T_WHITE}{short}{'...' if len(desc) > 160 else ''}{T_RESET}")
        print(f"\n  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
    print()


def print_ai_ioms(ioms):
    width = 64
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}  AI CLOUD SERVICES -- ACTIVE MISCONFIGURATIONS{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")
    print(f"  {t_label('Active misconfigurations:')} {T_BOLD}{T_RED}{len(ioms)}{T_RESET}")
    print(f"{T_BOLD}{T_CYAN}{'=' * width}{T_RESET}")

    if not ioms:
        print(f"\n  {T_YELLOW}No active AI service misconfigurations found.{T_RESET}\n")
        return

    for i, iom in enumerate(ioms, 1):
        print(f"\n  {T_BOLD}{T_WHITE}[{i} of {len(ioms)}]{T_RESET}")
        print(f"  {t_label('Resource:     ')} {T_BOLD}{T_CYAN}{iom['resource_id']}{T_RESET}")
        print(f"  {t_label('Type:         ')} {T_WHITE}{iom['resource_type']}{T_DIM}  [{iom.get('resource_type_raw', '')}]{T_RESET}")
        print(f"  {t_label('Service:      ')} {T_WHITE}{iom['service']}{T_RESET}")
        print(f"  {t_label('Provider:     ')} {T_BOLD}{T_WHITE}{iom['provider']}{T_RESET}")
        print(f"  {t_label('Account:      ')} {T_WHITE}{iom['account_name']}{T_GRAY} ({iom['account_id']}){T_RESET}")
        print(f"  {t_label('Region:       ')} {T_WHITE}{iom['region']}{T_RESET}")
        print(f"  {t_label('Rule:         ')} {T_BOLD}{T_WHITE}{iom['rule_name']}{T_RESET}")
        print(f"  {t_label('Severity:     ')} {T_BOLD}{T_RED}{iom['severity']}{T_RESET}")
        if iom.get("description"):
            desc = iom["description"][:160].replace("\n", " ")
            print(f"  {t_label('Description:  ')} {T_WHITE}{desc}{T_RESET}")
        if iom.get("remediation"):
            steps = iom["remediation"].split("|\n")
            print(f"\n  {T_BOLD}{T_CYAN}  Remediation{T_RESET}")
            for step in steps:
                step = step.strip()
                if step:
                    for wrapped in textwrap.wrap(step, width=56) or [step]:
                        print(f"    {T_DIM}{T_WHITE}{wrapped}{T_RESET}")
        print(f"\n  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
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
        m = _re.search(r"https://api\.([^/]+)\.crowdstrike\.com", api_base)
        if m:
            console = f"https://{m.group(1)}.falcon.crowdstrike.com"
        else:
            dbg(f"[_falcon_iom_url] unrecognised base URL {api_base!r}; defaulting to US-1 console")
            console = "https://falcon.crowdstrike.com"

    parts = entity_id.split("|")
    resource_id = parts[5] if len(parts) >= 6 else ""  # segment 5 = resource_id
    rule_uuid   = parts[6] if len(parts) >= 7 else ""  # segment 6 = rule UUID
    severity    = (iom.get("severity") or "high").lower()

    # Pipes encode as %7C; colons in resource_type stay bare
    encoded_id = entity_id.replace("|", "%7C")

    filter_str = (
        f"extension_status:'Unresolved'"
        f"+resource_status:'active'"
        f"+severity:'{severity}'"
        + (f"+rule_id:'{rule_uuid}'"   if rule_uuid   else "")
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
        if "::kms::"               in raw: return f"{b}/kms/home?region={region}#/kms/keys/{rid}"
        if "::secretsmanager::"    in raw: return f"{b}/secretsmanager/home?region={region}#!/secret?name={_arn_name(rid)}"
        if "::sagemaker::notebookinstance" in raw: return f"{b}/sagemaker/home?region={region}#/notebook-instances/{rid}"
        if "::sagemaker::model"    in raw: return f"{b}/sagemaker/home?region={region}#/models/{rid}"
        if "::sagemaker::endpoint" in raw: return f"{b}/sagemaker/home?region={region}#/endpoints/{rid}"
        if "::sagemaker::"         in raw: return f"{b}/sagemaker/home?region={region}"
        if "::bedrock::"           in raw: return f"{b}/bedrock/home?region={region}"
        if "::cloudtrail::"        in raw: return f"{b}/cloudtrail/home?region={region}#/trails/{rid}" if rid and rid != "N/A" else f"{b}/cloudtrail/home?region={region}#/trails"
        if "::cloudformation::stack" in raw: return f"{b}/cloudformation/home?region={region}#/stacks/stackinfo?stackId={rid}"
        if "::cloudformation::"    in raw: return f"{b}/cloudformation/home?region={region}"
        if "::logs::loggroup"      in raw: return f"{b}/cloudwatch/home?region={region}#logsV2:log-groups/log-group/{quote(rid, safe='')}"
        if "::organizations::"     in raw: return f"{b}/organizations/v2/home"
        if "::account::"           in raw: return f"{b}/account/home"
        return f"{b}/console/home?region={region}"

    if provider == "GCP":
        proj = acct
        if "compute.googleapis.com/instancegroupmanager" in raw: return f"https://console.cloud.google.com/compute/instancegroups/list?project={proj}"
        if "compute.googleapis.com/instance"   in raw: return f"https://console.cloud.google.com/compute/instances?project={proj}"
        if "compute.googleapis.com/disk"       in raw: return f"https://console.cloud.google.com/compute/disks?project={proj}"
        if "compute.googleapis.com/firewall"   in raw: return f"https://console.cloud.google.com/networking/firewalls/list?project={proj}"
        if "compute.googleapis.com/network"    in raw: return f"https://console.cloud.google.com/networking/networks/list?project={proj}"
        if "compute.googleapis.com/subnetwork" in raw: return f"https://console.cloud.google.com/networking/subnetworks/list?project={proj}"
        if "storage.googleapis.com"            in raw: return f"https://console.cloud.google.com/storage/browser/{rid}?project={proj}"
        if "iam.googleapis.com"                in raw: return f"https://console.cloud.google.com/iam-admin/iam?project={proj}"
        if "container.googleapis.com"          in raw: return f"https://console.cloud.google.com/kubernetes/list?project={proj}"
        if "aiplatform.googleapis.com"         in raw: return f"https://console.cloud.google.com/vertex-ai?project={proj}"
        if "secretmanager.googleapis.com"      in raw: return f"https://console.cloud.google.com/security/secret-manager?project={proj}"
        if "pubsub.googleapis.com"             in raw: return f"https://console.cloud.google.com/cloudpubsub/topic/list?project={proj}"
        if "artifactregistry.googleapis.com"   in raw: return f"https://console.cloud.google.com/artifacts?project={proj}"
        if "logging.googleapis.com"            in raw: return f"https://console.cloud.google.com/logs?project={proj}"
        return f"https://console.cloud.google.com/home/dashboard?project={proj}"

    if provider in ("AZURE", "MICROSOFT"):
        if rid.startswith("/subscriptions/"):
            return f"https://portal.azure.com/#resource{rid}"
        return "https://portal.azure.com"

    return ""


class FalconReport(FPDF):
    LABEL_W = 34

    def header(self):
        if self.page_no() == 1:
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
              ai_packages_count=None, ioms_count=None, ioms_label="", filter_desc=""):
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
            for provider, count in vm_totals.items():
                self.set_font("Helvetica", "", 9)
                self.set_text_color(*MID_GRAY)
                self.cell(0, 7, f"Unmanaged Virtual Machines ({provider}):  {count}", align="C",
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)

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
        col_w = self.epw - self.LABEL_W
        for idx, (field, value) in enumerate(fields):
            self.set_font("Helvetica", "", 8)
            char_w = self.get_string_width("m") or 2.5
            chars_per_line = max(1, int(col_w / char_w))
            n_lines = max(1, -(-len(str(value or "N/A")) // chars_per_line))
            field_h = n_lines * 6 + 4
            if self.get_y() + field_h > self.h - self.b_margin:
                self.add_page()
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


def build_pdf(risks, ioas, vm_data, ai_packages, ioms, config):
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
        risks_count=len(risks)             if config.get("include_risks")       else None,
        ioas_count=len(ioas)               if config.get("include_ioas")        else None,
        vm_totals=vm_totals                if config.get("include_vms")         else None,
        ai_packages_count=len(ai_packages) if config.get("include_ai_packages") else None,
        ioms_count=len(ioms)               if iom_cats                          else None,
        ioms_label=ioms_label              if iom_cats                          else "",
        filter_desc=fdesc,
    )

    if config.get("include_risks"):
        pdf.add_page()
        pdf.section_header(f"Cloud Risks  ({len(risks)} total)")
        if not risks:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No risks found matching the filter.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, risk in enumerate(risks, 1):
                pdf.risk_card(i, len(risks), risk)

    if config.get("include_ioas"):
        pdf.add_page()
        pdf.section_header(f"Cloud IOA Detections  ({len(ioas)} total)")
        if not ioas:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No Cloud IOA detections found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, ioa in enumerate(ioas, 1):
                pdf.ioa_card(i, len(ioas), ioa)

    if config.get("include_ai_packages"):
        pdf.add_page()
        pdf.section_header(f"AI Package Risks -- Critical CVEs  ({len(ai_packages)} packages)")
        if not ai_packages:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No AI-related packages with Critical CVEs found.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, pkg in enumerate(ai_packages, 1):
                pdf.ai_package_card(i, len(ai_packages), pkg)

    if iom_cats:
        pdf.add_page()
        section_title = f"Cloud Service IOMs  ({len(ioms)} total)  -  {ioms_label}"
        pdf.section_header(section_title)
        if not ioms:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*MID_GRAY)
            pdf.cell(0, 8, "  No active misconfigurations found for the selected categories.",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            for i, iom in enumerate(ioms, 1):
                pdf.ai_iom_card(i, len(ioms), iom)

    if config.get("include_vms"):
        pdf.add_page()
        total_vms = sum(vm_totals.values())
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
    csd             = CloudSecurityDetections(auth_object=auth)

    risks = []
    if config["include_risks"]:
        print(f"\n{T_DIM}Fetching risks:  {risks_filter}{T_RESET}")
        risks = fetch_all_risks(cs, risks_filter)
        print(f"{T_DIM}  Found {len(risks)} risk(s).{T_RESET}\n")

    ioas = []
    if config["include_ioas"]:
        print(f"{T_DIM}Fetching cloud IOAs...{T_RESET}")
        ioas = fetch_cloud_ioas(alerts, config.get("ioa_severities", []))
        print(f"{T_DIM}  Found {len(ioas)} Cloud IOA(s).{T_RESET}\n")

    vm_data = {}
    if config["include_vms"]:
        for provider, vm_filter in vm_filters:
            print(f"{T_DIM}Fetching VMs:    {vm_filter}{T_RESET}")
            assets = fetch_unmanaged_vms(csa, vm_filter)
            print(f"{T_DIM}  Found {len(assets)} unmanaged Virtual Machine(s) for {provider}.{T_RESET}")
            vm_data[provider] = assets

    ai_packages = []
    if config["include_ai_packages"]:
        ai_sevs = config.get("ai_package_severities", ["Critical"])
        sev_label = ", ".join(ai_sevs) if ai_sevs else "all severities"
        print(f"{T_DIM}Fetching AI-related packages ({sev_label})...{T_RESET}")
        ai_packages = fetch_ai_critical_packages(cp, ci, ai_sevs)
        print(f"{T_DIM}  Found {len(ai_packages)} AI package(s) matching filter.{T_RESET}")

    ioms = []
    iom_cats = config.get("iom_categories", [])
    if iom_cats:
        iom_sevs = config.get("iom_severities", [])
        cat_label = "all categories" if "all" in iom_cats else ", ".join(iom_cats)
        sev_label = ", ".join(iom_sevs) if iom_sevs else "all severities"
        print(f"{T_DIM}Fetching IOMs ({cat_label} / {sev_label})...{T_RESET}")
        ioms = fetch_ioms(csd, iom_cats, iom_sevs)
        print(f"{T_DIM}  Found {len(ioms)} active misconfiguration(s).{T_RESET}")

    print()
    if config["include_risks"]:
        print_risks(risks)
    if config["include_ioas"]:
        print_cloud_ioas(ioas)
    if config["include_vms"]:
        print_vms(vm_data)
    if config["include_ai_packages"]:
        print_ai_packages(ai_packages)
    if iom_cats:
        print_ai_ioms(ioms)

    print(f"{T_DIM}Building PDF...{T_RESET}")
    build_pdf(risks, ioas, vm_data, ai_packages, ioms, config)
    print(f"{T_BOLD}{T_CYAN}PDF written to {config['output_file']}{T_RESET}")
