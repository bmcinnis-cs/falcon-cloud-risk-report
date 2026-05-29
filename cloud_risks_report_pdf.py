import os
import sys
import argparse
import textwrap
from datetime import datetime, timezone
from dotenv import load_dotenv
from falconpy import OAuth2, CloudSecurity, CloudSecurityAssets, Alerts, ContainerPackages
from fpdf import FPDF, XPos, YPos

RISKS_FILTER = "status:'Open'+severity:'High'"
VM_FILTERS = [
    ("AWS",   "managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'"),
    ("Azure", "managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'"),
    ("GCP",   "managed_by:'Unmanaged'+cloud_provider:'gcp'+instance_state:'running'"),
]
OUTPUT_FILE = "falcon_cloud_security_report.pdf"

VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
VALID_PROVIDERS  = ["aws", "azure", "gcp"]

# PDF colors (R, G, B)
CS_RED     = (227, 24,  55)
DARK       = (20,  20,  20)
MID_GRAY   = (80,  80,  80)
LIGHT_GRAY = (230, 230, 230)
WHITE      = (255, 255, 255)
AMBER      = (200, 130, 0)
SECTION_BG = (245, 245, 245)

# ANSI terminal colors
T_RESET  = "\033[0m"
T_BOLD   = "\033[1m"
T_DIM    = "\033[2m"
T_RED    = "\033[91m"
T_YELLOW = "\033[93m"
T_CYAN   = "\033[96m"
T_WHITE  = "\033[97m"
T_GRAY   = "\033[90m"


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
    config["include_vms"]   = _prompt_yn("Include Unmanaged VMs", default=True)
    config["include_ai_packages"] = _prompt_yn("Include AI Package Risks (Critical CVEs)", default=True)
    print()

    if config["include_risks"]:
        print(f"  {T_BOLD}Risk Filters{T_RESET}")
        print(f"  {T_GRAY}Available severities: {', '.join(VALID_SEVERITIES)}{T_RESET}")
        sev_raw = _prompt("Severity (comma-separated)", "High")
        sevs = [s.strip().capitalize() for s in sev_raw.split(",") if s.strip()]
        config["severities"] = [s for s in sevs if s in VALID_SEVERITIES] or ["High"]

        status_raw = _prompt("Status (Open / Closed / All)", "Open")
        config["status"] = status_raw.strip().capitalize() if status_raw.strip() else "Open"

        prov_raw = _prompt("Cloud provider (aws / azure / gcp / all)", "all")
        prov = prov_raw.strip().lower()
        config["risk_provider"] = prov if prov in VALID_PROVIDERS else "all"
        print()

    if config["include_ioas"]:
        print(f"  {T_BOLD}Cloud IOA Filters{T_RESET}")
        ioa_sev_raw = _prompt("IOA severity filter (comma-separated, or all)", "all")
        if not ioa_sev_raw.strip() or ioa_sev_raw.strip().lower() == "all":
            config["ioa_severities"] = []
        else:
            sevs = [s.strip().capitalize() for s in ioa_sev_raw.split(",") if s.strip()]
            config["ioa_severities"] = [s for s in sevs if s in VALID_SEVERITIES]
        print()

    if config["include_ai_packages"]:
        print(f"  {T_BOLD}AI Package Filters{T_RESET}")
        ai_sev_raw = _prompt("Package severity filter (comma-separated, or all)", "Critical")
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

    print(f"  {T_BOLD}Output{T_RESET}")
    config["output_file"] = _prompt("Output filename", OUTPUT_FILE)
    print()

    return config


def _default_config():
    return {
        "include_risks":      True,
        "include_ioas":       True,
        "include_vms":        True,
        "include_ai_packages":    False,
        "ai_package_severities":  ["Critical"],
        "severities":      ["High"],
        "status":          "Open",
        "risk_provider":   "all",
        "ioa_severities":  [],
        "vm_providers":    ["AWS", "Azure", "GCP"],
        "output_file":     OUTPUT_FILE,
    }


def build_filters(config):
    sevs = config.get("severities", ["High"])
    if len(sevs) == 1:
        sev_filter = f"severity:'{sevs[0]}'"
    else:
        joined = ",".join(f"'{s}'" for s in sevs)
        sev_filter = f"severity:[{joined}]"

    status = config.get("status", "Open")
    risks_filter = sev_filter if status == "All" else f"status:'{status}'+{sev_filter}"

    provider = config.get("risk_provider", "all")
    if provider != "all":
        risks_filter += f"+cloud_provider:'{provider}'"

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
    return "  |  ".join(parts)


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


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
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if not batch or offset >= total:
            break
    return risks


def fetch_cloud_ioas(sdk):
    ids = []
    after = None
    while True:
        params = {"limit": 1000, "filter": "type:'cloud-ioa'"}
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


def fetch_ai_critical_packages(sdk, severities):
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
            result.append({
                "package_name_version": pkg.get("package_name_version", "N/A"),
                "type":                 pkg.get("type", "N/A"),
                "all_images":           pkg.get("all_images", 0),
                "running_images":       pkg.get("running_images", 0),
                "critical_vulnerabilities": matched,
            })
    return result


# --- Terminal output ---

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
        print(f"\n  {T_BOLD}{T_WHITE}[{i} of {len(packages)}]{T_RESET}")
        print(f"  {t_label('Package:  ')} {T_BOLD}{T_WHITE}{pkg['package_name_version']}{T_RESET}")
        print(f"  {t_label('Type:     ')} {T_WHITE}{pkg['type']}{T_RESET}")
        print(f"  {t_label('Images:   ')} {T_WHITE}{pkg['all_images']} total  |  {pkg['running_images']} running{T_RESET}")
        print(f"  {t_label('Critical: ')} {T_BOLD}{T_RED}{len(vulns)} CVE(s){T_RESET}")
        for v in vulns:
            fix = v.get("fix_resolution") or []
            fix_str = ", ".join(fix) if fix else "No fix available"
            print(f"\n    {T_BOLD}{T_RED}{v['cveid']}{T_RESET}")
            print(f"    {t_label('Fix:      ')} {T_YELLOW}{fix_str}{T_RESET}")
            desc = (v.get("description") or "").strip()
            if desc:
                short = desc[:160].replace("\n", " ")
                print(f"    {t_label('Desc:     ')} {T_DIM}{T_WHITE}{short}{'...' if len(desc) > 160 else ''}{T_RESET}")
        print(f"\n  {T_GRAY}{'-' * (width - 2)}{T_RESET}")
    print()


# --- PDF ---

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
              ai_packages_count=None, filter_desc=""):
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
        self.ln(12)

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
                self.cell(0, 7, f"Unmanaged Running VMs ({provider}):  {count}", align="C",
                          new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if ai_packages_count is not None:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 8, f"AI Package Risks (Critical CVEs):  {ai_packages_count}", align="C",
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
        self.cell(0, 7, f"Generated: {now_utc()}", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def section_header(self, title):
        if self.get_y() > self.h - self.b_margin - 20:
            self.add_page()
        self.set_fill_color(*CS_RED)
        self.rect(self.l_margin, self.get_y(), self.epw, 12, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 12, f"  {title}",
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
            self.cell(0, 8, "  No assets found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
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
            rid = asset.get("resource_id", "N/A")
            rid_display = rid if len(rid) <= 45 else rid[:42] + "..."
            self.set_fill_color(*(SECTION_BG if idx % 2 == 0 else WHITE))
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*DARK)
            self.set_x(self.l_margin)
            self.cell(col_w, 6.5, f"  {rid_display}", fill=True)
            self.cell(col_w, 6.5, f"  {asset.get('account_id', 'N/A')}", fill=True,
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
            self.cell(self.epw, 7, sanitize(f"  {vuln['cveid']}"),
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


def build_pdf(risks, ioas, vm_data, ai_packages, config):
    output_file = config.get("output_file", OUTPUT_FILE)
    vm_totals = {provider: len(assets) for provider, assets in vm_data.items()}
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

    if config.get("include_vms"):
        pdf.add_page()
        total_vms = sum(vm_totals.values())
        pdf.section_header(f"Unmanaged Running VMs  ({total_vms} total)")
        for provider, assets in vm_data.items():
            pdf.sub_header(f"{provider}  -  {len(assets)} asset(s)")
            pdf.vm_table(assets)

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

    pdf.output(output_file)
    print(f"Report written to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Falcon Cloud Security PDF Report")
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Prompt for report configuration (sections, filters, output filename)",
    )
    args = parser.parse_args()

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

    config = interactive_config() if args.interactive else _default_config()
    risks_filter, vm_filters = build_filters(config)

    auth = OAuth2(
        client_id=os.environ["FALCON_CLIENT_ID"],
        client_secret=os.environ["FALCON_CLIENT_SECRET"],
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    cs     = CloudSecurity(auth_object=auth)
    csa    = CloudSecurityAssets(auth_object=auth)
    alerts = Alerts(auth_object=auth)
    cp     = ContainerPackages(auth_object=auth)

    risks = []
    if config["include_risks"]:
        print(f"\n{T_DIM}Fetching risks:  {risks_filter}{T_RESET}")
        risks = fetch_all_risks(cs, risks_filter)
        print(f"{T_DIM}  Found {len(risks)} risk(s).{T_RESET}\n")

    ioas = []
    if config["include_ioas"]:
        print(f"{T_DIM}Fetching cloud IOAs...{T_RESET}")
        ioas = fetch_cloud_ioas(alerts)
        print(f"{T_DIM}  Found {len(ioas)} Cloud IOA(s).{T_RESET}\n")

    vm_data = {}
    if config["include_vms"]:
        for provider, vm_filter in vm_filters:
            print(f"{T_DIM}Fetching VMs:    {vm_filter}{T_RESET}")
            assets = fetch_unmanaged_vms(csa, vm_filter)
            print(f"{T_DIM}  Found {len(assets)} asset(s) for {provider}.{T_RESET}")
            vm_data[provider] = assets

    ai_packages = []
    if config["include_ai_packages"]:
        ai_sevs = config.get("ai_package_severities", ["Critical"])
        sev_label = ", ".join(ai_sevs) if ai_sevs else "all severities"
        print(f"{T_DIM}Fetching AI-related packages ({sev_label})...{T_RESET}")
        ai_packages = fetch_ai_critical_packages(cp, ai_sevs)
        print(f"{T_DIM}  Found {len(ai_packages)} AI package(s) matching filter.{T_RESET}")

    print()
    if config["include_risks"]:
        print_risks(risks)
    if config["include_ioas"]:
        print_cloud_ioas(ioas)
    if config["include_vms"]:
        print_vms(vm_data)
    if config["include_ai_packages"]:
        print_ai_packages(ai_packages)

    print(f"{T_DIM}Building PDF...{T_RESET}")
    build_pdf(risks, ioas, vm_data, ai_packages, config)
    print(f"{T_BOLD}{T_CYAN}PDF written to {config['output_file']}{T_RESET}")
