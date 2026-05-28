import os
import textwrap
from datetime import datetime, timezone
from dotenv import load_dotenv
from falconpy import OAuth2, CloudSecurity, CloudSecurityAssets, Alerts
from fpdf import FPDF, XPos, YPos

RISKS_FILTER = "status:'Open'+severity:'High'"
VM_FILTERS = [
    ("AWS",   "managed_by:'Unmanaged'+cloud_provider:'aws'+instance_state:'running'"),
    ("Azure", "managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'"),
    ("GCP",   "managed_by:'Unmanaged'+cloud_provider:'gcp'+instance_state:'running'"),
]
OUTPUT_FILE = "falcon_cloud_security_report.pdf"

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


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def sanitize(text):
    if not text:
        return ""
    replacements = {
        "—": "--", "–": "-", "‒": "-",
        "'": "'",  "'": "'", """: '"', """: '"',
        "•": "*",  "…": "...", " ": " ",
    }
    for char, sub in replacements.items():
        text = text.replace(char, sub)
    return text.encode("latin-1", errors="replace").decode("latin-1")


# --- Data fetching ---

def fetch_all_risks(sdk):
    risks = []
    offset = 0
    while True:
        r = sdk.combined_cloud_risks(limit=1000, offset=offset, filter=RISKS_FILTER)
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


# --- PDF ---

class FalconReport(FPDF):
    LABEL_W = 34

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*CS_RED)
        self.set_y(5)
        self.cell(0, 8, "CROWDSTRIKE FALCON CLOUD SECURITY", align="C")
        self.set_y(self.t_margin)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MID_GRAY)
        self.cell(0, 8, f"Generated {now_utc()}  |  Page {self.page_no()}", align="C")

    def cover(self, total_risks, total_ioas, vm_totals):
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

        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 8, f"Open High Severity Risks:  {total_risks}", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 8, f"Cloud IOA Detections:  {total_ioas}", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        for provider, count in vm_totals.items():
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 7, f"Unmanaged Running VMs ({provider}):  {count}", align="C",
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
        self.set_fill_color(*DARK)
        self.rect(self.l_margin, self.get_y(), self.epw, 8, "F")
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        self.cell(self.epw, 8, f"  {title}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def row(self, field, value, alt=False):
        fill_color = SECTION_BG if alt else WHITE
        self.set_fill_color(*fill_color)
        text = sanitize(str(value or "N/A"))
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

    def risk_card(self, i, total, risk):
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
                self.set_fill_color(*LIGHT_GRAY)
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(*DARK)
                self.set_x(self.l_margin)
                self.cell(self.epw, 7, sanitize(f"  {factor.get('insight_name', 'N/A')}"),
                          fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                for remediation in factor.get("remediation") or []:
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

        self.set_draw_color(*LIGHT_GRAY)
        self.line(self.l_margin, self.get_y(), self.l_margin + self.epw, self.get_y())
        self.ln(8)

    def ioa_card(self, i, total, ioa):
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

        fields = [
            ("Description",  ioa.get("description")),
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

        self.set_draw_color(*LIGHT_GRAY)
        self.line(self.l_margin, self.get_y(), self.l_margin + self.epw, self.get_y())
        self.ln(8)

    def vm_table(self, assets):
        if not assets:
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 8, "  No assets found.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)
            return

        self.set_fill_color(*DARK)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*WHITE)
        self.set_x(self.l_margin)
        col_w = self.epw / 2
        self.cell(col_w, 7, "  Resource ID", fill=True)
        self.cell(col_w, 7, "  Account ID", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        for idx, asset in enumerate(assets):
            self.set_fill_color(*(SECTION_BG if idx % 2 == 0 else WHITE))
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*DARK)
            self.set_x(self.l_margin)
            self.cell(col_w, 6.5, f"  {asset.get('resource_id', 'N/A')}", fill=True)
            self.cell(col_w, 6.5, f"  {asset.get('account_id', 'N/A')}", fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(4)


def build_pdf(risks, ioas, vm_data):
    vm_totals = {provider: len(assets) for provider, assets in vm_data.items()}

    pdf = FalconReport(orientation="P", unit="mm", format="A4")
    pdf.set_margins(10, 26, 10)
    pdf.set_auto_page_break(auto=True, margin=20)

    # Cover
    pdf.add_page()
    pdf.cover(len(risks), len(ioas), vm_totals)

    # Risks section
    pdf.add_page()
    pdf.section_header(f"Open High Severity Risks  ({len(risks)} total)")
    if not risks:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(0, 8, "  No risks found matching the filter.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for i, risk in enumerate(risks, 1):
            if pdf.get_y() > pdf.h - pdf.b_margin - 40:
                pdf.add_page()
            pdf.risk_card(i, len(risks), risk)

    # Cloud IOAs section
    pdf.add_page()
    pdf.section_header(f"Cloud IOA Detections  ({len(ioas)} total)")
    if not ioas:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(0, 8, "  No Cloud IOA detections found.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for i, ioa in enumerate(ioas, 1):
            if pdf.get_y() > pdf.h - pdf.b_margin - 40:
                pdf.add_page()
            pdf.ioa_card(i, len(ioas), ioa)

    # Unmanaged VMs section
    pdf.add_page()
    total_vms = sum(vm_totals.values())
    pdf.section_header(f"Unmanaged Running VMs  ({total_vms} total)")
    for provider, assets in vm_data.items():
        pdf.sub_header(f"{provider}  -  {len(assets)} asset(s)")
        pdf.vm_table(assets)

    pdf.output(OUTPUT_FILE)
    print(f"Report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    auth = OAuth2(
        client_id=os.environ["FALCON_CLIENT_ID"],
        client_secret=os.environ["FALCON_CLIENT_SECRET"],
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    cs    = CloudSecurity(auth_object=auth)
    csa   = CloudSecurityAssets(auth_object=auth)
    alerts = Alerts(auth_object=auth)

    print(f"\n{T_DIM}Fetching risks:  {RISKS_FILTER}{T_RESET}")
    risks = fetch_all_risks(cs)
    print(f"{T_DIM}  Found {len(risks)} risk(s).{T_RESET}\n")

    print(f"{T_DIM}Fetching cloud IOAs...{T_RESET}")
    ioas = fetch_cloud_ioas(alerts)
    print(f"{T_DIM}  Found {len(ioas)} Cloud IOA(s).{T_RESET}\n")

    vm_data = {}
    for provider, vm_filter in VM_FILTERS:
        print(f"{T_DIM}Fetching VMs:    {vm_filter}{T_RESET}")
        assets = fetch_unmanaged_vms(csa, vm_filter)
        print(f"{T_DIM}  Found {len(assets)} asset(s) for {provider}.{T_RESET}")
        vm_data[provider] = assets

    print()
    print_risks(risks)
    print_cloud_ioas(ioas)
    print_vms(vm_data)

    print(f"{T_DIM}Building PDF...{T_RESET}")
    build_pdf(risks, ioas, vm_data)
    print(f"{T_BOLD}{T_CYAN}PDF written to {OUTPUT_FILE}{T_RESET}")
