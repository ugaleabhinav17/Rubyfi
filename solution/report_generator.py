
# ═══════════════════════════════════════════════════════
# FILE 2: utils/report_generator.py  (UPDATED — uses shared REMEDIATION_DB)
# ═══════════════════════════════════════════════════════
REPORT_GENERATOR_PY = '''#!/usr/bin/env python3
"""
RubyFi — Session Attack Tracker + Final Report Generator  (utils/report_generator.py)
──────────────────────────────────────────────────────────────────────────────────────
• AttackSession  (singleton) — log_attack() called by post_attack_hook()
• FinalReportGenerator      — generates full PDF + TXT report at session end
• REMEDIATION dict (simple) — imported from utils.remediation (single source)

Usage:
    # At end of session (e.g., main.py exit):
    from utils.report_generator import AttackSession, FinalReportGenerator
    FinalReportGenerator(AttackSession.instance()).generate(tester_name="Omkar")
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from termcolor import colored

# ── Pull rich remediation data from the single source of truth ────────
try:
    from utils.remediation import REMEDIATION_DB as _RDB
    def _rem(attack_type):
        d = _RDB.get(attack_type, {})
        return {
            "vulnerability": d.get("vulnerability", "N/A"),
            "risk"         : d.get("risk", "INFO"),
            "fix"          : d.get("fixes", [{}])[0].get("title", "See remediation report"),
            "steps"        : d.get("fixes", [{}])[0].get("steps", []),
            "impact"       : d.get("impact", ""),
            "checklist"    : d.get("checklist", []),
            "all_fixes"    : d.get("fixes", []),
        }
except ImportError:
    # Fallback if import path differs
    def _rem(attack_type):
        return {}

# ── PDF library detection (fpdf2 preferred → reportlab → txt only) ────
try:
    from fpdf import FPDF
    PDF_ENGINE = "fpdf2"
except ImportError:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                        Spacer, Table, TableStyle)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.units import cm
        PDF_ENGINE = "reportlab"
    except ImportError:
        PDF_ENGINE = "txt_only"

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

RISK_COLORS = {
    "CRITICAL": (220,  53,  69),
    "HIGH"    : (255, 133,  27),
    "MEDIUM"  : (255, 193,   7),
    "LOW"     : ( 40, 167,  69),
    "INFO"    : ( 23, 162, 184),
}


# ══════════════════════════════════════════════════════════════════════
# AttackSession  — singleton — tracks every attack in the session
# ══════════════════════════════════════════════════════════════════════
class AttackSession:
    """
    Singleton session tracker.
    post_attack_hook() in remediation.py calls .log_attack() automatically.
    At session end, call:  FinalReportGenerator(AttackSession.instance()).generate()
    """
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        """Call between test sessions if needed."""
        cls._instance = None

    def __init__(self):
        self.session_start = datetime.now()
        self.attacks_log   = []
        self.target_ssid   = "Unknown"
        self.target_bssid  = "Unknown"
        self.tester_name   = "RubyFi Tester"

    def log_attack(self,
                   attack_type:  str,
                   attack_name:  str,
                   target_ssid:  str,
                   target_bssid: str,
                   success:      bool,
                   duration_sec: float = 0.0,
                   extra:        dict  = None):
        """Log a completed attack. Called automatically by post_attack_hook()."""
        rem   = _rem(attack_type)
        entry = {
            "attack_type"  : attack_type,
            "attack_name"  : attack_name,
            "target_ssid"  : target_ssid,
            "target_bssid" : target_bssid,
            "success"      : success,
            "duration_sec" : round(duration_sec, 2),
            "timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "extra"        : extra or {},
            "remediation"  : rem,
        }
        self.attacks_log.append(entry)
        self.target_ssid  = target_ssid
        self.target_bssid = target_bssid

        status = colored("✅ SUCCESS", "green") if success else colored("❌ FAILED", "red")
        print(colored(f"\\n  [SESSION] {attack_name} logged → {status}", "cyan"))

    def successful_attacks(self):
        return [a for a in self.attacks_log if a["success"]]

    def failed_attacks(self):
        return [a for a in self.attacks_log if not a["success"]]


# ══════════════════════════════════════════════════════════════════════
# FinalReportGenerator
# ══════════════════════════════════════════════════════════════════════
class FinalReportGenerator:
    """
    Generates a complete PDF + TXT report at the end of a session.

    Usage:
        FinalReportGenerator(AttackSession.instance()).generate(tester_name="Omkar")
    """

    def __init__(self, session: AttackSession):
        self.session   = session
        self.ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.pdf_path  = REPORTS_DIR / f"RubyFi_Report_{self.ts}.pdf"
        self.txt_path  = REPORTS_DIR / f"RubyFi_Report_{self.ts}.txt"

    def generate(self, tester_name: str = "RubyFi Tester"):
        self.session.tester_name = tester_name
        successful = self.session.successful_attacks()
        self._print_session_summary()
        if not successful:
            print(colored("\\n[!] No successful attacks to report.", "yellow"))
            return
        self._generate_txt()
        if PDF_ENGINE == "fpdf2":
            self._generate_pdf_fpdf()
        elif PDF_ENGINE == "reportlab":
            self._generate_pdf_reportlab()
        else:
            print(colored("\\n[!] No PDF library. Install: pip install fpdf2", "yellow"))
            print(colored(f"[✓] TXT report saved → {self.txt_path}", "green"))

    # ── Terminal Summary ──────────────────────────────────────────────
    def _print_session_summary(self):
        s        = self.session
        total    = len(s.attacks_log)
        n_ok     = len(s.successful_attacks())
        n_fail   = len(s.failed_attacks())
        duration = (datetime.now() - s.session_start).seconds

        print(colored("\\n" + "═" * 65, "cyan", attrs=["bold"]))
        print(colored("  📊 RUBYFI SESSION COMPLETE — FINAL REPORT", "cyan", attrs=["bold"]))
        print(colored("═" * 65, "cyan", attrs=["bold"]))
        print(colored(f"  Tester       : {s.tester_name}", "white"))
        print(colored(f"  Target SSID  : {s.target_ssid}", "white"))
        print(colored(f"  Target BSSID : {s.target_bssid}", "white"))
        print(colored(f"  Session Start: {s.session_start.strftime(\'%Y-%m-%d %H:%M:%S\')}", "white"))
        print(colored(f"  Duration     : {duration}s", "white"))
        print(colored("─" * 65, "cyan"))
        print(colored(f"  Total Attacks: {total}", "white"))
        print(colored(f"  ✅ Successful : {n_ok}",  "green", attrs=["bold"]))
        print(colored(f"  ❌ Failed     : {n_fail}", "red"))
        print(colored("─" * 65, "cyan"))
        for a in s.successful_attacks():
            risk   = a["remediation"].get("risk", "INFO")
            rcolor = {"CRITICAL": "red", "HIGH": "red",
                      "MEDIUM": "yellow", "LOW": "green"}.get(risk, "white")
            print(colored(f"  ⚠️  [{risk}] {a[\'attack_name\']} — {a[\'target_ssid\']}", rcolor))
        print(colored("═" * 65, "cyan", attrs=["bold"]))

    # ── TXT Report ───────────────────────────────────────────────────
    def _generate_txt(self):
        s   = self.session
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "=" * 65,
            "  RUBYFI WI-FI SECURITY AUDIT REPORT",
            "=" * 65,
            f"  Tester        : {s.tester_name}",
            f"  Target SSID   : {s.target_ssid}",
            f"  Target BSSID  : {s.target_bssid}",
            f"  Date          : {now}",
            f"  Session Start : {s.session_start.strftime(\'%Y-%m-%d %H:%M:%S\')}",
            "=" * 65, "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"  Total attacks performed : {len(s.attacks_log)}",
            f"  Successful attacks      : {len(s.successful_attacks())}",
            f"  Failed attacks          : {len(s.failed_attacks())}",
            "",
        ]
        for i, attack in enumerate(s.successful_attacks(), 1):
            rem = attack["remediation"]
            lines += [
                "=" * 65,
                f"  FINDING #{i}",
                "=" * 65,
                f"  Attack     : {attack[\'attack_name\']}",
                f"  Target     : {attack[\'target_ssid\']} ({attack[\'target_bssid\']})",
                f"  Timestamp  : {attack[\'timestamp\']}",
                f"  Duration   : {attack[\'duration_sec\']}s",
                f"  Risk Level : {rem.get(\'risk\', \'UNKNOWN\')}",
                "",
                "  VULNERABILITY:",
                f"    {rem.get(\'vulnerability\', \'N/A\')}",
                "",
                "  IMPACT:",
                f"    {rem.get(\'impact\', \'N/A\')}",
                "",
                "  QUICK FIX:",
                f"    {rem.get(\'fix\', \'See detailed steps below\')}",
                "",
                "  REMEDIATION STEPS:",
            ]
            for j, step in enumerate(rem.get("steps", []), 1):
                lines.append(f"    {j}. {step}")

            # All fixes (rich data)
            for fix in rem.get("all_fixes", [])[1:]:  # skip first (already shown)
                lines += [f"\\n  Alternative Fix #{fix[\'priority\']}: {fix[\'title\']}",
                           f"    Why: {fix[\'why\']}"]
                for j, step in enumerate(fix["steps"], 1):
                    lines.append(f"    {j}. {step}")

            # Checklist
            lines += ["", "  SECURITY CHECKLIST:"]
            for item in rem.get("checklist", []):
                lines.append(f"    {item}")

            if attack.get("extra"):
                lines += ["", "  DETAILS:"]
                for k, v in attack["extra"].items():
                    lines.append(f"    {k}: {v}")
            lines.append("")

        lines += [
            "=" * 65,
            "  DISCLAIMER",
            "=" * 65,
            "  This report was generated by RubyFi for authorized",
            "  security testing only. Unauthorized use is illegal.",
            "=" * 65,
        ]
        self.txt_path.write_text("\\n".join(lines))
        print(colored(f"\\n  [✓] TXT Report → {self.txt_path}", "green"))

    # ── PDF Report (fpdf2) ───────────────────────────────────────────
    def _generate_pdf_fpdf(self):
        from fpdf import FPDF
        s   = self.session
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Cover header
        pdf.set_fill_color(15, 20, 40)
        pdf.rect(0, 0, 210, 45, "F")
        pdf.set_text_color(0, 210, 255)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_y(10)
        pdf.cell(0, 10, "RubyFi Wi-Fi Security Audit Report", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(180, 180, 180)
        pdf.cell(0, 8, "Authorized Penetration Test Report", align="C", new_x="LMARGIN", new_y="NEXT")

        # Meta
        pdf.set_y(52)
        for label, value in [
            ("Tester", s.tester_name), ("Target SSID", s.target_ssid),
            ("Target BSSID", s.target_bssid), ("Date", now),
            ("Session Start", s.session_start.strftime("%Y-%m-%d %H:%M:%S")),
        ]:
            pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(80, 80, 80)
            pdf.cell(45, 7, f"{label}:", new_x="RIGHT", new_y="LAST")
            pdf.set_font("Helvetica", "", 10); pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 7, str(value), new_x="LMARGIN", new_y="NEXT")

        # Summary
        pdf.ln(5)
        pdf.set_fill_color(15, 20, 40); pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 9, " EXECUTIVE SUMMARY", fill=True, new_x="LMARGIN", new_y="NEXT")
        for label, value in [
            ("Total Attacks Performed", str(len(s.attacks_log))),
            ("Successful Attacks",      str(len(s.successful_attacks()))),
            ("Failed Attacks",          str(len(s.failed_attacks()))),
        ]:
            pdf.set_font("Helvetica", "B", 10); pdf.set_fill_color(245, 245, 245)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(100, 7, f" {label}", fill=True, border=1, new_x="RIGHT", new_y="LAST")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(90, 7, f" {value}", border=1, new_x="LMARGIN", new_y="NEXT")

        # Findings
        pdf.ln(8)
        for i, attack in enumerate(s.successful_attacks(), 1):
            rem  = attack["remediation"]
            risk = rem.get("risk", "INFO")
            rc   = RISK_COLORS.get(risk, (100, 100, 100))

            pdf.set_fill_color(*rc); pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10,
                     f" FINDING #{i} | {attack[\'attack_name\']} | RISK: {risk}",
                     fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.set_text_color(30, 30, 30); pdf.set_font("Helvetica", "", 10)
            pdf.set_fill_color(250, 250, 250)
            for label, value in [
                ("Target",   f"{attack[\'target_ssid\']} ({attack[\'target_bssid\']})"),
                ("Time",     attack["timestamp"]),
                ("Duration", f"{attack[\'duration_sec\']}s"),
                ("Risk",     risk),
            ]:
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(40, 7, f" {label}:", fill=True, border=1, new_x="RIGHT", new_y="LAST")
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 7, f" {value}", border=1, new_x="LMARGIN", new_y="NEXT")

            # Vulnerability
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(*rc)
            pdf.cell(0, 7, " VULNERABILITY:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30); pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f" {rem.get(\'vulnerability\', \'N/A\')}", border=1)

            # Impact
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(220, 53, 69)
            pdf.cell(0, 7, " IMPACT:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30); pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f" {rem.get(\'impact\', \'N/A\')}", border=1)

            # All fixes
            for fix in rem.get("all_fixes", []):
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(40, 167, 69)
                pdf.cell(0, 7, f" FIX #{fix[\'priority\']}: {fix[\'title\']}",
                         new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(23, 162, 184); pdf.set_font("Helvetica", "I", 9)
                pdf.multi_cell(0, 5, f"   Why: {fix[\'why\']}")
                pdf.set_text_color(30, 30, 30); pdf.set_font("Helvetica", "", 10)
                for j, step in enumerate(fix["steps"], 1):
                    pdf.cell(0, 6, f"   {j}. {step}", new_x="LMARGIN", new_y="NEXT")

            # Checklist
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(23, 162, 184)
            pdf.cell(0, 7, " SECURITY CHECKLIST:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30); pdf.set_font("Helvetica", "", 10)
            for item in rem.get("checklist", []):
                pdf.cell(0, 6, f"   {item}", new_x="LMARGIN", new_y="NEXT")

            # Extra
            if attack.get("extra"):
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 10); pdf.set_text_color(100, 100, 100)
                pdf.cell(0, 7, " ADDITIONAL DETAILS:", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9); pdf.set_text_color(60, 60, 60)
                for k, v in attack["extra"].items():
                    pdf.cell(0, 5, f"   {k}: {v}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)

        # Footer
        pdf.set_fill_color(15, 20, 40); pdf.set_text_color(150, 150, 150)
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 8,
                 "This report is for authorized security testing only. RubyFi Wi-Fi Security Framework.",
                 align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.output(str(self.pdf_path))
        print(colored(f"  [✓] PDF Report → {self.pdf_path}", "green", attrs=["bold"]))

    # ── PDF Report (reportlab fallback) ──────────────────────────────
    def _generate_pdf_reportlab(self):
        doc    = SimpleDocTemplate(str(self.pdf_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story  = []
        s      = self.session
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     fontSize=20, spaceAfter=6)
        h2          = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13)

        story.append(Paragraph("RubyFi Wi-Fi Security Audit Report", title_style))
        story.append(Spacer(1, 0.3 * cm))

        meta_data = [
            ["Tester",     s.tester_name],
            ["SSID",       s.target_ssid],
            ["BSSID",      s.target_bssid],
            ["Date",       now],
            ["Total",      str(len(s.attacks_log))],
            ["Successful", str(len(s.successful_attacks()))],
        ]
        t = Table(meta_data, colWidths=[5 * cm, 12 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), rl_colors.HexColor("#0f1428")),
            ("TEXTCOLOR",  (0, 0), (0, -1), rl_colors.white),
            ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
            ("GRID",       (0, 0), (-1, -1), 0.5, rl_colors.grey),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5 * cm))

        for i, attack in enumerate(s.successful_attacks(), 1):
            rem  = attack["remediation"]
            risk = rem.get("risk", "INFO")
            story.append(Paragraph(f"Finding #{i}: {attack[\'attack_name\']} — {risk}", h2))
            fd = [
                ["Target",        f"{attack[\'target_ssid\']} ({attack[\'target_bssid\']})"],
                ["Time",          attack["timestamp"]],
                ["Duration",      f"{attack[\'duration_sec\']}s"],
                ["Vulnerability", rem.get("vulnerability", "N/A")],
                ["Impact",        rem.get("impact", "N/A")],
                ["Quick Fix",     rem.get("fix",   "N/A")],
            ]
            ft = Table(fd, colWidths=[4 * cm, 13 * cm])
            ft.setStyle(TableStyle([
                ("GRID",       (0, 0), (-1, -1), 0.5, rl_colors.grey),
                ("FONTNAME",   (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 0), (0, -1), rl_colors.HexColor("#eaf4fb")),
            ]))
            story.append(ft)
            story.append(Paragraph("Remediation Steps:", styles["Heading3"]))
            for j, step in enumerate(rem.get("steps", []), 1):
                story.append(Paragraph(f"{j}. {step}", styles["Normal"]))
            story.append(Paragraph("Security Checklist:", styles["Heading3"]))
            for item in rem.get("checklist", []):
                story.append(Paragraph(item, styles["Normal"]))
            story.append(Spacer(1, 0.5 * cm))

        doc.build(story)
        print(colored(f"  [✓] PDF Report → {self.pdf_path}", "green", attrs=["bold"]))


# ══════════════════════════════════════════════════════════════════════
# Convenience wrapper — call at main.py exit
# ══════════════════════════════════════════════════════════════════════
def generate_final_report(tester_name: str = "RubyFi Tester"):
    """
    Convenience function to call at session end.
    Typical usage in main.py:
        from utils.report_generator import generate_final_report
        generate_final_report(tester_name="Omkar")
    """
    session = AttackSession.instance()
    FinalReportGenerator(session).generate(tester_name=tester_name)
'''

with open("output/utils/report_generator.py", "w") as f:
    f.write(REPORT_GENERATOR_PY)
print("✅ utils/report_generator.py written")
