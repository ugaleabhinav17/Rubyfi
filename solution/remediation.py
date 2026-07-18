#!/usr/bin/env python3
"""
RubyFi — Post-Attack Solution & Remediation Module
After every attack, this module shows:
  - What vulnerability was found
  - Risk rating
  - Step-by-step fix
  - Security checklist
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from termcolor import colored


# ══════════════════════════════════════════════════════════════════
#  RISK LEVELS
# ══════════════════════════════════════════════════════════════════
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"


# ══════════════════════════════════════════════════════════════════
#  REMEDIATION DATABASE
#  One entry per attack type
# ══════════════════════════════════════════════════════════════════
REMEDIATION_DB = {

    # ── HANDSHAKE CAPTURE ─────────────────────────────────────────
    "handshake": {
        "attack_name"   : "WPA2 Handshake Capture",
        "vulnerability" : "WPA2-PSK 4-Way Handshake captured — offline password cracking possible",
        "risk"          : HIGH,
        "impact"        : "Attacker can crack Wi-Fi password offline using wordlists or brute force",
        "fixes": [
            {
                "title": "Upgrade to WPA3",
                "priority": 1,
                "steps": [
                    "Login to router admin panel (192.168.1.1)",
                    "Go to Wireless Settings → Security",
                    "Change from WPA2-PSK to WPA3-SAE",
                    "Save and reboot router",
                    "Reconnect all devices"
                ],
                "why": "WPA3 uses SAE (Simultaneous Authentication of Equals) — immune to offline cracking"
            },
            {
                "title": "Use a Strong Password (Immediate Fix)",
                "priority": 2,
                "steps": [
                    "Use minimum 16 characters",
                    "Mix uppercase, lowercase, numbers, symbols",
                    "Avoid dictionary words, names, dates",
                    "Example: M@wifi#2024$Secure!X9",
                    "Change password every 6 months"
                ],
                "why": "Strong passwords make brute-force/dictionary attacks computationally infeasible"
            },
            {
                "title": "Enable WPA2-AES (if WPA3 not available)",
                "priority": 3,
                "steps": [
                    "Go to Wireless Settings → Encryption",
                    "Select WPA2-AES (NOT TKIP)",
                    "TKIP is deprecated and weak"
                ],
                "why": "AES encryption is significantly stronger than TKIP"
            }
        ],
        "checklist": [
            "☐ Upgraded to WPA3 or WPA2-AES",
            "☐ Password is 16+ characters",
            "☐ Password has no dictionary words",
            "☐ Router firmware is up to date",
            "☐ Changed password after test"
        ]
    },

    # ── DEAUTHENTICATION ATTACK ───────────────────────────────────
    "deauth": {
        "attack_name"   : "Deauthentication Attack",
        "vulnerability" : "802.11 management frames are unencrypted — deauth frames accepted without verification",
        "risk"          : HIGH,
        "impact"        : "Attacker can disconnect all clients from network at will (DoS)",
        "fixes": [
            {
                "title": "Enable 802.11w PMF (Protected Management Frames)",
                "priority": 1,
                "steps": [
                    "Login to router admin panel",
                    "Go to Wireless Settings → Advanced",
                    "Find 'Management Frame Protection' or '802.11w' or 'PMF'",
                    "Set to REQUIRED (not Optional)",
                    "Save and reboot router"
                ],
                "why": "PMF encrypts management frames — deauth attack is completely blocked"
            },
            {
                "title": "Upgrade to WPA3",
                "priority": 2,
                "steps": [
                    "WPA3 mandates PMF by default",
                    "Upgrade router firmware to support WPA3",
                    "Enable WPA3-SAE mode"
                ],
                "why": "WPA3 enforces PMF, making deauth attacks impossible"
            },
            {
                "title": "Use Enterprise Wi-Fi (WPA2-EAP)",
                "priority": 3,
                "steps": [
                    "Deploy RADIUS server for authentication",
                    "Use WPA2/WPA3-Enterprise with certificates",
                    "Each user gets unique credentials"
                ],
                "why": "Enterprise mode with PMF = fully protected against deauth DoS"
            }
        ],
        "checklist": [
            "☐ 802.11w PMF set to REQUIRED",
            "☐ Upgraded to WPA3 if router supports it",
            "☐ Verified PMF is active (not just optional)",
            "☐ Tested deauth — verify frames are blocked",
            "☐ Router firmware updated"
        ]
    },

    # ── EVIL TWIN / WI-FI PHISHING ────────────────────────────────
    "evil_twin": {
        "attack_name"   : "Evil Twin / Wi-Fi Phishing Attack",
        "vulnerability" : "No AP authentication — clients connect to any AP with matching SSID",
        "risk"          : CRITICAL,
        "impact"        : "All client traffic intercepted; credentials, passwords, sessions stolen",
        "fixes": [
            {
                "title": "Disable Auto-Connect on Devices",
                "priority": 1,
                "steps": [
                    "Windows: Settings → Wi-Fi → Manage Known Networks → Disable auto-connect",
                    "Android: Wi-Fi Settings → Saved Networks → Toggle off auto-connect",
                    "iOS: Settings → Wi-Fi → (i) icon → Disable Auto-Join",
                    "Linux: Edit /etc/NetworkManager — set autoconnect=false"
                ],
                "why": "Auto-connect is how clients fall into evil twin traps"
            },
            {
                "title": "Use WPA3-Enterprise + Certificate Authentication",
                "priority": 2,
                "steps": [
                    "Deploy RADIUS server (FreeRADIUS)",
                    "Issue client certificates (EAP-TLS)",
                    "Client only connects to AP with valid certificate",
                    "Fake AP cannot have your certificate → blocked"
                ],
                "why": "Certificate-based auth prevents connecting to rogue APs"
            },
            {
                "title": "Use VPN Always",
                "priority": 3,
                "steps": [
                    "Install VPN on all devices (OpenVPN, WireGuard)",
                    "Enable VPN kill-switch",
                    "VPN encrypts ALL traffic — even on fake AP",
                    "Attacker sees only encrypted gibberish"
                ],
                "why": "VPN provides end-to-end encryption regardless of which AP you connect to"
            },
            {
                "title": "Deploy WIDS (Wireless Intrusion Detection)",
                "priority": 4,
                "steps": [
                    "Enable WIDS on enterprise access points",
                    "Configure AP to detect duplicate SSIDs",
                    "Alert admin if evil twin detected",
                    "Tools: Kismet, Snort Wireless, enterprise APs"
                ],
                "why": "Automated detection of rogue APs in real-time"
            }
        ],
        "checklist": [
            "☐ Auto-connect disabled on all devices",
            "☐ VPN enabled on all devices",
            "☐ Only HTTPS sites visited on public Wi-Fi",
            "☐ WPA3-Enterprise deployed (for organization)",
            "☐ Certificate-based AP verification in place",
            "☐ WIDS/WIPS deployed and alerting"
        ]
    },

    # ── WPS ATTACK ────────────────────────────────────────────────
    "wps": {
        "attack_name"   : "WPS PIN Brute Force Attack",
        "vulnerability" : "WPS PIN is only 8 digits — crackable in hours via Reaver/Bully",
        "risk"          : CRITICAL,
        "impact"        : "WPA2 password revealed regardless of its strength",
        "fixes": [
            {
                "title": "Disable WPS Completely",
                "priority": 1,
                "steps": [
                    "Login to router admin (192.168.1.1)",
                    "Go to Wireless → WPS Settings",
                    "Toggle WPS OFF / Disable",
                    "Disable both PIN method AND push-button",
                    "Save and reboot router",
                    "Verify WPS is gone from scan results"
                ],
                "why": "WPS PIN is fundamentally broken — disable is the only fix"
            },
            {
                "title": "Update Router Firmware",
                "priority": 2,
                "steps": [
                    "Check router manufacturer website for latest firmware",
                    "Some routers auto-lock WPS after failed attempts",
                    "Firmware may add WPS rate-limiting"
                ],
                "why": "Newer firmware may add lockout after repeated failed WPS PINs"
            }
        ],
        "checklist": [
            "☐ WPS completely disabled in router settings",
            "☐ Verified WPS not visible in airodump scan",
            "☐ Router firmware updated",
            "☐ Changed Wi-Fi password after disabling WPS",
            "☐ Confirmed no WPS beacon in nearby scan"
        ]
    },

    # ── PASSWORD CRACKING ─────────────────────────────────────────
    "password_cracking": {
        "attack_name"   : "Wi-Fi Password Cracking (Dictionary / Brute Force)",
        "vulnerability" : "Weak or dictionary-based WPA2 password cracked successfully",
        "risk"          : CRITICAL,
        "impact"        : "Full network access — attacker joins network as legitimate client",
        "fixes": [
            {
                "title": "Set a Strong Password Immediately",
                "priority": 1,
                "steps": [
                    "Minimum 16 characters",
                    "Use a passphrase: 4+ random words + numbers",
                    "Example: BlueMango$Rain#92!Sky",
                    "Never use: names, birthdays, phone numbers",
                    "Never use: dictionary words alone",
                    "Change immediately after this test"
                ],
                "why": "A 20-char random password would take billions of years to crack"
            },
            {
                "title": "Upgrade to WPA3-SAE",
                "priority": 2,
                "steps": [
                    "WPA3 prevents offline dictionary attacks entirely",
                    "Each handshake is unique — wordlists useless",
                    "Enable in router wireless security settings"
                ],
                "why": "WPA3-SAE makes offline cracking mathematically impossible"
            }
        ],
        "checklist": [
            "☐ New password set (16+ chars, no dictionary words)",
            "☐ Upgraded to WPA3 if router supports it",
            "☐ Old password not reused anywhere",
            "☐ Router admin password also changed",
            "☐ All devices reconnected with new password"
        ]
    }
}


# ══════════════════════════════════════════════════════════════════
#  MAIN REMEDIATION CLASS
# ══════════════════════════════════════════════════════════════════
class RemediationAdvisor:
    """
    Show post-attack solution and save report after every attack.
    Call RemediationAdvisor.show("handshake") after each attack.
    """

    REPORTS_DIR = Path(__file__).parent.parent / "reports"

    def __init__(self):
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────────────────
    # MAIN ENTRY — call this after every attack
    # ─────────────────────────────────────────────────────────────
    def show(self, attack_type: str,
             target_ssid: str = "Unknown",
             target_bssid: str = "Unknown",
             extra_info: dict = None):
        """
        Display full remediation report for given attack type.
        attack_type: 'handshake' | 'deauth' | 'evil_twin' | 'wps' | 'password_cracking'
        """
        if attack_type not in REMEDIATION_DB:
            print(colored(f"[!] No remediation data for: {attack_type}", "yellow"))
            return

        data = REMEDIATION_DB[attack_type]

        self._print_header(data, target_ssid, target_bssid)
        self._print_vulnerability(data)
        self._print_fixes(data)
        self._print_checklist(data)
        self._save_report(data, target_ssid, target_bssid, extra_info)
        self._print_footer()

    # ─────────────────────────────────────────────────────────────
    # HEADER
    # ─────────────────────────────────────────────────────────────
    def _print_header(self, data: dict, ssid: str, bssid: str):
        risk   = data["risk"]
        colors = {CRITICAL: "red", HIGH: "red", MEDIUM: "yellow", LOW: "green"}
        c      = colors.get(risk, "white")

        print(colored("\n" + "═" * 65, c, attrs=["bold"]))
        print(colored(
            f"  🛡️  POST-ATTACK SOLUTION REPORT  —  RubyFi",
            "cyan", attrs=["bold"]
        ))
        print(colored("═" * 65, c, attrs=["bold"]))
        print(colored(f"  Attack   : {data['attack_name']}", "white"))
        print(colored(f"  Target   : {ssid}  ({bssid})", "white"))
        print(colored(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white"))
        print(colored(f"  Risk     : ", "white"), end="")
        print(colored(f"  ⚠️  {risk}  ", c, attrs=["bold", "reverse"]))
        print(colored("═" * 65 + "\n", c, attrs=["bold"]))

    # ─────────────────────────────────────────────────────────────
    # VULNERABILITY DETAILS
    # ─────────────────────────────────────────────────────────────
    def _print_vulnerability(self, data: dict):
        print(colored("  📌 VULNERABILITY FOUND", "red", attrs=["bold"]))
        print(colored("  " + "─" * 60, "red"))
        print(colored(f"  {data['vulnerability']}", "white"))
        print(colored(f"\n  💥 IMPACT:", "red", attrs=["bold"]))
        print(colored(f"  {data['impact']}\n", "white"))

    # ─────────────────────────────────────────────────────────────
    # FIXES
    # ─────────────────────────────────────────────────────────────
    def _print_fixes(self, data: dict):
        print(colored("  🔧 HOW TO FIX", "green", attrs=["bold"]))
        print(colored("  " + "─" * 60, "green"))

        for fix in data["fixes"]:
            priority_icon = ["🥇", "🥈", "🥉", "4️⃣"][fix["priority"] - 1]
            print(colored(
                f"\n  {priority_icon}  Fix #{fix['priority']}: {fix['title']}",
                "yellow", attrs=["bold"]
            ))
            print(colored(f"     Why: {fix['why']}", "cyan"))
            print(colored("     Steps:", "white"))
            for i, step in enumerate(fix["steps"], 1):
                print(colored(f"       {i}. {step}", "white"))

        print()

    # ─────────────────────────────────────────────────────────────
    # CHECKLIST
    # ─────────────────────────────────────────────────────────────
    def _print_checklist(self, data: dict):
        print(colored("  ✅ SECURITY CHECKLIST", "green", attrs=["bold"]))
        print(colored("  " + "─" * 60, "green"))
        for item in data["checklist"]:
            print(colored(f"  {item}", "white"))
        print()

    # ─────────────────────────────────────────────────────────────
    # SAVE REPORT TO FILE
    # ─────────────────────────────────────────────────────────────
    def _save_report(self, data: dict, ssid: str,
                     bssid: str, extra_info: dict = None):
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"report_{data['attack_name'].replace(' ', '_')}_{timestamp}.txt"
        report_path = self.REPORTS_DIR / report_name

        lines = [
            "=" * 65,
            f"  RubyFi — Post-Attack Remediation Report",
            "=" * 65,
            f"  Attack   : {data['attack_name']}",
            f"  Target   : {ssid}  ({bssid})",
            f"  Risk     : {data['risk']}",
            f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 65,
            "",
            "VULNERABILITY:",
            f"  {data['vulnerability']}",
            "",
            "IMPACT:",
            f"  {data['impact']}",
            "",
            "FIXES:",
        ]

        for fix in data["fixes"]:
            lines.append(f"\n  Fix #{fix['priority']}: {fix['title']}")
            lines.append(f"  Why: {fix['why']}")
            lines.append("  Steps:")
            for i, step in enumerate(fix["steps"], 1):
                lines.append(f"    {i}. {step}")

        lines += ["", "CHECKLIST:"]
        for item in data["checklist"]:
            lines.append(f"  {item}")

        if extra_info:
            lines += ["", "ADDITIONAL INFO:"]
            for k, v in extra_info.items():
                lines.append(f"  {k}: {v}")

        report_path.write_text("\n".join(lines))
        print(colored(
            f"  📄 Full report saved → {report_path}",
            "cyan"
        ))

    # ─────────────────────────────────────────────────────────────
    # FOOTER
    # ─────────────────────────────────────────────────────────────
    def _print_footer(self):
        print(colored("═" * 65, "cyan", attrs=["bold"]))
        print(colored(
            "  ⚠️  This report is for AUTHORIZED testing only.",
            "red", attrs=["bold"]
        ))
        print(colored(
            "  Implement fixes immediately to secure the network.",
            "yellow"
        ))
        print(colored("═" * 65 + "\n", "cyan", attrs=["bold"]))
        input(colored("  Press Enter to return to menu…", "cyan"))
