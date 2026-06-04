#!/usr/bin/env python
"""
Generate SECURITY_AUDIT_REPORT.pdf from pip-audit, Bandit, and django check --deploy.
Run from project root: python security/generate_audit_pdf.py
"""

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "deliverables"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd or PROJECT_ROOT,
            capture_output=True,
            text=True,
            shell=isinstance(cmd, str),
            timeout=300,
        )
        return result.stdout + result.stderr, result.returncode
    except Exception as exc:
        return str(exc), 1


def main():
    sections = []
    sections.append(("Report generated (UTC)", datetime.now(timezone.utc).isoformat()))
    sections.append(("Project", str(PROJECT_ROOT)))

    pip_out, pip_code = run_command(
        [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--format", "columns"]
    )
    sections.append((f"pip-audit (exit {pip_code})", pip_out or "(no output)"))

    bandit_out, bandit_code = run_command(
        [
            sys.executable, "-m", "bandit", "-r", str(PROJECT_ROOT),
            "--exclude", f"{PROJECT_ROOT / '.venv'},{PROJECT_ROOT / 'staticfiles'}",
            "-ll",
        ]
    )
    sections.append((f"Bandit (exit {bandit_code})", bandit_out or "(no output)"))

    deploy_out, deploy_code = run_command(
        [sys.executable, "manage.py", "check", "--deploy"],
        cwd=PROJECT_ROOT,
    )
    env = os.environ.copy()
    env.setdefault("DJANGO_DEBUG", "False")
    env.setdefault("DJANGO_SECRET_KEY", "audit-report-temp-key-min-50-chars-long-xx")
    env.setdefault("ALLOWED_HOSTS", "localhost,example.com")
    try:
        result = subprocess.run(
            [sys.executable, "manage.py", "check", "--deploy"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        deploy_out = result.stdout + result.stderr
        deploy_code = result.returncode
    except Exception as exc:
        deploy_out = str(exc)
        deploy_code = 1
    sections.append((f"Django check --deploy (exit {deploy_code})", deploy_out or "(no output)"))

    summary = (
        "ScholarVault Security Audit Log\n"
        "pip-audit | Bandit | Django deploy checks\n\n"
    )
    for title, body in sections:
        summary += f"\n{'=' * 60}\n{title}\n{'=' * 60}\n{body}\n"

    txt_path = REPORT_DIR / "SECURITY_AUDIT_REPORT.txt"
    txt_path.write_text(summary, encoding="utf-8")

    try:
        from fpdf import FPDF
    except ImportError:
        print(f"fpdf2 not installed. Text report written to {txt_path}")
        print("Install: pip install fpdf2")
        return

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(12, 12, 12)
    pdf.add_page()
    pdf.set_font("Helvetica", size=8)
    for line in summary.splitlines():
        safe = line.encode("latin-1", errors="replace").decode("latin-1")
        if not safe.strip():
            pdf.ln(3)
            continue
        # Wrap long lines (e.g. Bandit output) to fit page width
        width = pdf.epw
        while len(safe) > 100:
            pdf.multi_cell(width, 4, safe[:100])
            safe = safe[100:]
        pdf.multi_cell(width, 4, safe or ' ')
    pdf_path = REPORT_DIR / "SECURITY_AUDIT_REPORT.pdf"
    pdf.output(str(pdf_path))
    print(f"Wrote {pdf_path}")
    print(f"Wrote {txt_path}")


if __name__ == "__main__":
    main()
