import json
import os
import sys
from collections import Counter
from pathlib import Path

reports = Path(os.environ["REPORT_DIR"])
report_file = reports / "semgrep.json"
exit_file = reports / "semgrep-exit-code.txt"

try:
    scanner_exit = int(exit_file.read_text().strip())
    data = json.loads(report_file.read_text())
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    if not isinstance(data.get("results"), list):
        raise ValueError("Missing or invalid results")
except Exception as exc:
    print(f"::error::Semgrep report is missing or invalid: {exc}")
    sys.exit(1)

findings = data["results"]
errors = data.get("errors", [])
paths = data.get("paths", {})
scanned = paths.get("scanned", [])
skipped = paths.get("skipped", [])

def blocks_gate(finding):
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    impact = str(
        metadata.get("impact") or
        metadata.get("severity") or ""
    ).upper()

    # Metadata muc đo đuoc uu tien neu nhan dien đuoc.
    if impact in {"HIGH", "CRITICAL"}:
        return True
    if impact in {"LOW", "MEDIUM", "MODERATE", "INFO"}:
        return False

    # Quy uoc du phong cua nhom khi thieu metadata.
    return str(extra.get("severity", "")).upper() == "ERROR"

blocking = [f for f in findings if blocks_gate(f)]
counts = Counter(
    str(f.get("extra", {}).get("severity", "UNKNOWN")).upper()
    for f in findings
)

# Loi scanner hoac khong phan tich đuoc file nao khong đuoc coi la sach.
scan_error = scanner_exit != 0 or bool(errors) or not scanned
if scan_error:
    status = "ERROR"
elif blocking:
    status = "BLOCKED"
else:
    status = "PASS"

lines = [
    "##SAST / Semgrep",
    "",
    "| Noi dung | Ket qua |",
    "|---|---|",
    f"| Quality Gate | {status} |",
    f"| File đa phan tich | {len(scanned)} |",
    f"| Mcc bo qua đuoc ghi trong JSON | {len(skipped)} |",
    f"| Tong finding | {len(findings)} |",
    f"| Finding bi chan | {len(blocking)} |",
    f"| Loi phan tich | {len(errors)} |",
    f"| Exit code scanner | {scanner_exit} |",
    "",
    "### Finding theo severity cua rule",
    "",
    "| Severity | So luong |",
    "|---|---|",
]
lines += [f"| {key} | {value} |" for key, value in sorted(counts.items())]

with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
    summary.write("\n".join(lines) + "\n")

(reports / "gate-result.json").write_text(
    json.dumps({
        "status": status,
        "scanned_files": len(scanned),
        "findings": len(findings),
        "blocking_findings": len(blocking),
        "scanner_exit_code": scanner_exit,
        "analysis_errors": len(errors),
    }, indent=2)
)

if scan_error:
    print("::error::Semgrep failed or scan coverage is incomplete.")
    sys.exit(1)
if blocking:
    print("::error::SAST quality gate blocked deployment.")
    sys.exit(1)
