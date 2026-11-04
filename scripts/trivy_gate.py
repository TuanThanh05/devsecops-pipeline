import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAX_ROWS = 30
DETAIL_HEADER = [
    "| Library | CVE | Severity | Installed | Fixed | Status |",
    "|---|---|---|---|---|---|",
]


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def write_summary(lines):
    # chay tren may ca nhan thi khong co file summary, bo qua
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    except OSError as exc:
        fail(f"cannot write summary: {exc}")


def is_valid_result(result):
    # moi muc trong results phai la object, packages va vulnerabilities la danh sach object
    if not isinstance(result, dict):
        return False
    for key in ("Packages", "Vulnerabilities"):
        items = result.get(key) or []
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            return False
    return True


def severity_of(vuln):
    # thieu severity thi coi la unknown
    return str(vuln.get("Severity") or "UNKNOWN").upper()


def has_fix(vuln):
    # co ban va khi va chi khi truong phien ban va khac rong
    return bool(vuln.get("FixedVersion"))


def detail_table(vulns):
    rows = [
        f"| {v.get('PkgName') or '-'} | {v.get('VulnerabilityID') or '-'} "
        f"| {severity_of(v)} | {v.get('InstalledVersion') or '-'} "
        f"| {v.get('FixedVersion') or '-'} | {v.get('Status') or '-'} |"
        for v in vulns[:MAX_ROWS]
    ]
    if len(vulns) > MAX_ROWS:
        rows.append(f"| ... | {len(vulns) - MAX_ROWS} more rows, see artifact | | | | |")
    return DETAIL_HEADER + rows


# 1. doc tham so va cau hinh
parser = argparse.ArgumentParser(description="quality gate for Trivy JSON reports")
parser.add_argument("--report", required=True, help="JSON file produced by Trivy")
parser.add_argument("--title", required=True, help="table title on the job Summary")
args = parser.parse_args()
report_path = Path(args.report)

raw_severity = os.environ.get("GATE_SEVERITY", "")
gate_levels = {s.strip().upper() for s in raw_severity.split(",") if s.strip()}
if not gate_levels or not gate_levels <= set(LEVELS):
    reason = f"GATE_SEVERITY is invalid: {raw_severity!r}"
    write_summary([f"## {args.title}", "", f"**Quality Gate: ERROR** - {reason}"])
    fail(reason)
gate_order = [level for level in LEVELS if level in gate_levels]

# chi dung "true" moi chan loi chua co ban va
block_unfixed = os.environ.get("BLOCK_UNFIXED", "false").strip().lower() == "true"

# 2. doc bao cao
# khong doc duoc bao cao thi khong duoc coi la sach
reason = None
try:
    data = json.loads(report_path.read_text(encoding="utf-8"))
except OSError as exc:
    reason = f"{report_path}: {exc.strerror}"
except ValueError:
    reason = f"{report_path}: not valid JSON"
else:
    results = data.get("Results") if isinstance(data, dict) else None
    if not isinstance(results, list) or not all(is_valid_result(r) for r in results):
        reason = f"{report_path.name}: Results is missing or malformed"

if reason:
    write_summary([
        f"## {args.title}", "", f"**Quality Gate: ERROR** - cannot read report ({reason})"
    ])
    fail(f"cannot read report ({reason})")

# 3. phan loai
all_vulns = [v for r in results for v in (r.get("Vulnerabilities") or [])]
packages = [p for r in results for p in (r.get("Packages") or [])]
counts = Counter(severity_of(v) for v in all_vulns)

in_gate = [v for v in all_vulns if severity_of(v) in gate_levels]
fixed = [v for v in in_gate if has_fix(v)]
unfixed = [v for v in in_gate if not has_fix(v)]

# loi ngoai muc xet chi duoc dem, khong chan, khong canh bao
if block_unfixed:
    blocking, warning = fixed + unfixed, []
else:
    blocking, warning = fixed, unfixed

# quet ra 0 goi thi khong duoc coi la sach
if not packages:
    status = "ERROR"
elif blocking:
    status = "BLOCKED"
elif warning:
    status = "PASS_WITH_WARNINGS"
else:
    status = "PASS"

# 4. ghi bao cao
lines = [
    f"## {args.title}",
    "",
    "| Item | Result |",
    "|---|---|",
    f"| Quality Gate | {status} |",
    f"| Gate severity | {', '.join(gate_order)} |",
    f"| Unfixed vulnerabilities | {'BLOCK' if block_unfixed else 'WARN (not blocking)'} |",
    f"| Packages detected | {len(packages)} |",
    f"| Total vulnerabilities (all severities) | {len(all_vulns)} |",
    f"| In gate - fix available | {len(fixed)} |",
    f"| In gate - no fix available | {len(unfixed)} |",
    f"| Blocked | {len(blocking)} |",
    f"| Warnings | {len(warning)} |",
    "",
    "| Severity | Count |",
    "|---|---|",
]
lines += [f"| {level} | {counts.get(level, 0)} |" for level in LEVELS]
if blocking:
    lines += ["", "### Blocked vulnerabilities", ""] + detail_table(blocking)
if warning:
    lines += ["", "### Warnings - no fix available (not blocking, monitor)", ""]
    lines += detail_table(warning)
write_summary(lines)

gate_result = {
    "status": status,
    "report": report_path.name,
    "gate_severity": gate_order,
    "block_unfixed": block_unfixed,
    "packages": len(packages),
    "vulnerabilities_all": len(all_vulns),
    "in_gate_fixed": len(fixed),
    "in_gate_unfixed": len(unfixed),
    "blocking": len(blocking),
    "warning": len(warning),
    "blocking_ids": [v.get("VulnerabilityID") for v in blocking],
    "warning_ids": [v.get("VulnerabilityID") for v in warning],
}
try:
    (report_path.parent / "gate-result.json").write_text(
        json.dumps(gate_result, indent=2) + "\n", encoding="utf-8"
    )
except OSError as exc:
    fail(f"cannot write gate-result.json: {exc}")

# 5. quyet dinh
for v in warning:
    print(f"::warning::{v.get('PkgName')} {v.get('VulnerabilityID')} "
          f"({severity_of(v)}) has no fix available")

if status == "ERROR":
    fail(f"{args.title}: no packages detected, report cannot be treated as clean")
if status == "BLOCKED":
    fail(f"{args.title}: blocked ({len(blocking)} blocking at {', '.join(gate_order)})")
print(f"{args.title}: {status}")
