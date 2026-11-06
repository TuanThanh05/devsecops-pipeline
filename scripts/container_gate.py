# 1. doc tham so va cau hinh
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

TITLE = "Container Image Scan Report (Trivy)"
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAX_ROWS = 30
DETAIL_HEADER = [
    "| Source | Library | CVE | Severity | Installed | Fixed | Status |",
    "|---|---|---|---|---|---|---|",
]
WARNING_HEADER = [
    "| Source | Library | CVE | Severity | Installed | Fixed | Status | Reason |",
    "|---|---|---|---|---|---|---|---|",
]


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def read_config():
    parser = argparse.ArgumentParser(description="Container quality gate for Trivy JSON reports")
    parser.add_argument("--report", required=True, help="JSON file produced by Trivy")
    parser.error = fail
    args = parser.parse_args()
    raw_severity = os.environ.get("GATE_SEVERITY", "")
    gate_levels = {s.strip().upper() for s in raw_severity.split(",") if s.strip()}
    if not gate_levels or not gate_levels <= set(LEVELS):
        reason = f"GATE_SEVERITY is invalid: {raw_severity!r}"
        write_summary([f"## {TITLE}", "", f"**Quality Gate: ERROR** - {reason}"])
        fail(reason)
    gate_order = [level for level in LEVELS if level in gate_levels]
    # chi gia tri dung moi chan loi chua co ban va
    block_unfixed = os.environ.get("BLOCK_UNFIXED", "false").strip().lower() == "true"
    return Path(args.report), gate_order, block_unfixed


# 2. doc bao cao
def is_valid_result(result):
    # moi muc phai la doi tuong, goi va lo hong phai la danh sach doi tuong
    if not isinstance(result, dict):
        return False
    for key in ("Packages", "Vulnerabilities"):
        items = result.get(key) or []
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            return False
    return True


def read_report(report_path):
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
        message = f"cannot read report ({reason})"
        write_summary([f"## {TITLE}", "", f"**Quality Gate: ERROR** - {message}"])
        fail(message)
    return data


def report_details(data):
    metadata = data.get("Metadata")
    operating_system = metadata.get("OS") if isinstance(metadata, dict) else None
    if not isinstance(operating_system, dict):
        operating_system = {}
    base_os = " ".join(
        str(operating_system[key]) for key in ("Family", "Name") if operating_system.get(key)
    )
    return {"image": data.get("ArtifactName") or "-", "base_os": base_os or "-"}


# 3. phan loai
def severity_of(vuln):
    # thieu muc do thi coi la khong ro
    return str(vuln.get("Severity") or "UNKNOWN").upper()


def has_fix(vuln):
    # co ban va khi va chi khi truong phien ban va khac rong
    return bool(vuln.get("FixedVersion"))


def source_of(result):
    if result.get("Class") == "os-pkgs":
        return "OS"
    if result.get("Class") == "lang-pkgs":
        return result.get("Type") or "language"
    return "other"


def counts_by_source(all_vulns, gate_order):
    by_source = {}
    for vuln in all_vulns:
        counts = by_source.setdefault(vuln["source"], {"fixed": 0, "unfixed": 0, "total": 0})
        counts["total"] += 1
        if severity_of(vuln) in gate_order:
            counts["fixed" if has_fix(vuln) else "unfixed"] += 1
    return by_source


def classify(results, gate_order, block_unfixed):
    all_vulns = [
        {**vuln, "source": source_of(result)}
        for result in results
        for vuln in (result.get("Vulnerabilities") or [])
    ]
    packages = [p for r in results for p in (r.get("Packages") or [])]
    in_gate = [v for v in all_vulns if severity_of(v) in gate_order]
    fixed = [v for v in in_gate if has_fix(v)]
    unfixed = [v for v in in_gate if not has_fix(v)]
    blocking, warning = (fixed + unfixed, []) if block_unfixed else (fixed, unfixed)
    unrated = [
        v for v in all_vulns
        if severity_of(v) == "UNKNOWN" and "UNKNOWN" not in gate_order
    ]
    warning = [{**v, "reason": "severity not rated"} for v in unrated] + [
        {**v, "reason": "no fix available"} for v in warning
    ]
    other = [
        v for v in all_vulns
        if severity_of(v) not in gate_order and severity_of(v) != "UNKNOWN"
    ]
    return {
        "all": all_vulns,
        "packages": packages,
        "counts": Counter(severity_of(v) for v in all_vulns),
        "fixed": fixed,
        "unfixed": unfixed,
        "blocking": blocking,
        "warning": warning,
        "other": other,
    }


# 4. ghi bao cao
def write_summary(lines):
    # chay tren may ca nhan thi khong co file tom tat, bo qua
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    except OSError as exc:
        fail(f"cannot write summary: {exc}")


def table_cell(value):
    text = str(value) if value is not None and value != "" else "-"
    return text.replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def detail_table(vulns, show_reason=False):
    rows = [
        f"| {table_cell(v.get('source'))} | {table_cell(v.get('PkgName'))} "
        f"| {table_cell(v.get('VulnerabilityID'))} | {table_cell(severity_of(v))} "
        f"| {table_cell(v.get('InstalledVersion'))} "
        f"| {table_cell(v.get('FixedVersion'))} | {table_cell(v.get('Status'))} "
        f"| {table_cell(v.get('reason'))} |"
        if show_reason else
        f"| {table_cell(v.get('source'))} | {table_cell(v.get('PkgName'))} "
        f"| {table_cell(v.get('VulnerabilityID'))} | {table_cell(severity_of(v))} "
        f"| {table_cell(v.get('InstalledVersion'))} "
        f"| {table_cell(v.get('FixedVersion'))} | {table_cell(v.get('Status'))} |"
        for v in vulns[:MAX_ROWS]
    ]
    if len(vulns) > MAX_ROWS:
        empty_cells = " |" * (7 if show_reason else 6)
        rows.append(
            f"| ... | {len(vulns) - MAX_ROWS} more rows, see artifact{empty_cells}"
        )
    return (WARNING_HEADER if show_reason else DETAIL_HEADER) + rows


def other_section(other):
    if not other:
        return []
    order = {level: index for index, level in enumerate(LEVELS)}
    sorted_other = sorted(other, key=lambda v: order.get(severity_of(v), len(LEVELS)))
    lines = [
        "",
        "<details>",
        f"<summary>Other findings (not blocking): {len(other)}</summary>",
        "",
    ]
    lines += detail_table(sorted_other)
    lines += ["", "</details>"]
    return lines


def overview(status, stats, gate_order, block_unfixed, details):
    return [
        f"## {TITLE}",
        "",
        "| Item | Result |",
        "|---|---|",
        f"| Quality Gate | {status} |",
        f"| Image | {details['image']} |",
        f"| Base OS | {details['base_os']} |",
        f"| Gate severity | {', '.join(gate_order)} |",
        f"| Unfixed vulnerabilities | {'BLOCK' if block_unfixed else 'WARN (not blocking)'} |",
        f"| Packages detected | {len(stats['packages'])} |",
        f"| Total vulnerabilities (all severities) | {len(stats['all'])} |",
        f"| In gate - fix available | {len(stats['fixed'])} |",
        f"| In gate - no fix available | {len(stats['unfixed'])} |",
        f"| Blocked | {len(stats['blocking'])} |",
        f"| Warnings | {len(stats['warning'])} |",
        f"| Warnings - no fix available | {warning_count(stats, 'no fix available')} |",
        f"| Warnings - severity not rated | {warning_count(stats, 'severity not rated')} |",
    ]


def warning_count(stats, reason):
    return sum(v.get("reason") == reason for v in stats["warning"])


def source_table(by_source):
    lines = [
        "",
        "### Vulnerabilities by source",
        "",
        "| Source | In gate - fix available | In gate - no fix available | Total |",
        "|---|---|---|---|",
    ]
    entries = list(by_source.items())
    lines += [
        f"| {source} | {counts['fixed']} | {counts['unfixed']} | {counts['total']} |"
        for source, counts in entries[:MAX_ROWS]
    ]
    if len(entries) > MAX_ROWS:
        lines.append(f"| ... | {len(entries) - MAX_ROWS} more rows, see artifact | | |")
    return lines


def summary_tables(stats, details):
    lines = ["", "| Severity | Count |", "|---|---|"]
    lines += [f"| {level} | {stats['counts'].get(level, 0)} |" for level in LEVELS]
    lines += source_table(details["by_source"])
    if stats["blocking"]:
        lines += ["", "### Blocked vulnerabilities", ""] + detail_table(stats["blocking"])
    if stats["warning"]:
        lines += ["", "### Warnings (not blocking, monitor)", ""]
        lines += detail_table(stats["warning"], show_reason=True)
    return lines + other_section(stats["other"])


def write_gate_result(report_path, status, stats, gate_order, block_unfixed, details):
    gate_result = {
        "status": status,
        "report": report_path.name,
        "gate_severity": gate_order,
        "block_unfixed": block_unfixed,
        "packages": len(stats["packages"]),
        "vulnerabilities_all": len(stats["all"]),
        "in_gate_fixed": len(stats["fixed"]),
        "in_gate_unfixed": len(stats["unfixed"]),
        "blocking": len(stats["blocking"]),
        "warning": len(stats["warning"]),
        "warning_no_fix": warning_count(stats, "no fix available"),
        "warning_unrated": warning_count(stats, "severity not rated"),
        "other": len(stats["other"]),
        "blocking_ids": [v.get("VulnerabilityID") for v in stats["blocking"]],
        "warning_ids": [v.get("VulnerabilityID") for v in stats["warning"]],
        **details,
    }
    try:
        (report_path.parent / "gate-result.json").write_text(
            json.dumps(gate_result, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        fail(f"cannot write gate-result.json: {exc}")


# 5. quyet dinh
def gate_status(stats):
    # quet ra khong goi thi khong duoc coi la sach
    if not stats["packages"]:
        return "ERROR"
    if stats["blocking"]:
        return "BLOCKED"
    if stats["warning"]:
        return "PASS_WITH_WARNINGS"
    return "PASS"


def decide(status, stats, gate_order):
    for vuln in stats["warning"]:
        if vuln["reason"] == "no fix available":
            print(f"::warning::{vuln.get('PkgName')} {vuln.get('VulnerabilityID')} "
                  f"({severity_of(vuln)}) has no fix available")
        else:
            print(f"::warning::{vuln.get('PkgName')} {vuln.get('VulnerabilityID')} "
                  "severity not rated yet")
    if status == "ERROR":
        fail(f"{TITLE}: no packages detected, report cannot be treated as clean")
    if status == "BLOCKED":
        fail(f"{TITLE}: blocked ({len(stats['blocking'])} blocking at {', '.join(gate_order)})")
    print(f"{TITLE}: {status}")


def main():
    report_path, gate_order, block_unfixed = read_config()
    data = read_report(report_path)
    stats = classify(data["Results"], gate_order, block_unfixed)
    details = report_details(data)
    details["by_source"] = counts_by_source(stats["all"], gate_order)
    status = gate_status(stats)
    lines = overview(status, stats, gate_order, block_unfixed, details)
    write_summary(lines + summary_tables(stats, details))
    write_gate_result(report_path, status, stats, gate_order, block_unfixed, details)
    decide(status, stats, gate_order)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        fail(f"{TITLE}: {exc}")
