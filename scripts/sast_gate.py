# 1. doc tham so va cau hinh
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

TITLE = "SAST Report (Semgrep)"
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAX_ROWS = 30
# khi doi bo quy tac hoac pham vi, phai sua dong thoi trong main.yml
RULESETS = "p/security-audit, p/owasp-top-ten"
SCOPE = "whole repository, except .github/workflows/main.yml"
DETAIL_HEADER = [
    "| Rule | File | Line | Severity |",
    "|---|---|---|---|",
]
WARNING_HEADER = [
    "| Rule | File | Line | Severity | Reason |",
    "|---|---|---|---|---|",
]


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def read_config():
    parser = argparse.ArgumentParser(description="SAST quality gate for Semgrep JSON reports")
    parser.add_argument("--report", required=True, help="JSON file produced by Semgrep")
    parser.error = fail
    args = parser.parse_args()
    raw_severity = os.environ.get("GATE_SEVERITY", "")
    gate_levels = {s.strip().upper() for s in raw_severity.split(",") if s.strip()}
    if not gate_levels or not gate_levels <= set(LEVELS):
        reason = f"GATE_SEVERITY is invalid: {raw_severity!r}"
        write_summary([f"## {TITLE}", "", f"**Quality Gate: ERROR** - {reason}"])
        fail(reason)
    gate_order = [level for level in LEVELS if level in gate_levels]
    return Path(args.report), gate_order


# 2. doc bao cao
def as_object(value):
    return value if isinstance(value, dict) else {}


def validate_report(data):
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise ValueError("results is missing or malformed")
    errors = data.get("errors", [])
    if not isinstance(errors, list) or not all(isinstance(item, dict) for item in errors):
        raise ValueError("errors is malformed")
    paths = data.get("paths", {})
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned", []), list):
        raise ValueError("paths.scanned is malformed")


def read_report(report_path):
    # khong doc duoc bao cao hoac ma thoat thi khong duoc coi la sach
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        report_error(f"cannot read report: {exc.strerror}")
    except ValueError:
        report_error("report is not valid JSON")
    try:
        validate_report(data)
    except ValueError as exc:
        report_error(str(exc))
    exit_path = report_path.parent / "semgrep-exit-code.txt"
    try:
        scanner_exit = int(exit_path.read_text(encoding="utf-8").strip())
    except OSError as exc:
        report_error(f"cannot read semgrep-exit-code.txt: {exc.strerror}")
    except ValueError:
        report_error("semgrep-exit-code.txt must contain an integer")
    return data, scanner_exit


def report_error(message):
    write_summary([f"## {TITLE}", "", f"**Quality Gate: ERROR** - {message}"])
    fail(message)


# 3. phan loai
def severity_of(finding):
    extra = as_object(finding.get("extra"))
    metadata = as_object(extra.get("metadata"))
    impact = str(metadata.get("impact") or metadata.get("severity") or "").upper()
    # uu tien muc do trong thong tin bo sung neu nhan dien duoc
    levels = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM", "LOW": "LOW", "INFO": "LOW",
    }
    if impact in levels:
        return levels[impact]
    # neu khong nhan dien duoc thi dung muc do cua cong cu
    fallback = str(extra.get("severity") or "").upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(fallback, "UNKNOWN")


def classify(data, scanner_exit, gate_order):
    findings = data["results"]
    blocking = [finding for finding in findings if severity_of(finding) in gate_order]
    unrated = [
        finding
        for finding in findings
        if severity_of(finding) == "UNKNOWN" and "UNKNOWN" not in gate_order
    ]
    warning = [{**finding, "reason": "severity not rated"} for finding in unrated]
    other = [
        finding
        for finding in findings
        if severity_of(finding) not in gate_order and severity_of(finding) != "UNKNOWN"
    ]
    return {
        "all": findings,
        "counts": Counter(severity_of(finding) for finding in findings),
        "blocking": blocking,
        "warning": warning,
        "other": other,
        "scanned": data.get("paths", {}).get("scanned", []),
        "errors": data.get("errors", []),
        "scanner_exit": scanner_exit,
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


def detail_table(findings, show_reason=False):
    rows = [
        f"| {table_cell(finding.get('check_id'))} | {table_cell(finding.get('path'))} "
        f"| {table_cell(as_object(finding.get('start')).get('line'))} "
        f"| {table_cell(severity_of(finding))} | {table_cell(finding.get('reason'))} |"
        if show_reason else
        f"| {table_cell(finding.get('check_id'))} | {table_cell(finding.get('path'))} "
        f"| {table_cell(as_object(finding.get('start')).get('line'))} "
        f"| {table_cell(severity_of(finding))} |"
        for finding in findings[:MAX_ROWS]
    ]
    if len(findings) > MAX_ROWS:
        empty_cells = " |" * (4 if show_reason else 3)
        rows.append(
            f"| ... | {len(findings) - MAX_ROWS} more rows, see artifact{empty_cells}"
        )
    return (WARNING_HEADER if show_reason else DETAIL_HEADER) + rows


def error_table(errors):
    lines = ["| Type | Path | Message |", "|---|---|---|"]
    lines += [
        f"| {table_cell(error.get('type'))} | {table_cell(error.get('path'))} "
        f"| {table_cell(str(error.get('message') or '-')[:120])} |"
        for error in errors[:MAX_ROWS]
    ]
    if len(errors) > MAX_ROWS:
        lines.append(f"| ... | {len(errors) - MAX_ROWS} more rows, see artifact | |")
    return lines


def other_section(other):
    if not other:
        return []
    order = {level: index for index, level in enumerate(LEVELS)}
    sorted_other = sorted(other, key=lambda finding: order.get(severity_of(finding), len(LEVELS)))
    lines = [
        "",
        "<details>",
        f"<summary>Other findings (not blocking): {len(other)}</summary>",
        "",
    ]
    lines += detail_table(sorted_other)
    lines += ["", "</details>"]
    return lines


def overview(status, stats, gate_order):
    return [
        f"## {TITLE}",
        "",
        "| Item | Result |",
        "|---|---|",
        f"| Quality Gate | {status} |",
        f"| Scope | {SCOPE} |",
        f"| Rulesets | {RULESETS} |",
        f"| Gate severity | {', '.join(gate_order)} |",
        f"| Files scanned | {len(stats['scanned'])} |",
        f"| Total findings | {len(stats['all'])} |",
        f"| Blocked | {len(stats['blocking'])} |",
        f"| Warnings | {len(stats['warning'])} |",
        f"| Analysis errors | {len(stats['errors'])} |",
        f"| Scanner exit code | {stats['scanner_exit']} |",
    ]


def summary_tables(stats):
    lines = ["", "| Severity | Count |", "|---|---|"]
    lines += [f"| {level} | {stats['counts'].get(level, 0)} |" for level in LEVELS]
    if stats["blocking"]:
        lines += ["", "### Blocked findings", ""] + detail_table(stats["blocking"])
    if stats["warning"]:
        lines += ["", "### Warnings (not blocking, monitor)", ""]
        lines += detail_table(stats["warning"], show_reason=True)
    if stats["errors"]:
        lines += ["", "### Analysis errors", ""] + error_table(stats["errors"])
    return lines + other_section(stats["other"])


def write_gate_result(report_path, status, stats, gate_order):
    gate_result = {
        "status": status,
        "report": report_path.name,
        "gate_severity": gate_order,
        "files_scanned": len(stats["scanned"]),
        "findings": len(stats["all"]),
        "blocking": len(stats["blocking"]),
        "warning": len(stats["warning"]),
        "other": len(stats["other"]),
        "analysis_errors": len(stats["errors"]),
        "scanner_exit_code": stats["scanner_exit"],
        "blocking_rules": [finding.get("check_id") for finding in stats["blocking"]],
        "warning_rules": [finding.get("check_id") for finding in stats["warning"]],
    }
    try:
        (report_path.parent / "gate-result.json").write_text(
            json.dumps(gate_result, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        fail(f"cannot write gate-result.json: {exc}")


# 5. quyet dinh
def gate_status(stats):
    # loi quet duoc uu tien truoc cac phat hien bi chan
    if stats["scanner_exit"] != 0 or stats["errors"] or not stats["scanned"]:
        return "ERROR"
    if stats["blocking"]:
        return "BLOCKED"
    if stats["warning"]:
        return "PASS_WITH_WARNINGS"
    return "PASS"


def decide(status, stats, gate_order):
    for finding in stats["warning"]:
        print(f"::warning::{finding.get('check_id')} at {finding.get('path')}:"
              f"{as_object(finding.get('start')).get('line')} severity not rated")
    if status == "ERROR":
        fail(f"{TITLE}: scanner failed or scan coverage is incomplete")
    if status == "BLOCKED":
        fail(f"{TITLE}: blocked ({len(stats['blocking'])} blocking at {', '.join(gate_order)})")
    print(f"{TITLE}: {status}")


def main():
    report_path, gate_order = read_config()
    data, scanner_exit = read_report(report_path)
    stats = classify(data, scanner_exit, gate_order)
    status = gate_status(stats)
    write_summary(overview(status, stats, gate_order) + summary_tables(stats))
    write_gate_result(report_path, status, stats, gate_order)
    decide(status, stats, gate_order)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        fail(f"{TITLE}: {exc}")
