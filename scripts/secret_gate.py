# 1. doc tham so va cau hinh
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

TITLE = "Secret Scan Report (Gitleaks)"
POLICY = "any detected secret blocks deploy"
MAX_ROWS = 30
DETAIL_HEADER = [
    "| Rule | File | Line | Commit |",
    "|---|---|---|---|",
]


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def read_config():
    parser = argparse.ArgumentParser(description="Secret quality gate for Gitleaks SARIF reports")
    parser.add_argument("--report", required=True, help="SARIF file produced by Gitleaks")
    parser.error = fail
    args = parser.parse_args()
    return Path(args.report)


# 2. doc bao cao
def as_object(value):
    return value if isinstance(value, dict) else {}


def validate_report(data):
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        raise ValueError("runs is missing or malformed")
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("runs must contain objects")
        results = run.get("results", [])
        if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
            raise ValueError("run results is malformed")


def read_report(report_path):
    # khong doc duoc bao cao thi khong duoc coi la sach
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
    return data


def report_error(message):
    write_summary([f"## {TITLE}", "", f"**Quality Gate: ERROR** - {message}"])
    fail(message)


# 3. phan loai
def display_value(value):
    if isinstance(value, (str, int)) and value != "":
        return value
    return "-"


def finding_details(finding):
    # chi lay vi tri va ma quy tac, khong lay noi dung bi mat hay thong tin tac gia
    locations = finding.get("locations")
    first = as_object(locations[0]) if isinstance(locations, list) and locations else {}
    physical = as_object(first.get("physicalLocation"))
    artifact = as_object(physical.get("artifactLocation"))
    region = as_object(physical.get("region"))
    fingerprints = as_object(finding.get("partialFingerprints"))
    commit = fingerprints.get("commitSha")
    return {
        "rule": display_value(finding.get("ruleId")),
        "file": display_value(artifact.get("uri")),
        "line": display_value(region.get("startLine")),
        "commit": commit[:7] if isinstance(commit, str) and commit else "-",
    }


def classify(data):
    findings = [
        finding_details(finding)
        for run in data["runs"]
        for finding in run.get("results", [])
    ]
    return {"all": findings, "rules": Counter(finding["rule"] for finding in findings)}


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
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def detail_table(findings):
    rows = [
        f"| {table_cell(finding['rule'])} | {table_cell(finding['file'])} "
        f"| {table_cell(finding['line'])} | {table_cell(finding['commit'])} |"
        for finding in findings[:MAX_ROWS]
    ]
    if len(findings) > MAX_ROWS:
        rows.append(f"| ... | {len(findings) - MAX_ROWS} more rows, see artifact | | |")
    return DETAIL_HEADER + rows


def overview(status, stats):
    return [
        f"## {TITLE}",
        "",
        "| Item | Result |",
        "|---|---|",
        f"| Quality Gate | {status} |",
        f"| Policy | {POLICY} |",
        f"| Secrets found | {len(stats['all'])} |",
        f"| Rules matched | {len(stats['rules'])} |",
    ]


def summary_tables(stats):
    if stats["all"]:
        return ["", "### Detected secrets", ""] + detail_table(stats["all"])
    return []


def write_gate_result(report_path, status, stats):
    gate_result = {
        "status": status,
        "report": report_path.name,
        "findings": len(stats["all"]),
        "rules": stats["rules"],
    }
    try:
        (report_path.parent / "gate-result.json").write_text(
            json.dumps(gate_result, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        fail(f"cannot write gate-result.json: {exc}")


# 5. quyet dinh
def gate_status(stats):
    if stats["all"]:
        return "BLOCKED"
    return "PASS"


def decide(status, stats):
    if status == "ERROR":
        fail(f"{TITLE}: report cannot be evaluated")
    if status == "BLOCKED":
        fail(f"{TITLE}: blocked ({len(stats['all'])} secrets found)")
    print(f"{TITLE}: {status}")


def main():
    report_path = read_config()
    data = read_report(report_path)
    stats = classify(data)
    status = gate_status(stats)
    write_summary(overview(status, stats) + summary_tables(stats))
    write_gate_result(report_path, status, stats)
    decide(status, stats)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # khong dua du lieu bao cao vao thong bao loi ngoai du kien
        fail(f"{TITLE}: unexpected processing error")
