# 1. doc tham so va cau hinh
import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

TITLE = "Secret Scan Report (Gitleaks)"
POLICY = "any detected secret blocks deploy"
MAX_ROWS = 30


def fail(message):
    print(f"::error::{message}")
    sys.exit(1)


def read_config():
    parser = argparse.ArgumentParser(description="Secret quality gate for Gitleaks SARIF reports")
    parser.add_argument("--report", required=True, help="SARIF file produced by Gitleaks")
    parser.error = fail
    args = parser.parse_args()
    event = os.environ.get("GITHUB_EVENT_NAME") or None
    actor = os.environ.get("GITHUB_ACTOR") or "-"
    return Path(args.report), event, actor, scan_scope(event)


def scan_scope(event):
    if event == "push":
        return "commits in this push"
    if event == "pull_request":
        return "commits in this pull request"
    if event in ("workflow_dispatch", "schedule"):
        return "full history (all branches)"
    if event is None:
        return "local run"
    return f"unknown ({event})"


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


def integer_value(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def column_value(region):
    start = integer_value(region.get("startColumn"))
    end = integer_value(region.get("endColumn"))
    if start is not None and end is not None:
        return f"{start}-{end}"
    if start is not None:
        return start
    return "-"


def date_value(value):
    prefix = value[:10] if isinstance(value, str) else ""
    return prefix if re.fullmatch(r"\d{4}-\d{2}-\d{2}", prefix) else "-"


def finding_details(finding):
    # chi lay cac truong an toan can cho bao cao
    locations = finding.get("locations")
    first = as_object(locations[0]) if isinstance(locations, list) and locations else {}
    physical = as_object(first.get("physicalLocation"))
    artifact = as_object(physical.get("artifactLocation"))
    region = as_object(physical.get("region"))
    fingerprints = as_object(finding.get("partialFingerprints"))
    commit = fingerprints.get("commitSha")
    full_commit = commit if isinstance(commit, str) and commit else None
    return {
        "rule": display_value(finding.get("ruleId")),
        "file": display_value(artifact.get("uri")),
        "line": display_value(region.get("startLine")),
        "column": column_value(region),
        "commit": full_commit[:7] if full_commit else "-",
        "full_commit": full_commit,
        "date": date_value(fingerprints.get("date")),
    }


def description_of(rule):
    short = as_object(rule.get("shortDescription")).get("text")
    full = as_object(rule.get("fullDescription")).get("text")
    description = short or full
    return str(description)[:160] if description else "-"


def rule_catalog(run):
    tool = as_object(run.get("tool"))
    driver = as_object(tool.get("driver"))
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return {}
    return {
        str(rule.get("id")): description_of(rule)
        for rule in rules
        if isinstance(rule, dict) and rule.get("id")
    }


def fingerprint_of(finding):
    commit = finding["full_commit"]
    file_name = finding["file"]
    rule = finding["rule"]
    line = finding["line"]
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        return None
    if file_name == "-" or rule == "-" or line == "-":
        return None
    return f"{commit}:{file_name}:{rule}:{line}"


def classify(data):
    findings = []
    descriptions = {}
    for run in data["runs"]:
        catalog = rule_catalog(run)
        for raw_finding in run.get("results", []):
            finding = finding_details(raw_finding)
            findings.append(finding)
            description = catalog.get(finding["rule"], "-")
            if descriptions.get(finding["rule"], "-") == "-":
                descriptions[finding["rule"]] = description
    rules = Counter(finding["rule"] for finding in findings)
    fingerprints = [fingerprint_of(finding) for finding in findings]
    return {
        "all": findings,
        "rules": rules,
        "descriptions": {rule: descriptions[rule] for rule in rules},
        "fingerprints": [fingerprint for fingerprint in fingerprints if fingerprint],
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
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def table_row(values):
    return "| " + " | ".join(table_cell(value) for value in values) + " |"


def detail_table(findings):
    lines = [
        table_row(("Rule", "File", "Line", "Column", "Commit", "Date")),
        table_row(("---", "---", "---", "---", "---", "---")),
    ]
    rows = [
        table_row((
            finding["rule"], finding["file"], finding["line"], finding["column"],
            finding["commit"], finding["date"],
        ))
        for finding in findings[:MAX_ROWS]
    ]
    if len(findings) > MAX_ROWS:
        rows.append(table_row((
            "...", f"{len(findings) - MAX_ROWS} more rows, see artifact", "", "", "", "",
        )))
    return lines + rows


def reason_table(stats):
    lines = [
        table_row(("Rule", "Count", "Description")),
        table_row(("---", "---", "---")),
    ]
    entries = sorted(stats["rules"].items(), key=lambda item: (-item[1], item[0]))
    lines += [
        table_row((rule, count, stats["descriptions"].get(rule, "-")))
        for rule, count in entries
    ]
    return lines


def overview(status, stats, event, actor, scope):
    actor_label = "Pushed by" if event in ("push", "pull_request") else "Triggered by"
    return [
        f"## {TITLE}",
        "",
        table_row(("Item", "Result")),
        table_row(("---", "---")),
        table_row(("Quality Gate", status)),
        table_row(("Policy", POLICY)),
        table_row(("Scan scope", scope)),
        table_row((actor_label, actor)),
        table_row(("Secrets found", len(stats["all"]))),
        table_row(("Rules matched", len(stats["rules"]))),
    ]


def summary_tables(stats):
    if not stats["all"]:
        return []
    lines = ["", "### Detected secrets", ""] + detail_table(stats["all"])
    lines += [
        "",
        'Redacted line context: see the "Secret Scan By Gitleaks" step log.',
        "",
        "### Why blocked",
        "",
    ]
    lines += reason_table(stats)
    lines += [
        "",
        "### How to fix",
        "",
        (
            "1. Revoke or rotate the leaked credential now. The repository is public, "
            "so treat it as compromised."
        ),
        "2. Remove it from the code and load it from GitHub Secrets or an environment variable.",
        (
            "3. A new commit that deletes the secret is not enough: it stays in git history "
            "and the pull request keeps failing. Recreate the branch from main with clean code "
            "(or rewrite the feature branch), close the old pull request and delete the old "
            "branch."
        ),
        (
            "4. False positive only: add the fingerprint below to .gitleaksignore through a "
            "reviewed pull request."
        ),
        "",
    ]
    if stats["fingerprints"]:
        lines += fingerprint_section(stats["fingerprints"])
    return lines


def fingerprint_section(fingerprints):
    lines = [
        "<details>",
        "<summary>Fingerprints for .gitleaksignore (false positives only)</summary>",
        "",
        "```text",
    ]
    lines += fingerprints[:MAX_ROWS]
    if len(fingerprints) > MAX_ROWS:
        lines.append(f"... {len(fingerprints) - MAX_ROWS} more, see artifact")
    lines += ["```", "", "</details>"]
    return lines


def write_gate_result(report_path, status, stats, event, scope):
    gate_result = {
        "status": status,
        "report": report_path.name,
        "findings": len(stats["all"]),
        "rules": stats["rules"],
        "scan_scope": scope,
        "event": event,
        "rule_descriptions": stats["descriptions"],
        "fingerprints": stats["fingerprints"],
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
    report_path, event, actor, scope = read_config()
    data = read_report(report_path)
    stats = classify(data)
    status = gate_status(stats)
    write_summary(overview(status, stats, event, actor, scope) + summary_tables(stats))
    write_gate_result(report_path, status, stats, event, scope)
    decide(status, stats)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # khong dua du lieu bao cao vao thong bao loi ngoai du kien
        fail(f"{TITLE}: unexpected processing error")
