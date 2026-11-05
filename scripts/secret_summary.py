"""Write the Secret Scanning summary; Gitleaks keeps control of its gate."""
import os
from pathlib import Path


def main():
    result = os.environ.get("SCAN_RESULT", "unknown")
    lines = [
        "Secret Scanning",
        "",
        "| Noi dung | Ket qua |",
        "|---|---|",
        "| Cong cu | Gitleaks |",
        f"| Trang thai buoc quet | {result} |",
        "| Chinh sach | Chan khi phat hien secret hoac scanner loi |",
        "| Bao cao | Artifact SARIF do Gitleaks Action quan ly |",
    ]
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
