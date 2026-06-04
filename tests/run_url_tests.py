#!/usr/bin/env python3
import csv
import json
import signal
import sys
from datetime import datetime
from pathlib import Path


TEST_TIMEOUT_SECONDS = 45
CSV_COLUMNS = [
    "name",
    "url",
    "category",
    "expected_level",
    "min_score",
    "max_score",
    "actual_level",
    "actual_score",
    "pass",
    "error",
    "notes",
]

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
TEST_URLS_PATH = TESTS_DIR / "test_urls.json"
MARKDOWN_RESULTS_PATH = TESTS_DIR / "latest_results.md"
CSV_RESULTS_PATH = TESTS_DIR / "latest_results.csv"

sys.path.insert(0, str(PROJECT_ROOT))

from scamslyce_core import analyse_url  # noqa: E402


class UrlTestTimeout(Exception):
    pass


def timeout_handler(signum, frame):
    raise UrlTestTimeout(f"Timed out after {TEST_TIMEOUT_SECONDS} seconds")


def load_test_cases():
    with TEST_URLS_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def should_skip(test_case):
    url = test_case.get("url", "")
    return not url.strip() or "PASTE_YOUR_STREAMLIT_URL_HERE" in url


def check_expectations(test_case, actual_level, actual_score):
    expected_level = test_case.get("expected_level")
    min_score = test_case.get("min_score")
    max_score = test_case.get("max_score")

    if expected_level and actual_level != expected_level:
        return False

    if min_score is not None and actual_score < min_score:
        return False

    if max_score is not None and actual_score > max_score:
        return False

    return True


def run_one_test(test_case):
    row = {
        "name": test_case.get("name", ""),
        "url": test_case.get("url", ""),
        "category": test_case.get("category", ""),
        "expected_level": test_case.get("expected_level", ""),
        "min_score": test_case.get("min_score", ""),
        "max_score": test_case.get("max_score", ""),
        "actual_level": "",
        "actual_score": "",
        "pass": "",
        "error": "",
        "notes": test_case.get("notes", ""),
    }

    if should_skip(test_case):
        row["pass"] = "SKIP"
        row["error"] = "Skipped empty or placeholder URL"
        return row

    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(TEST_TIMEOUT_SECONDS)
        result = analyse_url(row["url"], message_text="")
        signal.alarm(0)

        row["actual_level"] = result["risk_level"]
        row["actual_score"] = result["risk_score"]
        row["pass"] = check_expectations(
            test_case,
            result["risk_level"],
            result["risk_score"],
        )

    except Exception as error:
        signal.alarm(0)
        row["pass"] = False
        row["error"] = str(error)

    return row


def format_table(rows):
    headers = ["status", "name", "category", "expected", "actual", "score", "error"]
    table_rows = []

    for row in rows:
        if row["pass"] == "SKIP":
            status = "SKIP"
        elif row["pass"]:
            status = "PASS"
        else:
            status = "FAIL"

        expected_parts = []
        if row["expected_level"]:
            expected_parts.append(str(row["expected_level"]))
        if row["min_score"] != "":
            expected_parts.append(f">={row['min_score']}")
        if row["max_score"] != "":
            expected_parts.append(f"<={row['max_score']}")

        table_rows.append([
            status,
            row["name"],
            row["category"],
            " ".join(expected_parts),
            str(row["actual_level"]),
            str(row["actual_score"]),
            row["error"],
        ])

    widths = []
    for index, header in enumerate(headers):
        values = [str(table_row[index]) for table_row in table_rows]
        widths.append(max(len(header), *(len(value) for value in values)))

    lines = []
    lines.append(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    lines.append("-+-".join("-" * width for width in widths))

    for table_row in table_rows:
        lines.append(
            " | ".join(
                str(value).ljust(widths[index])
                for index, value in enumerate(table_row)
            )
        )

    return "\n".join(lines)


def write_csv_report(rows):
    with CSV_RESULTS_PATH.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_markdown_report(rows):
    generated_at = datetime.now().isoformat(timespec="seconds")
    pass_count = sum(1 for row in rows if row["pass"] is True)
    fail_count = sum(1 for row in rows if row["pass"] is False)
    skip_count = sum(1 for row in rows if row["pass"] == "SKIP")

    lines = [
        "# ScamSlyce URL Regression Results",
        "",
        f"Generated: {generated_at}",
        "",
        f"Passed: {pass_count}",
        f"Failed: {fail_count}",
        f"Skipped: {skip_count}",
        "",
        "| Status | Name | Category | Expected Level | Min Score | Max Score | Actual Level | Actual Score | Error | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for row in rows:
        if row["pass"] == "SKIP":
            status = "SKIP"
        elif row["pass"]:
            status = "PASS"
        else:
            status = "FAIL"

        lines.append(
            "| "
            + " | ".join([
                markdown_escape(status),
                markdown_escape(row["name"]),
                markdown_escape(row["category"]),
                markdown_escape(row["expected_level"]),
                markdown_escape(row["min_score"]),
                markdown_escape(row["max_score"]),
                markdown_escape(row["actual_level"]),
                markdown_escape(row["actual_score"]),
                markdown_escape(row["error"]),
                markdown_escape(row["notes"]),
            ])
            + " |"
        )

    MARKDOWN_RESULTS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    test_cases = load_test_cases()
    rows = []

    for test_case in test_cases:
        rows.append(run_one_test(test_case))

    print(format_table(rows))
    print()
    print(f"Markdown report: {MARKDOWN_RESULTS_PATH}")
    print(f"CSV report: {CSV_RESULTS_PATH}")

    write_markdown_report(rows)
    write_csv_report(rows)

    failed = any(row["pass"] is False for row in rows)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
