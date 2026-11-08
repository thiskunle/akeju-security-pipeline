"""Combine scanner reports into one summary. Created by Adekunle Akeju.

A scanner that crashed or wrote nothing is an error, never a pass. Secret values are never printed.
"""
import argparse
import json
import os
import pathlib
import sys

ATTRIBUTION = "akeju-security-pipeline, created by Adekunle Akeju"


class ReportError(Exception):
    pass


def load(path: pathlib.Path):
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text) if text.strip() else None
    except FileNotFoundError:
        raise ReportError(f"{path.name} is missing, so that scanner did not finish.")
    except json.JSONDecodeError:
        raise ReportError(f"{path.name} is not valid JSON, so that scanner did not finish.")


def secrets(data) -> list[dict]:
    seen, rows = set(), []
    for item in data or []:
        key = (item.get("File"), item.get("StartLine"), item.get("RuleID"), item.get("Commit", ""))
        if key not in seen:
            seen.add(key)
            where = f"{item.get('File')}:{item.get('StartLine')}"
            if item.get("Commit"):
                where += f" (commit {item['Commit'][:7]})"
            rows.append({"where": where, "what": item.get("RuleID", "secret")})
    return rows


def dependencies(data) -> list[dict]:
    rows = []
    for result in (data or {}).get("results", []):
        source = result.get("source", {}).get("path", "?")
        for package in result.get("packages", []):
            info = package.get("package", {})
            for vuln in package.get("vulnerabilities", []):
                rows.append({"where": source, "what": f"{info.get('name')} {info.get('version')}: {vuln.get('id')}"})
    return rows


def code(data) -> list[dict]:
    if data is None:
        raise ReportError("semgrep.json is empty, so that scanner did not finish.")
    return [{"where": f"{r.get('path')}:{r.get('start', {}).get('line')}", "what": f"{r.get('extra', {}).get('severity', '?')}: {r.get('check_id', '').rsplit('.', 1)[-1]}"}
            for r in data.get("results", [])]


def clean(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def render(sections: dict[str, list[dict]]) -> str:
    total = sum(map(len, sections.values()))
    lines = ["## Security summary", "", "**Nothing found.**" if total == 0 else f"**{total} finding(s).**", "",
             "| Check | Findings |", "|---|---|"]
    lines += [f"| {name} | {len(rows)} |" for name, rows in sections.items()]
    for name, rows in sections.items():
        if rows:
            lines += ["", f"### {name}", "", "| Where | What |", "|---|---|"]
            lines += [f"| `{clean(r['where'])}` | {clean(r['what'])} |" for r in rows[:100]]
            if len(rows) > 100:
                lines.append(f"\n{len(rows) - 100} more not shown.")
    lines += ["", f"*{ATTRIBUTION}*", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=ATTRIBUTION)
    parser.add_argument("--reports", type=pathlib.Path, required=True)
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args(argv)

    try:
        found = secrets(load(args.reports / "gitleaks.json"))
        history = args.reports / "gitleaks-history.json"
        if history.exists():
            found = secrets((load(args.reports / "gitleaks.json") or []) + (load(history) or []))
        sections = {
            "Secrets": found,
            "Vulnerable dependencies": dependencies(load(args.reports / "osv.json")),
            "Code issues": code(load(args.reports / "semgrep.json")),
        }
    except ReportError as exc:
        print(f"::error::{exc}")
        return 2

    text = render(sections)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text)
    total = sum(map(len, sections.values()))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"findings={total}\n")
    return 1 if total and args.fail_on_findings else 0


if __name__ == "__main__":
    sys.exit(main())
