# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Security Pipeline, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import importlib.util
import json
import pathlib
import shutil
import subprocess

import pytest

_path = pathlib.Path(__file__).parents[1] / "scripts" / "summarize.py"
_spec = importlib.util.spec_from_file_location("summarize", _path)
summarize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summarize)

LEAK = [{"File": "a.env", "StartLine": 3, "RuleID": "aws-access-token", "Secret": "SUPERSECRETVALUE", "Match": "SUPERSECRETVALUE"}]
OSV = {"results": [{"source": {"path": "req.txt"}, "packages": [{"package": {"name": "django", "version": "2.0.1"}, "vulnerabilities": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]}]}
SEMGREP = {"results": [{"path": "a.py", "start": {"line": 4}, "check_id": "python.lang.dangerous-subprocess", "extra": {"severity": "ERROR"}}], "errors": []}


def write(folder, gitleaks=None, osv=None, semgrep=None):
    (folder / "gitleaks.json").write_text(json.dumps([] if gitleaks is None else gitleaks))
    (folder / "osv.json").write_text(json.dumps({"results": []} if osv is None else osv))
    (folder / "semgrep.json").write_text(json.dumps({"results": []} if semgrep is None else semgrep))


def test_clean_reports_pass(tmp_path, capsys):
    write(tmp_path)
    assert summarize.main(["--reports", str(tmp_path), "--fail-on-findings"]) == 0
    out = capsys.readouterr().out
    assert "Nothing found" in out and "Adekunle Akeju" in out


def test_findings_fail_only_when_asked(tmp_path):
    write(tmp_path, LEAK, OSV, SEMGREP)
    assert summarize.main(["--reports", str(tmp_path), "--fail-on-findings"]) == 1
    assert summarize.main(["--reports", str(tmp_path)]) == 0


def test_counts_and_outputs(tmp_path, monkeypatch):
    out, summary = tmp_path / "out", tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    write(tmp_path, LEAK, OSV, SEMGREP)
    summarize.main(["--reports", str(tmp_path)])
    assert "findings=4" in out.read_text()
    assert "django 2.0.1: GHSA-2" in summary.read_text()


def test_secret_values_are_never_printed(tmp_path, capsys):
    write(tmp_path, LEAK)
    summarize.main(["--reports", str(tmp_path)])
    assert "SUPERSECRETVALUE" not in capsys.readouterr().out


def test_history_results_are_merged_without_double_counting(tmp_path, capsys):
    write(tmp_path, LEAK)
    (tmp_path / "gitleaks-history.json").write_text(json.dumps(LEAK + [{**LEAK[0], "Commit": "abcdef1234"}]))
    summarize.main(["--reports", str(tmp_path)])
    out = capsys.readouterr().out
    assert "commit abcdef1" in out and "2 finding(s)" in out


@pytest.mark.parametrize("victim", ["gitleaks.json", "osv.json", "semgrep.json"])
def test_missing_report_is_an_error_not_a_pass(tmp_path, victim):
    write(tmp_path)
    (tmp_path / victim).unlink()
    assert summarize.main(["--reports", str(tmp_path)]) == 2


def test_corrupt_report_is_an_error(tmp_path):
    write(tmp_path)
    (tmp_path / "osv.json").write_text("{nope")
    assert summarize.main(["--reports", str(tmp_path)]) == 2


def test_markdown_injection_is_neutralized():
    text = summarize.render({"Secrets": [{"where": "a|b`c\nd", "what": "x"}]})
    assert "a\\|b'c d" in text


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks is not installed")
def test_real_gitleaks_finds_a_committed_secret(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    reports = tmp_path / "reports"
    reports.mkdir()
    # Assembled at run time so this test file does not itself contain a key.
    (repo / "config.txt").write_text("AWS_ACCESS_KEY_ID=" + "AKIA" + "Q7XK2M4PLNT5Z6WB" + "\n")
    subprocess.run(["gitleaks", "dir", str(repo), "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", str(reports / "gitleaks.json")], check=True, capture_output=True)
    write_others = {"osv.json": {"results": []}, "semgrep.json": {"results": []}}
    for name, value in write_others.items():
        (reports / name).write_text(json.dumps(value))
    assert summarize.main(["--reports", str(reports), "--fail-on-findings"]) == 1


@pytest.mark.skipif(not shutil.which("osv-scanner"), reason="osv-scanner is not installed")
def test_real_osv_scanner_finds_a_known_bad_package(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "requirements.txt").write_text("django==2.0.1\n")
    out = tmp_path / "osv.json"
    result = subprocess.run(["osv-scanner", "scan", "source", "-r", str(project), "--format", "json", "--output-file", str(out)], capture_output=True)
    assert result.returncode == 1, result.stderr
    assert len(summarize.dependencies(json.loads(out.read_text(encoding="utf-8")))) > 0
