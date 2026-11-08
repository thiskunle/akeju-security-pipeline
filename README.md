# akeju-security-pipeline

**Created by Adekunle Akeju, founder of GramByte Technologies Inc.**

A reusable GitHub Actions workflow that runs secret scanning, dependency checks and static analysis, then posts one summary on the run.

| Check | Tool |
|---|---|
| Secrets, current files and history | Gitleaks |
| Vulnerable dependencies | OSV-Scanner |
| Code issues | Semgrep, OWASP Top Ten and secure-defaults rules |

## Use it

```yaml
jobs:
  security:
    uses: thiskunle/akeju-security-pipeline/.github/workflows/security.yml@main
```

Inputs: `path`, `exclude`, `scan-history`, `fail-on-findings`, `pipeline-ref`. The workflow also returns `findings`, the total count.

## How it stays trustworthy

- Scanner downloads are pinned to a version and verified by SHA-256 before they run.
- Actions are pinned to commit hashes, and the workflow only asks for read access to the code.
- A scanner that crashes or writes no report fails the run. It is never counted as clean.
- Gitleaks runs with redaction, and the summary lists only the file and rule, never the secret.

## Proof that it catches problems

`self-test.yml` runs the real workflow against `tests/fixtures/planted`, a deliberately insecure sample, and fails unless the issues are found. The AWS key in that folder is made up.

## License and credit

AGPL-3.0-or-later, with an attribution requirement. See [NOTICE.md](NOTICE.md). Copyright (c) 2026 Adekunle Akeju.
