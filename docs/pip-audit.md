# pip-audit

Converts `pip-audit -f json` output into SARIF. Each vulnerability becomes its own rule,
so GitHub shows one alert per advisory. The alert title is the first sentence of the
advisory text, the rule id is the advisory id, and the rule links to its page on osv.dev.

## Capture the native output

```bash
pip-audit -r requirements.txt -f json > pip-audit.json || true
```

The `|| true` matters in CI: pip-audit exits nonzero when it finds vulnerabilities, and
you want the workflow to carry on to the conversion and upload steps. It cannot hide a
broken audit, because pip-audit writes a JSON document even when everything is clean;
if the file comes out empty the audit itself failed, and sarif-kit refuses to convert it.
Auditing an installed environment instead of a requirements file works the same way,
just drop the `-r` flag.

## Convert

```bash
sarif-kit convert --tool pip-audit -i pip-audit.json -o pip-audit.sarif --dep-file requirements.txt
```

pip-audit's JSON names packages, not files, so sarif-kit needs to know which file the
alerts should point at. `--dep-file` sets that path (default `requirements.txt`). Use the
repo-relative path of whatever manifest you audited so the alert links resolve.

## Severity mapping

Every finding is reported at SARIF level `error`. A known vulnerability in a dependency
you install is not a style nit. pip-audit's JSON carries no CVSS scores, so sarif-kit
does not invent a `security-severity` value; GitHub falls back to the alert level.

## Full workflow example

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - name: Audit dependencies
    run: pipx run pip-audit -r requirements.txt -f json > pip-audit.json || true
  - name: Convert to SARIF
    uses: sarif-kit/sarif-kit@v0.3.0
    with:
      tool: pip-audit
      input: pip-audit.json
      output: pip-audit.sarif
      dep-file: requirements.txt
  - name: Upload to Code Scanning
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: pip-audit.sarif
      category: pip-audit
```

## What it looks like

![A pip-audit finding rendered as a GitHub Code Scanning alert](img/pip-audit-alert.jpg)

## Notes

- Duplicate advisory entries for the same package (OSV sometimes lists one advisory
  twice) are collapsed into a single alert.
- Aliases (CVE, GHSA) and fix versions are included in the alert message.
- pip-audit resolves transitive dependencies unless you pass `--no-deps`, so expect alerts
  naming packages your manifest never mentions. They point at the manifest regardless,
  because that is the file you would edit to fix them.
