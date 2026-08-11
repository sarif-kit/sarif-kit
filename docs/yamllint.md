# yamllint

Converts yamllint's parsable output into SARIF. Each yamllint rule (trailing-spaces,
indentation, key-duplicates, and so on) becomes a SARIF rule with a link to its page in
the yamllint documentation, and every finding keeps its exact line and column.

## Capture the native output

```bash
yamllint -f parsable . > yamllint.txt || [ $? -eq 1 ]
```

Only the `parsable` format is supported. It is the one stable, documented format yamllint
has, one finding per line:

```
file.yaml:8:1: [error] duplication of key "key" in mapping (key-duplicates)
```

yamllint exits 1 when it finds errors; a run with only warnings exits 0 and needs no
special handling. The `[ $? -eq 1 ]` guard tolerates the errors case and nothing else,
so a bad flag or a missing binary still fails the job instead of silently uploading
nothing.

## Convert

```bash
sarif-kit convert --tool yamllint -i yamllint.txt -o yamllint.sarif
```

Run yamllint from the repository root so the paths in its output are repo-relative;
that is what makes the file links in GitHub's alerts work.

## Severity mapping

| yamllint level | SARIF level |
|---|---|
| error | error |
| warning | warning |

## What it looks like

![A yamllint finding rendered as a GitHub Code Scanning alert](img/yamllint-alert.jpg)

## Full workflow example

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - name: Lint YAML
    run: pipx run yamllint -f parsable . > yamllint.txt || [ $? -eq 1 ]
  - name: Convert to SARIF
    uses: sarif-kit/sarif-kit@v0.3.0
    with:
      tool: yamllint
      input: yamllint.txt
      output: yamllint.sarif
  - name: Upload to Code Scanning
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: yamllint.sarif
      category: yamllint
```
