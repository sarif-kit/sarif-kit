# codespell

Converts codespell's text output into SARIF. Each distinct typo becomes its own rule, so
the alert list shows what is actually wrong ("recieve" should be "receive") instead of a
generic label repeated for every finding.

## Capture the native output

```bash
codespell > codespell.txt || [ $? -eq 65 ]
```

codespell has no JSON output; sarif-kit parses its standard text format directly:

```
src/module.py:14: recieve ==> receive
```

codespell exits 65 when it finds typos. The `[ $? -eq 65 ]` guard tolerates exactly that,
so the workflow carries on to the upload, while a real failure (bad flag, missing binary)
still fails the job instead of silently uploading nothing.
Do not use `--context`, it interleaves source lines with the findings and breaks parsing.

## Convert

```bash
sarif-kit convert --tool codespell -i codespell.txt -o codespell.sarif
```

Run codespell from the repository root so its paths are repo-relative and the alert file
links resolve.

## Severity mapping

Everything is reported at SARIF level `warning`; typos are worth fixing but they do not
fail a build. The rule id is the lowercased typo, so the same word in different casing
groups under one rule. When codespell offers several candidate corrections, or a note
explaining why a word is flagged, the full suggestion text is kept in the alert message.

## What it looks like

![A codespell finding rendered as a GitHub Code Scanning alert](img/codespell-alert.jpg)

## Full workflow example

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - name: Spell-check the tree
    run: pipx run codespell > codespell.txt || [ $? -eq 65 ]
  - name: Convert to SARIF
    uses: sarif-kit/sarif-kit@v0.3.0
    with:
      tool: codespell
      input: codespell.txt
      output: codespell.sarif
  - name: Upload to Code Scanning
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: codespell.sarif
      category: codespell
```
