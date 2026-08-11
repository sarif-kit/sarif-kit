# PlatformIO check

Converts `pio check --json-output` into SARIF. `pio check` drives cppcheck by default
(clang-tidy and PVS-Studio are the alternatives) over a PlatformIO project. Each defect
id becomes a SARIF rule namespaced by the tool that reported it, `cppcheck:uninitvar`
for example, and when the defect carries a CWE number the rule links to that CWE's page.

## Capture the native output

```bash
pio check --json-output > pio-check.json
```

No exit-code guard is needed: `pio check` exits 0 even when it finds defects. If you
want the check step itself to fail the job, that is what its own `--fail-on-defect`
flag is for; conversion works either way.

Run it from the project root. The JSON reports absolute paths resolved against the
working directory, and `--src-root` (below) can only rewrite them if they line up.

On a fresh machine, which includes every CI runner, PlatformIO installs packages first
and prints "Tool Manager: Installing..." lines to stdout ahead of the JSON. sarif-kit
tolerates that: when the input as a whole is not valid JSON, it parses the last line,
which is where the JSON array always ends up.

## Convert

```bash
sarif-kit convert --tool platformio -i pio-check.json -o pio-check.sarif --src-root .
```

The defect paths are absolute, so `--src-root` matters here more than for any other
adapter: it rewrites them relative to your repository root, which is what makes the
file links in GitHub's alerts resolve.

## Severity mapping

| pio check severity | SARIF level |
|---|---|
| high | error |
| medium | warning |
| low | note |

The severity comes from the underlying tool; cppcheck's `error` arrives as high,
`warning` as medium, and `style`, `performance` and `portability` as low, with the
original class kept in the defect's category field. No `security-severity` is set:
nothing in the input carries a CVSS score, and sarif-kit does not invent one. Findings
with a CWE keep it as a `cwe` property on the result. cppcheck reports CWE 0 for checks
that have none assigned; sarif-kit drops it instead of linking to a CWE-0 page that
does not exist.

## What it looks like

![A pio check finding rendered as a GitHub Code Scanning alert](img/platformio-alert.jpg)

## Full workflow example

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - name: Static analysis
    run: pipx run platformio check --json-output > pio-check.json
  - name: Convert to SARIF
    uses: sarif-kit/sarif-kit@v0.3.0
    with:
      tool: platformio
      input: pio-check.json
      output: pio-check.sarif
      src-root: ${{ github.workspace }}
  - name: Upload to Code Scanning
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: pio-check.sarif
      category: platformio
```

## Notes

- The same defect reported by several environments (they usually compile the same
  `src/`) is collapsed into a single alert.
- A result entry with `"succeeded": false` and no defects means that check run itself
  failed, and the conversion refuses it with exit 2 rather than uploading an empty,
  green-looking run. With defects present the flag just means `--fail-on-defect`
  tripped, and the findings convert normally.
- clang-tidy and PVS-Studio emit the same JSON shape and should convert unchanged, but
  the fixtures sarif-kit tests against are cppcheck's, which is what `pio check` runs
  unless told otherwise.
- Messages longer than 1024 characters are clipped with a `... (truncated)` marker.
  GitHub caps rule description text at that length, and in practice an oversized
  message is cppcheck dumping its entire preprocessor configuration into the text.
