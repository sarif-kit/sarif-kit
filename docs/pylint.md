# pylint

Converts `pylint --output-format=json2` into SARIF. Each pylint message symbol becomes a
SARIF rule, `unused-import` for example, and the rule links to that message's page in the
pylint documentation. The numeric code goes into the rule description, so `W0611` is still
there for anyone who reads pylint output that way.

Use `json2`, not the older `json`, which pylint's own help calls the old one. Both report
the same findings at the same positions, end line and column included. What json2 adds is
a `statistics` block, the only part of the output that identifies it as pylint's rather
than any other JSON, and the `messageId` spelling of the code that the old format writes
as `message-id`. The old format is a bare array with neither, so sarif-kit refuses it
instead of half-reading it.

## Capture the native output

```bash
pylint --exit-zero --output-format=json2 src > pylint.json
```

`--exit-zero` is the guard here, and it is a better one than `|| true`. pylint encodes
what it found in the exit code as a bit mask (1 fatal, 2 error, 4 warning, 8 refactor,
16 convention), so a run that found something exits nonzero and would otherwise stop the
job before the upload. What `--exit-zero` does not swallow is 32, a usage error, so a
mistyped flag still fails the step instead of quietly producing nothing.

Run it from the repository root. pylint reports every path relative to the working
directory, even when the target is named absolutely, so from the root they come out
repo-relative on their own and `--src-root` is not needed. Run it from a subdirectory and
they come out relative to that instead, and the alerts point at paths that do not exist.
`--src-root` cannot repair that: it rewrites absolute paths, and these are already
relative.

## Convert

```bash
sarif-kit convert --tool pylint -i pylint.json -o pylint.sarif
```

## Severity mapping

| pylint message type | SARIF level |
|---|---|
| fatal | error |
| error | error |
| warning | warning |
| refactor | note |
| convention | note |
| info | note |

Style-level findings land at `note` on purpose. Convention and refactor messages are
opinions about style and design, not defects, and they arrive in bulk on any repository
that adopts pylint mid-life; GitHub has one informational tier to hold them, and the
alternative puts `line-too-long` beside `undefined-variable`. In the requests capture
sarif-kit tests against, they are 27 of 66 findings.

`info` messages only appear if you ask for them: `locally-disabled` and
`suppressed-message` are off unless the run adds `--enable=I`. The row is in the table
because the mapping exists, not because a default run produces any.

No `security-severity` is set, since nothing in pylint's output carries a CVSS score and
sarif-kit does not invent one.

## Full workflow example

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - name: Lint
    run: pipx run pylint --exit-zero --output-format=json2 src > pylint.json
  - name: Convert to SARIF
    uses: sarif-kit/sarif-kit@v0.3.0
    with:
      tool: pylint
      input: pylint.json
      output: pylint.sarif
  - name: Upload to Code Scanning
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: pylint.sarif
      category: pylint
```

## Notes

- pylint counts columns from zero and SARIF counts from one, so every column shifts by
  one on the way through. Both formats put the end position one past the last character,
  so that end lines up too.
- A message carries no description of the check behind it, only the text of the one
  occurrence, so the first message a symbol produces becomes the rule's title: for
  `line-too-long`, the rule is titled "Line too long (137/100)". Only its first line is
  used, because `duplicate-code` quotes the offending source into its message and eight
  lines of Python make a poor title. The finding keeps the whole text, so the duplicated
  blocks are still there to read.
- Messages with no end position, `line-too-long` among them, convert to a start position
  alone rather than an invented range.
- Messages longer than 1024 characters are clipped with a `... (truncated)` marker, which
  is GitHub's cap on rule description text. Most pylint messages are nowhere near it, but
  `fixme` quotes the whole comment it found, so one long TODO passes it alone.
- Messages from a plugin get the right level, since a plugin registers its checks under
  one of pylint's own categories: `W5101` is a warning like any other `W`. Its symbol has
  no page in the pylint documentation though, so that rule's help link points at one that
  does not exist.
- pylint writes a JSON document even when it finds nothing, so an empty file means the
  run itself failed. Converting it would report a clean, green run; sarif-kit exits 2
  instead. The same goes for a document that isn't pylint's: naming `--tool pylint` for
  some other JSON is an error rather than a run with no findings.
