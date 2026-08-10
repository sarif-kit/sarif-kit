"""Adapter tests: golden SARIF per captured fixture, plus parsing edge cases."""

from __future__ import annotations

import json

import pytest

from sarif_kit import SarifBuilder, assert_valid
from sarif_kit.adapters import ADAPTERS, detect_tool, get_adapter
from sarif_kit.adapters import codespell, pip_audit, platformio, pylint, yamllint

from .utils import assert_matches_golden, read_fixture

# (tool, fixture, golden) for every captured fixture.
CASES = [
    ("pip-audit", "pip-audit/native.json", "pip-audit.native.sarif.json"),
    ("pip-audit", "pip-audit/native.mixed.json", "pip-audit.mixed.sarif.json"),
    ("yamllint", "yamllint/native.parsable.txt", "yamllint.native.sarif.json"),
    ("yamllint", "yamllint/native.warnings.parsable.txt", "yamllint.warnings.sarif.json"),
    ("codespell", "codespell/native.txt", "codespell.native.sarif.json"),
    ("codespell", "codespell/native.multi.txt", "codespell.multi.sarif.json"),
    ("platformio", "platformio/native.fastled.json", "platformio.fastled.sarif.json"),
    ("pylint", "pylint/native.requests.json", "pylint.requests.sarif.json"),
    ("pylint", "pylint/native.fire.json", "pylint.fire.sarif.json"),
]

# Which adapter each fixture belongs to; vulture has no adapter, so nothing claims it.
OWNERS = {
    "pip-audit/native.json": "pip-audit",
    "pip-audit/native.mixed.json": "pip-audit",
    "yamllint/native.parsable.txt": "yamllint",
    "yamllint/native.warnings.parsable.txt": "yamllint",
    "codespell/native.txt": "codespell",
    "codespell/native.multi.txt": "codespell",
    "platformio/native.fastled.json": "platformio",
    "pylint/native.requests.json": "pylint",
    "pylint/native.fire.json": "pylint",
    "vulture/native.txt": None,
}


def build(tool: str, raw: str) -> dict:
    adapter = get_adapter(tool)
    rules, results = adapter.convert(raw)
    builder = SarifBuilder(adapter.TOOL_NAME, information_uri=adapter.INFORMATION_URI)
    for rule in rules:
        builder.add_rule(rule)
    builder.add_results(results)
    return builder.build()


@pytest.mark.parametrize(("tool", "fixture", "golden"), CASES)
def test_fixture_converts_to_valid_sarif(tool, fixture, golden):
    log = build(tool, read_fixture(fixture))
    assert_valid(log)
    assert_matches_golden(log, golden)


@pytest.mark.parametrize("fixture", sorted(OWNERS))
@pytest.mark.parametrize("tool", sorted(ADAPTERS))
def test_detect_claims_only_its_own_fixtures(tool, fixture):
    assert get_adapter(tool).detect(read_fixture(fixture)) is (OWNERS[fixture] == tool)


@pytest.mark.parametrize("fixture", sorted(f for f, owner in OWNERS.items() if owner))
def test_detect_tool_names_exactly_one_tool(fixture):
    assert detect_tool(read_fixture(fixture)) == [OWNERS[fixture]]


@pytest.mark.parametrize("tool", sorted(ADAPTERS))
def test_garbage_input_raises(tool):
    with pytest.raises(ValueError):
        get_adapter(tool).convert("this is not any tool's output\n")


@pytest.mark.parametrize("tool", ["yamllint", "codespell"])
def test_empty_text_input_is_a_clean_run(tool):
    assert get_adapter(tool).convert("  \n\n") == ([], [])


def test_pip_audit_empty_input_raises():
    # pip-audit writes JSON even for a clean audit, so an empty file means the audit
    # itself failed. Converting it to zero findings would hide that.
    with pytest.raises(ValueError, match="empty input"):
        pip_audit.convert("  \n\n")


def test_get_adapter_rejects_unknown_tool():
    with pytest.raises(ValueError, match="unknown tool"):
        get_adapter("nosuchtool")


# -- pip-audit ------------------------------------------------------------------


def test_pip_audit_no_vulns_is_an_empty_success():
    raw = '{"dependencies": [{"name": "packaging", "version": "24.2", "vulns": []}], "fixes": []}'
    assert pip_audit.convert(raw) == ([], [])


def test_pip_audit_dedupes_repeated_vuln_id():
    # The mixed fixture lists PYSEC-2026-215 twice for idna; only the first survives.
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.mixed.json"))
    assert [r.id for r in rules] == ["PYSEC-2026-215"]
    assert len(results) == 1
    assert "idna 3.10" in results[0].message


def test_pip_audit_message_carries_the_details():
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.json"))
    first = results[0]
    assert first.message == (
        "jinja2 2.10 is affected by PYSEC-2021-66 (also known as SNYK-PYTHON-JINJA2-1012994, "
        "GHSA-g3rq-g295-4j3m, CVE-2020-28493). Fixed in 2.11.3."
    )
    assert rules[0].help_uri == "https://osv.dev/vulnerability/PYSEC-2021-66"


def test_pip_audit_every_finding_is_an_error_without_a_score():
    rules, results = pip_audit.convert(read_fixture("pip-audit/native.json"))
    assert {r.default_level for r in rules} == {"error"}
    assert all(r.security_severity is None for r in results)


def test_pip_audit_points_at_the_manifest():
    _, results = pip_audit.convert(read_fixture("pip-audit/native.json"), dep_file="reqs/prod.txt")
    assert results[0].location.uri == "reqs/prod.txt"
    assert results[0].location.start_line is None


def test_pip_audit_summary_is_one_sentence():
    rules, _ = pip_audit.convert(read_fixture("pip-audit/native.json"))
    summaries = {r.id: r.short_description for r in rules}
    assert summaries["PYSEC-2019-217"] == "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape."
    assert all(len(s) <= 305 for s in summaries.values())


def test_pip_audit_truncates_an_endless_first_sentence():
    long_description = "word " * 200
    raw = json.dumps(
        {
            "dependencies": [
                {"name": "x", "version": "1.0", "vulns": [{"id": "CVE-1", "description": long_description}]}
            ]
        }
    )
    rules, _ = pip_audit.convert(raw)
    assert len(rules[0].short_description) <= 303
    assert rules[0].short_description.endswith("...")


def test_pip_audit_missing_fix_version_is_said_so():
    raw = '{"dependencies": [{"name": "x", "version": "1.0", "vulns": [{"id": "CVE-1", "description": "Bad."}]}]}'
    _, results = pip_audit.convert(raw)
    assert results[0].message == "x 1.0 is affected by CVE-1. No fixed version is available."


def test_pip_audit_rejects_json_that_is_not_pip_audit():
    with pytest.raises(ValueError, match="dependencies"):
        pip_audit.convert('{"results": []}')


# -- yamllint -------------------------------------------------------------------


def test_yamllint_keeps_line_and_column():
    _, results = yamllint.convert(read_fixture("yamllint/native.parsable.txt"))
    first = results[0]
    assert (first.location.uri, first.location.start_line, first.location.start_column) == (
        "fx/messy.yaml",
        2,
        7,
    )
    assert first.rule_id == "colons"
    assert first.message == "too many spaces after colon"


def test_yamllint_maps_levels():
    _, results = yamllint.convert(read_fixture("yamllint/native.warnings.parsable.txt"))
    assert [r.level for r in results] == ["warning", "warning", "warning", "error"]


def test_yamllint_rule_help_uri():
    rules, _ = yamllint.convert(read_fixture("yamllint/native.warnings.parsable.txt"))
    assert rules[0].help_uri == (
        "https://yamllint.readthedocs.io/en/stable/rules.html#module-yamllint.rules.document-start"
    )


def test_yamllint_message_keeps_its_own_parentheses():
    _, results = yamllint.convert("a.yaml:4:81: [error] line too long (127 > 80 characters) (line-length)")
    assert results[0].rule_id == "line-length"
    assert results[0].message == "line too long (127 > 80 characters)"


def test_yamllint_handles_awkward_paths():
    raw = "\n".join(
        [
            "dir with spaces/a b.yaml:1:1: [error] trailing spaces (trailing-spaces)",
            "odd:name.yaml:2:1: [error] trailing spaces (trailing-spaces)",
            "C:\\repo\\ci.yaml:3:1: [error] trailing spaces (trailing-spaces)",
        ]
    )
    _, results = yamllint.convert(raw)
    assert [r.location.uri for r in results] == [
        "dir with spaces/a b.yaml",
        "odd:name.yaml",
        "C:\\repo\\ci.yaml",
    ]


def test_yamllint_skips_blank_and_unparseable_lines():
    raw = "\n".join(
        [
            "",
            "yamllint 1.35.1",
            "a.yaml:1:1: [warning] missing document start \"---\" (document-start)",
            "   ",
            "not a finding at all",
        ]
    )
    _, results = yamllint.convert(raw)
    assert len(results) == 1


# -- codespell ------------------------------------------------------------------


def test_codespell_message_and_location():
    rules, results = codespell.convert(read_fixture("codespell/native.txt"))
    assert rules[0].id == "recieve"
    assert rules[0].short_description == '"recieve" should be "Receive"'
    assert results[0].rule_id == "recieve"
    assert results[0].message == '"Recieve" is a misspelling of "Receive"'
    assert results[0].location.uri == "fx/typos.py"
    assert results[0].location.start_line == 1
    assert results[0].location.start_column is None


def test_codespell_keeps_every_correction():
    _, results = codespell.convert(read_fixture("codespell/native.multi.txt"))
    messages = [r.message for r in results]
    assert '"procede" is a misspelling of "proceed, precede"' in messages


def test_codespell_keeps_a_trailing_reason():
    _, results = codespell.convert("a.txt:7: ba ==> by, be (disabled due to being a common word)")
    assert results[0].message == '"ba" is a misspelling of "by, be (disabled due to being a common word)"'


def test_codespell_defaults_to_warning():
    rules, _ = codespell.convert(read_fixture("codespell/native.txt"))
    assert {r.default_level for r in rules} == {"warning"}


def test_codespell_one_rule_per_typo_regardless_of_case():
    raw = "\n".join(["a.txt:1: Teh ==> The", "b.txt:2: teh ==> the", "b.txt:3: wich ==> which"])
    rules, results = codespell.convert(raw)
    assert [r.id for r in rules] == ["teh", "wich"]
    assert [r.rule_id for r in results] == ["teh", "teh", "wich"]


def test_codespell_handles_awkward_paths():
    _, results = codespell.convert("dir with spaces/read me.txt:3: teh ==> the")
    assert results[0].location.uri == "dir with spaces/read me.txt"


def test_codespell_skips_blank_and_unparseable_lines():
    raw = "\n".join(["", "WARNING: Binary file skipped", "a.txt:2: teh ==> the", "  "])
    _, results = codespell.convert(raw)
    assert len(results) == 1


# -- platformio -----------------------------------------------------------------


def defect(**overrides) -> dict:
    """One entry of a `pio check --json-output` ``defects`` list."""
    base = {
        "severity": "high",
        "category": "error",
        "message": "Uninitialized variable: total",
        "file": "/build/proj/src/main.c",
        "line": 22,
        "column": 12,
        "callstack": "[/build/proj/src/main.c:22]",
        "id": "uninitvar",
        "cwe": "457",
    }
    return {**base, **overrides}


def pio(*entries: dict) -> str:
    """A `pio check --json-output` array; every entry is a successful run unless it says so."""
    defaults = {"env": "native", "tool": "cppcheck", "succeeded": True, "duration": 2.2, "defects": []}
    return json.dumps([{**defaults, **entry} for entry in entries])


def test_platformio_namespaces_the_rule_id_and_keeps_the_position():
    rules, results = platformio.convert(pio({"defects": [defect()]}))
    assert [r.id for r in rules] == ["cppcheck:uninitvar"]
    assert rules[0].name == "uninitvar"
    assert rules[0].short_description == "Uninitialized variable: total"
    assert rules[0].full_description == "uninitvar, reported by cppcheck via pio check at high severity."
    assert rules[0].default_level == "error"
    first = results[0]
    assert first.rule_id == "cppcheck:uninitvar"
    assert first.message == "Uninitialized variable: total"
    assert (first.location.uri, first.location.start_line, first.location.start_column) == (
        "/build/proj/src/main.c",
        22,
        12,
    )
    assert first.security_severity is None


def test_platformio_maps_severities():
    defects = [
        defect(severity="high", id="uninitvar"),
        defect(severity="medium", id="nullPointer"),
        defect(severity="low", id="unusedVariable"),
    ]
    rules, results = platformio.convert(pio({"defects": defects}))
    assert [r.level for r in results] == ["error", "warning", "note"]
    assert [r.default_level for r in rules] == ["error", "warning", "note"]


def test_platformio_converts_to_valid_sarif():
    log = build("platformio", pio({"defects": [defect(), defect(id="unusedVariable", severity="low", cwe=None)]}))
    assert_valid(log)


def test_platformio_reads_the_json_after_the_install_chatter():
    raw = "\n".join(
        [
            "Tool Manager: Installing platformio/tool-cppcheck @ ~1.21100.0",
            "Downloading  0% 10% 55% 100%",
            "git version 2.43.0",
            "HEAD is now at abc1234 Release 2.13",
            "Tool Manager: tool-cppcheck @ 1.21100.230717 has been installed!",
            pio({"defects": [defect()]}),
        ]
    )
    assert platformio.detect(raw) is True
    _, results = platformio.convert(raw)
    assert [r.rule_id for r in results] == ["cppcheck:uninitvar"]


def test_platformio_failed_check_run_raises():
    raw = pio({"env": "esp32dev", "tool": "clang-tidy", "succeeded": False})
    with pytest.raises(ValueError) as exc:
        platformio.convert(raw)
    assert "esp32dev" in str(exc.value)
    assert "clang-tidy" in str(exc.value)


def test_platformio_fail_on_defect_output_still_converts():
    # `--fail-on-defect` marks a run that worked and found things as not succeeded;
    # the findings are exactly what should reach the upload.
    raw = pio({"succeeded": False, "defects": [defect()]})
    _, results = platformio.convert(raw)
    assert [r.rule_id for r in results] == ["cppcheck:uninitvar"]


@pytest.mark.parametrize("raw", ["[1]", '[{"foo": 1}]', '[{"env": "native"}]'])
def test_platformio_rejects_entries_without_the_check_shape(raw):
    # Skipping malformed entries would turn a bad capture into a clean-looking run.
    with pytest.raises(ValueError):
        platformio.convert(raw)


def test_platformio_dedupes_the_same_defect_across_environments():
    shared = defect()
    other = defect(line=30, message="Array index out of bounds", id="arrayIndexOutOfBounds")
    raw = pio({"env": "uno", "defects": [shared, other]}, {"env": "nanoatmega328", "defects": [shared]})
    rules, results = platformio.convert(raw)
    assert [r.id for r in rules] == ["cppcheck:uninitvar", "cppcheck:arrayIndexOutOfBounds"]
    assert [(r.rule_id, r.location.start_line) for r in results] == [
        ("cppcheck:uninitvar", 22),
        ("cppcheck:arrayIndexOutOfBounds", 30),
    ]


@pytest.mark.parametrize("cwe", ["476", 476, "CWE-476"])
def test_platformio_cwe_reaches_the_help_link_and_properties(cwe):
    rules, results = platformio.convert(pio({"defects": [defect(cwe=cwe)]}))
    assert rules[0].help_uri == "https://cwe.mitre.org/data/definitions/476.html"
    assert results[0].properties == {"cwe": "CWE-476"}


@pytest.mark.parametrize(
    "defect_json",
    [defect(cwe=None), {k: v for k, v in defect().items() if k != "cwe"}, defect(cwe=0), defect(cwe="0")],
)
def test_platformio_without_a_cwe_falls_back_to_the_tool_docs(defect_json):
    # cppcheck writes cwe 0 for checks with no CWE assigned; CWE-0 does not exist.
    rules, results = platformio.convert(pio({"defects": [defect_json]}))
    assert rules[0].help_uri == platformio.INFORMATION_URI
    assert results[0].properties == {}


def test_platformio_clips_oversized_messages():
    # Real cppcheck output can dump its whole preprocessor configuration into the
    # message (the FastLED fixture carries a 12 KB one); GitHub caps rule description
    # text at 1024 characters.
    rules, results = platformio.convert(pio({"defects": [defect(message="x" * 5000)]}))
    assert len(results[0].message) == 1024
    assert results[0].message.endswith("... (truncated)")
    assert len(rules[0].short_description) == 1024


def test_platformio_short_messages_pass_through_unclipped():
    _, results = platformio.convert(pio({"defects": [defect(message="x" * 1024)]}))
    assert results[0].message == "x" * 1024


def test_platformio_drops_unknown_line_and_column():
    # 0 is what PlatformIO writes when the tool named no position, and SARIF is 1-based.
    _, results = platformio.convert(pio({"defects": [defect(file="unknown", line=0, column=0)]}))
    location = results[0].location
    assert (location.uri, location.start_line, location.start_column) == ("unknown", None, None)


def test_platformio_clean_project_has_no_findings():
    assert platformio.convert(pio({"defects": []})) == ([], [])
    assert platformio.convert("[]") == ([], [])
    # An empty array names no tool, so it isn't enough to claim the input.
    assert platformio.detect("[]") is False


def test_platformio_one_rule_per_check_id():
    defects = [defect(), defect(line=40, message="Uninitialized variable: count")]
    rules, results = platformio.convert(pio({"defects": defects}))
    assert [r.id for r in rules] == ["cppcheck:uninitvar"]
    assert rules[0].short_description == "Uninitialized variable: total"
    assert len(results) == 2


def test_platformio_rejects_json_that_is_not_pio_check():
    with pytest.raises(ValueError, match="JSON array"):
        platformio.convert('{"dependencies": []}')


# -- pylint ---------------------------------------------------------------------


def message(**overrides) -> dict:
    """One entry of a `pylint --output-format=json2` ``messages`` list."""
    base = {
        "type": "warning",
        "symbol": "unused-import",
        "message": "Unused import os",
        "messageId": "W0611",
        "confidence": "UNDEFINED",
        "module": "demo",
        "obj": "",
        "line": 1,
        "column": 0,
        "endLine": 1,
        "endColumn": 9,
        "path": "demo.py",
        "absolutePath": "/repo/demo.py",
    }
    return {**base, **overrides}


def pyl(*messages: dict) -> str:
    """A `pylint --output-format=json2` document wrapping ``messages``."""
    counts = {"fatal": 0, "error": 0, "warning": 0, "refactor": 0, "convention": 0, "info": 0}
    for entry in messages:
        counts[entry["type"]] = counts.get(entry["type"], 0) + 1
    statistics = {"messageTypeCount": counts, "modulesLinted": 1, "score": 5.0}
    return json.dumps({"messages": list(messages), "statistics": statistics})


def test_pylint_rule_id_is_the_symbol_and_the_code_is_in_the_description():
    rules, results = pylint.convert(pyl(message()))
    assert [r.id for r in rules] == ["unused-import"]
    # SARIF wants a legible id and an opaque one is no use as a name, so the code lives
    # in the description rather than being put in the slot meant for a readable name.
    assert rules[0].name is None
    assert rules[0].short_description == "Unused import os"
    assert rules[0].full_description == "W0611, reported by pylint in the warning category."
    assert rules[0].default_level == "warning"
    assert results[0].rule_id == "unused-import"
    assert results[0].message == "Unused import os"


def test_pylint_shifts_columns_out_of_zero_based_numbering():
    # pylint counts columns from 0 and SARIF from 1. `x` at 0-based column 4 is SARIF
    # column 5, and the end position moves with it: both formats point one past the end.
    _, results = pylint.convert(pyl(message(line=6, column=4, endLine=6, endColumn=5)))
    location = results[0].location
    assert (location.start_line, location.start_column) == (6, 5)
    assert (location.end_line, location.end_column) == (6, 6)


def test_pylint_keeps_a_column_that_starts_the_line():
    # Column 0 is the common case for whole-line messages, and must not be dropped.
    _, results = pylint.convert(pyl(message(column=0)))
    assert results[0].location.start_column == 1


def test_pylint_maps_every_message_type():
    types = ["fatal", "error", "warning", "refactor", "convention", "info"]
    raw = pyl(*(message(type=t, symbol=f"s-{t}") for t in types))
    rules, results = pylint.convert(raw)
    assert [r.level for r in results] == ["error", "error", "warning", "note", "note", "note"]
    assert [r.default_level for r in rules] == ["error", "error", "warning", "note", "note", "note"]


@pytest.mark.parametrize(
    ("message_type", "symbol", "expected"),
    [
        ("convention", "line-too-long", "convention/line-too-long.html"),
        ("error", "import-error", "error/import-error.html"),
        ("fatal", "fatal", "fatal/fatal.html"),
        # The docs spell the info category out in full.
        ("info", "locally-disabled", "information/locally-disabled.html"),
    ],
)
def test_pylint_help_uri_points_at_the_message_docs(message_type, symbol, expected):
    rules, _ = pylint.convert(pyl(message(type=message_type, symbol=symbol)))
    assert rules[0].help_uri == "https://pylint.readthedocs.io/en/stable/user_guide/messages/" + expected


def test_pylint_plugin_message_keeps_its_category():
    # A plugin registers under one of pylint's own letters (W5101 here), so its findings
    # get the right level. Only its symbol is unknown, and that page does not exist.
    rules, results = pylint.convert(pyl(message(type="warning", symbol="house-style", messageId="W5101")))
    assert results[0].level == "warning"
    assert rules[0].help_uri.endswith("/warning/house-style.html")


def test_pylint_unrecognised_type_falls_back_to_the_project_docs():
    # Unreachable from pylint itself, which rejects a message id outside its six
    # categories. It covers a damaged document, and a category a later release may add.
    raw = json.dumps({"messages": [message(type="quality")], "statistics": {"messageTypeCount": {}}})
    rules, _ = pylint.convert(raw)
    assert rules[0].help_uri == pylint.INFORMATION_URI
    assert rules[0].default_level == "warning"


def test_pylint_rule_title_is_the_first_line_only():
    # duplicate-code puts the offending source in the message. The whole block as an
    # alert title makes the list unreadable, so only the first line becomes the title.
    body = "Similar lines in 2 files\n==a:[1:5]\n==b:[9:13]\n    stream=stream,\n    timeout=timeout,"
    rules, results = pylint.convert(pyl(message(symbol="duplicate-code", messageId="R0801", message=body)))
    assert rules[0].short_description == "Similar lines in 2 files"
    # The detail is worth keeping, just not in the title.
    assert results[0].message == body


def test_pylint_clips_an_oversized_message():
    # fixme quotes the comment it found, so one long TODO runs past GitHub's 1024-character
    # cap on rule description text. A real capture of this reached 2290 characters.
    long_todo = "TODO: " + "refactor this whole subsystem because " * 60
    rules, results = pylint.convert(pyl(message(symbol="fixme", messageId="W0511", message=long_todo)))
    assert len(rules[0].short_description) == 1024
    assert rules[0].short_description.endswith("... (truncated)")
    assert len(results[0].message) == 1024


def test_pylint_title_is_clipped_on_its_own():
    # Clipping the whole message first would eat into a first line that fits by itself.
    body = "A" * 1010 + "\n" + "B" * 200
    rules, results = pylint.convert(pyl(message(message=body)))
    assert rules[0].short_description == "A" * 1010
    assert len(results[0].message) == 1024


def test_pylint_statistics_without_real_counts_is_not_pylint():
    raw = '{"messages": [], "statistics": {"messageTypeCount": null}}'
    assert pylint.detect(raw) is False
    with pytest.raises(ValueError, match="statistics"):
        pylint.convert(raw)


def test_pylint_malformed_message_raises():
    # Skipping the bad entry would upload a clean-looking run built from a damaged capture.
    raw = json.dumps({"messages": [None], "statistics": {"messageTypeCount": {"warning": 1}}})
    with pytest.raises(ValueError, match="not an object"):
        pylint.convert(raw)


def test_pylint_rejects_json_that_is_not_pylint():
    # detect() refuses it, but naming the tool explicitly bypasses detection, and a
    # foreign document converting to zero findings would look like a clean run.
    with pytest.raises(ValueError, match="statistics"):
        pylint.convert('{"messages": [], "tool": "something-else"}')


def test_pylint_missing_end_position_is_left_out():
    _, results = pylint.convert(pyl(message(endLine=None, endColumn=None)))
    location = results[0].location
    assert (location.start_line, location.start_column) == (1, 1)
    assert (location.end_line, location.end_column) == (None, None)


def test_pylint_one_rule_per_symbol():
    raw = pyl(message(), message(line=2, message="Unused import sys"), message(symbol="unused-variable"))
    rules, results = pylint.convert(raw)
    assert [r.id for r in rules] == ["unused-import", "unused-variable"]
    assert rules[0].short_description == "Unused import os"
    assert len(results) == 3


def test_pylint_clean_run_is_an_empty_success():
    assert pylint.convert(pyl()) == ([], [])


def test_pylint_empty_input_raises():
    # pylint writes a JSON document even when it finds nothing, so an empty file means
    # the run itself failed. Converting it to zero findings would hide that.
    with pytest.raises(ValueError, match="empty input"):
        pylint.convert("  \n\n")


def test_pylint_rejects_the_older_json_format():
    # `--output-format=json` writes a bare array with no statistics block, so nothing in
    # it says pylint, and it spells the code 'message-id'. Positions it does carry.
    raw = json.dumps([{"type": "warning", "symbol": "unused-import", "path": "demo.py", "line": 1}])
    assert pylint.detect(raw) is False
    with pytest.raises(ValueError, match="messages"):
        pylint.convert(raw)


def test_pylint_real_capture_keeps_position_and_level():
    _, results = pylint.convert(read_fixture("pylint/native.requests.json"))
    first = results[0]
    assert first.rule_id == "line-too-long"
    assert first.message == "Line too long (137/100)"
    assert (first.location.uri, first.location.start_line, first.location.start_column) == (
        "src/requests/sessions.py",
        96,
        1,
    )
    assert first.level == "note"


def test_pylint_real_capture_carries_the_information_category():
    rules, results = pylint.convert(read_fixture("pylint/native.fire.json"))
    levels = {r.rule_id: r.level for r in results}
    assert levels["locally-disabled"] == "note"
    assert levels["import-error"] == "error"
    help_uris = {r.id: r.help_uri for r in rules}
    assert help_uris["locally-disabled"].endswith("/information/locally-disabled.html")
