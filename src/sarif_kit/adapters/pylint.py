"""pylint adapter, for the output of ``pylint --output-format=json2``.

json2 is the format to convert from, not the older ``json``, which pylint's own help calls
the old one. Both carry the same positions, down to the end line and column; what json2
adds is the ``statistics`` block, which is the only thing that identifies this output as
pylint's rather than any other JSON, and the ``messageId`` spelling of the code that the
old format writes as ``message-id``. The old format is a bare array with neither, so it is
refused rather than half-read.

pylint counts columns from zero and SARIF counts from one, so every column moves up by
one; the end column needs the same shift, since both formats point one past the last
character.

A message carries no description of the check that produced it, only the rendered text of
this one occurrence, so the first message a symbol produces stands in as the alert title.
Only the first line of it: ``duplicate-code`` puts the offending source into its message,
and a title running to eight lines of Python makes the alert list unreadable. The full text
stays on the result, clipped to 1024 characters, GitHub's cap on description text, which
``fixme`` passes on its own by quoting the entire comment it found.

Rule ids are pylint's symbols (``unused-import``) rather than its codes (``W0611``). The
symbol is what a reader disables in a comment, what the documentation URL is keyed on, and
what SARIF wants in an id a person will read; the code stays in the rule description.
Every message type maps onto a documentation page, which becomes the rule's help link.
"""

from __future__ import annotations

import json

from ..models import Location, Result, Rule
from ..severity import level_from_severity

TOOL_NAME = "pylint"
INFORMATION_URI = "https://pylint.readthedocs.io/"

_DOCS_URI = "https://pylint.readthedocs.io/en/stable/user_guide/messages/"

#: Message type to documentation directory. Every type is its own directory except
#: ``info``, which the docs spell out as ``information``. pylint enforces these six:
#: a checker registering a message under any other letter fails to load, so a plugin
#: cannot introduce a seventh.
_DOC_DIRS = {
    "fatal": "fatal",
    "error": "error",
    "warning": "warning",
    "refactor": "refactor",
    "convention": "convention",
    "info": "information",
}

#: GitHub's limit on rule description text, applied to messages too.
_MAX_TEXT = 1024
_CLIP_MARK = "... (truncated)"


def detect(raw: str) -> bool:
    """Whether ``raw`` looks like `pylint --output-format=json2`."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return False
    return _messages(payload) is not None


def convert(raw: str) -> tuple[list[Rule], list[Result]]:
    """Parse `pylint --output-format=json2` into rules and results.

    A run where every module scores clean is a legitimate empty result. Empty input is
    not: pylint writes a JSON document even when it has nothing to report, so an empty
    file means the run itself failed, and converting it to zero findings would hide that.
    """
    if not raw.strip():
        raise ValueError("empty input; pylint writes JSON even for a clean run, so the run itself probably failed")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"input is not valid JSON: {exc}") from exc
    messages = _messages(payload)
    if messages is None:
        raise ValueError(
            "input has no 'messages' list alongside 'statistics'; expected output of "
            "`pylint --output-format=json2` (the older `json` format writes a bare array, "
            "which names no tool and spells the code 'message-id')"
        )

    rules: list[Rule] = []
    results: list[Result] = []
    rule_ids: set[str] = set()

    for message in messages:
        # Skipping a malformed entry would turn a damaged capture into a clean run.
        if not isinstance(message, dict):
            raise ValueError(f"message is not an object: {message!r}")
        symbol = str(message.get("symbol") or "unknown")
        message_type = str(message.get("type") or "")
        message_id = str(message.get("messageId") or "")
        text = str(message.get("message", ""))
        level = level_from_severity(message_type)
        if symbol not in rule_ids:
            rule_ids.add(symbol)
            rules.append(
                Rule(
                    id=symbol,
                    # Split before clipping, so a long tail can't eat into a first line
                    # that would have fitted on its own.
                    short_description=_clip(text.partition("\n")[0]),
                    full_description=_description(message_id, message_type),
                    help_uri=_help_uri(message_type, symbol),
                    default_level=level,
                )
            )
        results.append(
            Result(
                rule_id=symbol,
                message=_clip(text),
                location=Location(
                    uri=str(message.get("path") or "unknown"),
                    start_line=_line(message.get("line")),
                    start_column=_column(message.get("column")),
                    end_line=_line(message.get("endLine")),
                    end_column=_column(message.get("endColumn")),
                ),
                level=level,
            )
        )

    return rules, results


def _messages(payload: object) -> list | None:
    """The ``messages`` of a json2 document, or ``None`` if ``payload`` isn't one.

    ``statistics`` is what tells json2 apart from any other JSON carrying a ``messages``
    list, so detect and convert share this check rather than keeping one each. Were they to
    disagree, ``--tool pylint`` on a foreign document would convert to a clean, empty run
    rather than failing, since naming the tool skips detection.
    """
    if not isinstance(payload, dict):
        return None
    messages = payload.get("messages")
    statistics = payload.get("statistics")
    if not isinstance(messages, list) or not isinstance(statistics, dict):
        return None
    # The counts themselves, not just the key: a null there would pass a bare `in` test
    # and let the document through as a clean run.
    return messages if isinstance(statistics.get("messageTypeCount"), dict) else None


def _description(message_id: str, message_type: str) -> str:
    """One line naming the code and the category behind a rule."""
    return f"{message_id}, reported by pylint in the {message_type} category."


def _clip(text: str) -> str:
    """``text``, cut to GitHub's 1024-character description limit."""
    if len(text) <= _MAX_TEXT:
        return text
    return text[: _MAX_TEXT - len(_CLIP_MARK)] + _CLIP_MARK


def _help_uri(message_type: str, symbol: str) -> str:
    """The documentation page for a message, or the project docs if the type is unknown.

    pylint only issues the six types above, so the fallback is for a damaged document or
    a category some later release adds, not for anything current pylint writes.
    """
    directory = _DOC_DIRS.get(message_type)
    if not directory:
        return INFORMATION_URI
    return f"{_DOCS_URI}{directory}/{symbol}.html"


def _line(value: object) -> int | None:
    """A 1-based line number, or ``None`` where pylint reported no position."""
    if not isinstance(value, int):
        return None
    return value if value >= 1 else None


def _column(value: object) -> int | None:
    """A pylint column shifted into SARIF's 1-based numbering."""
    if not isinstance(value, int):
        return None
    return value + 1 if value >= 0 else None
