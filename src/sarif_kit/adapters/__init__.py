"""Adapter registry.

One module per supported tool. Each of them exposes ``TOOL_NAME``, ``INFORMATION_URI``,
``detect(raw)`` and ``convert(raw)``, and nothing else is part of the contract. Adapters
only parse: they return :class:`~sarif_kit.models.Rule` and
:class:`~sarif_kit.models.Result` objects and leave the SARIF writing to
:class:`~sarif_kit.builder.SarifBuilder`.
"""

from __future__ import annotations

from types import ModuleType

from . import codespell, pip_audit, platformio, pylint, yamllint

#: Tool name to adapter module. The keys are what the CLI's ``--tool`` accepts.
ADAPTERS: dict[str, ModuleType] = {
    pip_audit.TOOL_NAME: pip_audit,
    yamllint.TOOL_NAME: yamllint,
    codespell.TOOL_NAME: codespell,
    platformio.TOOL_NAME: platformio,
    pylint.TOOL_NAME: pylint,
}


def get_adapter(name: str) -> ModuleType:
    """Return the adapter module for a tool name."""
    try:
        return ADAPTERS[name]
    except KeyError:
        known = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"unknown tool {name!r}; supported tools are {known}") from None


def detect_tool(raw: str) -> list[str]:
    """Names of every registered adapter whose ``detect`` claims ``raw``, sorted."""
    return [name for name in sorted(ADAPTERS) if ADAPTERS[name].detect(raw)]


__all__ = ["ADAPTERS", "detect_tool", "get_adapter"]
