"""Shared helpers for tests/ops: contract.yml values, the Kuma field expressions and host tool imports."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import re
from pathlib import Path
from types import ModuleType

import yaml


def load_contract(repo: Path) -> dict:
    return yaml.safe_load((repo / "contract/contract.yml").read_text(encoding="utf-8"))


def service_list_expression(services: list[str]) -> str:
    alt = "|".join(re.escape(s) for s in services)
    return f"^(?:(?:{alt})(?:,(?:{alt}))*)?$"


def kuma_expressions(repo: Path) -> dict[str, str]:
    """Key -> expression the Kuma payload values must match.

    The expressions are those declared in legatto-health (KUMA_FIELDS); `ctbad`
    is rebuilt from contract.yml legatto_compose_services, so a service list in
    the tool that drifts from the contract fails the tests.
    """
    health = load_tool(repo / "sbin/legatto-health")
    result = dict(health.KUMA_FIELDS)
    result["ctbad"] = service_list_expression(load_contract(repo)["legatto_compose_services"])
    return result


def load_tool(path: Path) -> ModuleType:
    """Import a host tool (script without .py) as a module."""
    loader = importlib.machinery.SourceFileLoader(path.name.replace("-", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
