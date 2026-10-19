"""Deterministic passive signal plugins for LogicHunter Lite.

Built-ins inspect imported evidence only; they never send network requests.
External Python plugins are opt-in because importing them executes local code.
Set LH_ENABLE_EXTERNAL_PLUGINS=1 only when the plugins directory is trusted.
"""
from __future__ import annotations
import importlib.util
import os
import re
from pathlib import Path
from typing import Any, Callable

Detector = Callable[[dict[str, Any]], dict[str, Any] | None]
_REGISTRY: dict[str, Detector] = {}
_EXTERNAL_LOADED: set[str] = set()


def register(name: str, detector: Detector, *, replace: bool = False) -> None:
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", name):
        raise ValueError("plugin name must be a short lowercase identifier")
    if not callable(detector):
        raise TypeError("detector must be callable")
    if name in _REGISTRY and not replace:
        if _REGISTRY[name] is detector:
            return
        raise ValueError(f"duplicate signal plugin: {name}")
    _REGISTRY[name] = detector


def _signal(name: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {"signal": name, "details": detail, "source": "passive_plugin"}


def ssrf_indicator(record: dict[str, Any]) -> dict[str, Any] | None:
    params = record.get("query_params", []) + record.get("body_params", [])
    url_names = {"url", "uri", "callback", "webhook", "redirect_url", "image_url", "endpoint"}
    for item in params:
        key = str(item.get("key", "")).lower()
        value = str(item.get("value", ""))
        if key in url_names and re.match(r"^https?://", value, re.I):
            return _signal("ssrf_input_candidate", {"parameter": key, "value_is_url": True})
    return None


def xml_input_indicator(record: dict[str, Any]) -> dict[str, Any] | None:
    headers = {str(k).lower(): str(v) for k, v in record.get("request_headers", {}).items()}
    content_type = headers.get("content-type", "").lower()
    body = str(record.get("request_body_preview", "")).lstrip().lower()
    if "xml" in content_type or body.startswith("<?xml") or body.startswith("<root"):
        return _signal("xml_input_candidate", {"content_type_xml": "xml" in content_type,
                                               "body_looks_xml": body.startswith(("<?xml", "<root"))})
    return None


def open_redirect_indicator(record: dict[str, Any]) -> dict[str, Any] | None:
    status = record.get("status")
    if not isinstance(status, int) or status not in range(300, 400):
        return None
    params = record.get("query_params", []) + record.get("body_params", [])
    names = {str(p.get("key", "")).lower() for p in params}
    headers = {str(k).lower(): str(v) for k, v in record.get("response_headers", {}).items()}
    location = headers.get("location", "")
    if names.intersection({"next", "url", "return", "return_url", "redirect", "redirect_uri", "continue"}) and location:
        # Candidate only: this intentionally does not claim that the redirect is exploitable.
        return _signal("redirect_behavior_candidate", {"status": status, "location_present": True})
    return None


register("ssrf_input", ssrf_indicator)
register("xml_input", xml_input_indicator)
register("redirect_behavior", open_redirect_indicator)


def load_external_plugins(directory: Path | None = None) -> list[str]:
    """Load trusted local plugins once; disabled by default, failures are isolated."""
    if os.environ.get("LH_ENABLE_EXTERNAL_PLUGINS", "0").strip().lower() not in {"1", "true", "yes"}:
        return []
    root = directory or (Path(__file__).resolve().parent / "plugins")
    loaded: list[str] = []
    if not root.is_dir():
        return loaded
    for path in sorted(root.glob("*.py")):
        resolved = str(path.resolve())
        if path.name.startswith("_") or resolved in _EXTERNAL_LOADED:
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"lh_external_{path.stem}", path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            # Plugins export register_plugins(register_fn); no automatic module execution without opt-in.
            spec.loader.exec_module(module)
            installer = getattr(module, "register_plugins", None)
            if not callable(installer):
                continue
            installer(register)
            _EXTERNAL_LOADED.add(resolved)
            loaded.append(path.stem)
        except Exception as exc:
            print(f"[plugin] skipped {path.name}: {type(exc).__name__}")
    return loaded


def run_plugins(record: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for name, detector in list(_REGISTRY.items()):
        try:
            result = detector(dict(record))
            if result is None:
                continue
            if not isinstance(result, dict) or not isinstance(result.get("signal"), str):
                continue
            # Bound and sanitize the plugin contract; no raw request values in plugin output.
            details = result.get("details", {})
            if not isinstance(details, dict):
                details = {"note": "invalid details omitted"}
            safe_details = {}
            for key, value in list(details.items())[:12]:
                if isinstance(key, str) and isinstance(value, (str, int, float, bool, type(None))):
                    safe_details[key[:64]] = value if not isinstance(value, str) else value[:160]
            results.append({"signal": result["signal"][:80], "details": safe_details,
                            "source": "passive_plugin", "plugin": name})
        except Exception as exc:
            print(f"[plugin] detector {name} failed: {type(exc).__name__}")
    return results


def list_plugins() -> list[str]:
    return sorted(_REGISTRY)


def _reset_for_tests() -> None:
    """Test helper: restore only built-ins and clear external load cache."""
    global _REGISTRY, _EXTERNAL_LOADED
    _REGISTRY = {"ssrf_input": ssrf_indicator, "xml_input": xml_input_indicator,
                 "redirect_behavior": open_redirect_indicator}
    _EXTERNAL_LOADED = set()
