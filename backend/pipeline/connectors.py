"""Pluggable live threat-intelligence connectors.

Vulnify's core analytics run on *offline* feeds (NVD / KEV / EPSS). This module
adds an optional layer that streams **live** intelligence from external sources
onto the dashboard. It ships with:

  * ``alienvault_otx`` - AlienVault OTX (Open Threat Exchange) pulse feed.
  * ``custom_http``    - any JSON HTTP endpoint, mapped with a few hints.
  * ``demo``           - built-in synthetic OTX-style data so the panel works
                         offline / without an API key (great for a one-click demo).

Every connector normalises its source into the same ``LiveEvent`` / stats shape
so the frontend renders them generically. Only the Python standard library is
used for HTTP (``urllib``) so there are no extra dependencies to install.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import CONNECTORS_FILE

OTX_BASE = "https://otx.alienvault.com/api/v1"
HTTP_TIMEOUT = 12
CACHE_TTL = 30  # seconds; avoid hammering remote APIs on every poll
USER_AGENT = "Vulnify-Connector/1.0 (+https://github.com/sami9211/vulnify)"

CONNECTOR_TYPES = {
    "alienvault_otx": {
        "label": "AlienVault OTX",
        "description": "Open Threat Exchange community pulses and indicators.",
        "fields": [
            {"key": "api_key", "label": "OTX API key", "type": "secret", "required": True},
            {
                "key": "endpoint",
                "label": "Feed",
                "type": "select",
                "options": ["activity", "subscribed"],
                "default": "activity",
            },
            {"key": "limit", "label": "Pulses to fetch", "type": "number", "default": 20},
        ],
    },
    "custom_http": {
        "label": "Custom HTTP (JSON)",
        "description": "Any JSON endpoint. Vulnify auto-detects the item list or "
        "you can point it at one with a dotted path.",
        "fields": [
            {"key": "url", "label": "Feed URL", "type": "text", "required": True},
            {"key": "items_path", "label": "Items path (optional, e.g. data.results)", "type": "text"},
            {"key": "title_field", "label": "Title field (optional)", "type": "text"},
            {"key": "auth_header", "label": "Authorization header value (optional)", "type": "secret"},
        ],
    },
    "demo": {
        "label": "Demo feed (offline)",
        "description": "Synthetic OTX-style pulses. No network or API key required.",
        "fields": [],
    },
}


class ConnectorError(Exception):
    """Raised when a connector cannot fetch or parse live data."""


@dataclass
class LiveEvent:
    id: str
    title: str
    subtitle: str = ""
    description: str = ""
    timestamp: str | None = None
    tags: list[str] = field(default_factory=list)
    metrics: list[dict[str, Any]] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    url: str | None = None
    severity: str | None = None
    source: str = ""


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #
def _http_get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        raise ConnectorError(f"HTTP {e.code} from source. {detail}".strip()) from e
    except urllib.error.URLError as e:
        raise ConnectorError(f"Could not reach source: {e.reason}") from e
    except Exception as e:  # noqa: BLE001 - surface any transport error cleanly
        raise ConnectorError(f"Request failed: {e}") from e

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConnectorError("Source did not return valid JSON.") from e


def _dig(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        part = part.strip()
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# --------------------------------------------------------------------------- #
# AlienVault OTX
# --------------------------------------------------------------------------- #
def _otx_pulse_to_event(p: dict) -> LiveEvent:
    pulse_id = str(p.get("id") or p.get("pulse_id") or uuid.uuid4())
    indicators = p.get("indicators") or []
    ind_count = p.get("indicator_count")
    if ind_count is None:
        ind_count = len(indicators)
    malware = [m.get("display_name") or m.get("id") for m in (p.get("malware_families") or []) if m]
    countries = [c for c in (p.get("targeted_countries") or []) if c]
    tags = [t for t in (p.get("tags") or []) if t][:8]
    adversary = p.get("adversary") or ""

    metrics = [{"label": "Indicators", "value": ind_count}]
    if malware:
        metrics.append({"label": "Malware", "value": ", ".join(str(m) for m in malware[:3])})
    if adversary:
        metrics.append({"label": "Adversary", "value": adversary})
    tlp = p.get("TLP") or p.get("tlp")
    if tlp:
        metrics.append({"label": "TLP", "value": str(tlp).upper()})

    return LiveEvent(
        id=pulse_id,
        title=p.get("name") or "Untitled pulse",
        subtitle=(f"by {p.get('author_name')}" if p.get("author_name") else "AlienVault OTX"),
        description=(p.get("description") or "").strip()[:280],
        timestamp=p.get("modified") or p.get("created"),
        tags=tags,
        metrics=metrics,
        countries=countries,
        url=f"https://otx.alienvault.com/pulse/{pulse_id}",
        source="AlienVault OTX",
    )


def _fetch_otx(cfg: dict) -> list[LiveEvent]:
    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        raise ConnectorError("An OTX API key is required. Add one in the connector settings.")
    endpoint = cfg.get("endpoint") or "activity"
    if endpoint not in ("activity", "subscribed"):
        endpoint = "activity"
    try:
        limit = max(1, min(50, int(cfg.get("limit") or 20)))
    except (TypeError, ValueError):
        limit = 20

    url = f"{OTX_BASE}/pulses/{endpoint}?limit={limit}&page=1"
    data = _http_get_json(url, headers={"X-OTX-API-KEY": api_key})
    pulses = data.get("results") if isinstance(data, dict) else data
    if not isinstance(pulses, list):
        raise ConnectorError("Unexpected OTX response shape.")
    return [_otx_pulse_to_event(p) for p in pulses if isinstance(p, dict)]


# --------------------------------------------------------------------------- #
# Custom HTTP (generic JSON)
# --------------------------------------------------------------------------- #
_TITLE_KEYS = ("name", "title", "summary", "headline", "id", "cve", "cveID")
_TIME_KEYS = ("modified", "created", "published", "date", "timestamp", "dateAdded", "updated")
_DESC_KEYS = ("description", "shortDescription", "details", "summary", "body", "text")
_LIST_KEYS = ("results", "data", "items", "pulses", "vulnerabilities", "entries", "records", "objects")


def _coerce_items(payload: Any, items_path: str | None) -> list[Any]:
    if items_path:
        found = _dig(payload, items_path)
        if isinstance(found, list):
            return found
        raise ConnectorError(f"No list found at path '{items_path}'.")
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in _LIST_KEYS:
            if isinstance(payload.get(key), list):
                return payload[key]
        # fall back to the first list-valued field
        for value in payload.values():
            if isinstance(value, list):
                return value
    raise ConnectorError("Could not locate a list of items in the response. "
                         "Set an 'Items path' to point at one.")


def _first_str(item: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = item.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip():
            return str(v)
    return ""


def _custom_item_to_event(item: Any, title_field: str | None, idx: int) -> LiveEvent:
    if not isinstance(item, dict):
        return LiveEvent(id=str(idx), title=str(item)[:120], source="Custom feed")

    title = ""
    if title_field:
        title = _first_str(item, (title_field,))
    if not title:
        title = _first_str(item, _TITLE_KEYS) or f"Item {idx + 1}"

    tags = item.get("tags") or item.get("labels") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    tags = [str(t) for t in tags][:8]

    # surface a couple of short scalar fields as metrics
    metrics: list[dict[str, Any]] = []
    for k, v in item.items():
        if k in _DESC_KEYS or k in _TITLE_KEYS:
            continue
        if isinstance(v, (int, float)) or (isinstance(v, str) and 0 < len(v) <= 40):
            metrics.append({"label": k, "value": v})
        if len(metrics) >= 4:
            break

    url = None
    for k in ("url", "link", "reference", "permalink"):
        if isinstance(item.get(k), str) and item[k].startswith("http"):
            url = item[k]
            break

    return LiveEvent(
        id=str(item.get("id") or item.get("cve") or item.get("cveID") or idx),
        title=title[:160],
        subtitle="Custom feed",
        description=_first_str(item, _DESC_KEYS)[:280],
        timestamp=_first_str(item, _TIME_KEYS) or None,
        tags=tags,
        metrics=metrics,
        url=url,
        source="Custom feed",
    )


def _fetch_custom(cfg: dict) -> list[LiveEvent]:
    url = (cfg.get("url") or "").strip()
    if not url:
        raise ConnectorError("A feed URL is required.")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ConnectorError("Feed URL must start with http:// or https://")

    headers: dict[str, str] = {"Accept": "application/json"}
    if cfg.get("auth_header"):
        headers["Authorization"] = str(cfg["auth_header"])

    payload = _http_get_json(url, headers=headers)
    items = _coerce_items(payload, cfg.get("items_path"))
    title_field = cfg.get("title_field") or None
    return [_custom_item_to_event(it, title_field, i) for i, it in enumerate(items[:40])]


# --------------------------------------------------------------------------- #
# Demo (synthetic, offline)
# --------------------------------------------------------------------------- #
_DEMO_PULSES = [
    ("APT29 spear-phishing infrastructure update", "Cozy Bear", ["apt29", "phishing", "c2"],
     ["United States", "United Kingdom", "Germany"], ["CobaltStrike"], 42),
    ("Emerging ransomware loader targeting healthcare", "TrendMicro Research", ["ransomware", "healthcare", "loader"],
     ["United States", "Canada"], ["LockBit"], 88),
    ("Exploitation of edge VPN appliances in the wild", "OTX Community", ["exploit", "vpn", "ivanti"],
     ["United States", "Australia", "Japan"], [], 27),
    ("Mirai variant scanning IoT routers", "Honeypot Network", ["mirai", "iot", "botnet"],
     ["China", "Brazil", "India"], ["Mirai"], 150),
    ("Credential-stealer campaign via fake updates", "AlienVault Labs", ["stealer", "malvertising"],
     ["United States", "France"], ["RedLine"], 63),
    ("Supply-chain compromise of npm packages", "Open Source Watch", ["supply-chain", "npm", "javascript"],
     ["Global"], [], 19),
    ("SSRF exploitation against cloud metadata", "Cloud SOC", ["ssrf", "cloud", "aws"],
     ["United States"], [], 12),
    ("Phishing kit impersonating finance portals", "Anti-Phishing WG", ["phishing", "finance"],
     ["United Kingdom", "Germany", "Netherlands"], [], 35),
    ("Zero-day chatter for popular web framework", "Threat Intel Pool", ["0day", "web", "rce"],
     ["United States", "South Korea"], [], 8),
    ("Lazarus crypto-theft toolkit indicators", "DPRK Tracker", ["lazarus", "cryptocurrency", "apt"],
     ["South Korea", "United States", "Japan"], ["AppleJeus"], 54),
    ("Commodity infostealer targeting browsers", "Malware Bazaar", ["stealer", "browser"],
     ["Brazil", "India", "Russia"], ["Vidar"], 71),
    ("ICS/SCADA reconnaissance from new infrastructure", "ICS-CERT Watch", ["ics", "scada", "manufacturing"],
     ["Germany", "United States"], [], 16),
]


def _fetch_demo(cfg: dict | None = None) -> list[LiveEvent]:
    now = datetime.now(timezone.utc)
    events: list[LiveEvent] = []
    for i, (name, author, tags, countries, malware, ind) in enumerate(_DEMO_PULSES):
        ts = (now - timedelta(minutes=i * 37 + (now.minute % 17))).isoformat()
        metrics = [{"label": "Indicators", "value": ind}]
        if malware:
            metrics.append({"label": "Malware", "value": ", ".join(malware)})
        metrics.append({"label": "TLP", "value": "GREEN"})
        events.append(
            LiveEvent(
                id=f"demo-{i}",
                title=name,
                subtitle=f"by {author}",
                description="[SAMPLE] Synthetic OTX-style pulse for the Vulnify demo. "
                "Connect a real AlienVault OTX key to stream live community intelligence.",
                timestamp=ts,
                tags=tags,
                metrics=metrics,
                countries=countries,
                url="https://otx.alienvault.com/",
                source="Demo feed",
            )
        )
    return events


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def _summarise(events: list[LiveEvent]) -> dict[str, Any]:
    from collections import Counter

    tags: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    indicators = 0
    for e in events:
        tags.update(t for t in e.tags if t)
        countries.update(c for c in e.countries if c)
        for m in e.metrics:
            if str(m.get("label", "")).lower().startswith("indicator"):
                try:
                    indicators += int(m.get("value") or 0)
                except (TypeError, ValueError):
                    pass
    return {
        "total_events": len(events),
        "total_indicators": indicators,
        "top_tags": [{"tag": t, "count": c} for t, c in tags.most_common(12)],
        "top_countries": [{"country": c, "count": n} for c, n in countries.most_common(10)],
    }


_FETCHERS = {
    "alienvault_otx": _fetch_otx,
    "custom_http": _fetch_custom,
    "demo": _fetch_demo,
}


# --------------------------------------------------------------------------- #
# Registry / persistence
# --------------------------------------------------------------------------- #
class ConnectorRegistry:
    """Loads, saves and runs user-configured connectors (with a small cache)."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict]] = {}

    # ---- persistence ----
    def _load_raw(self) -> list[dict]:
        if not CONNECTORS_FILE.exists():
            return []
        try:
            data = json.loads(CONNECTORS_FILE.read_text(encoding="utf-8"))
            return data.get("connectors", []) if isinstance(data, dict) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _save_raw(self, connectors: list[dict]) -> None:
        CONNECTORS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONNECTORS_FILE.write_text(
            json.dumps({"connectors": connectors}, indent=2), encoding="utf-8"
        )

    def all_configs(self) -> list[dict]:
        """User connectors plus the always-present built-in demo connector."""
        configs = self._load_raw()
        if not any(c.get("type") == "demo" for c in configs):
            configs = [
                {"id": "demo", "type": "demo", "name": "Demo feed (offline)", "enabled": True}
            ] + configs
        return configs

    def get(self, connector_id: str) -> dict | None:
        return next((c for c in self.all_configs() if c.get("id") == connector_id), None)

    # ---- mutation ----
    def upsert(self, payload: dict) -> dict:
        ctype = payload.get("type")
        if ctype not in CONNECTOR_TYPES:
            raise ConnectorError(f"Unknown connector type: {ctype}")
        connectors = self._load_raw()
        cid = payload.get("id")
        existing = next((c for c in connectors if c.get("id") == cid), None) if cid else None

        record = existing or {"id": payload.get("id") or f"{ctype}-{uuid.uuid4().hex[:8]}"}
        record["type"] = ctype
        record["name"] = payload.get("name") or CONNECTOR_TYPES[ctype]["label"]
        record["enabled"] = bool(payload.get("enabled", True))
        # copy known config fields; preserve an existing secret if a blank is sent
        for fielddef in CONNECTOR_TYPES[ctype]["fields"]:
            key = fielddef["key"]
            if key in payload and payload[key] not in (None, ""):
                record[key] = payload[key]
            elif fielddef.get("type") == "secret" and key not in record:
                record[key] = ""
            elif key not in record and "default" in fielddef:
                record[key] = fielddef["default"]

        if existing is None:
            connectors.append(record)
        self._save_raw(connectors)
        self._cache.pop(record["id"], None)
        return self._public(record)

    def delete(self, connector_id: str) -> bool:
        connectors = self._load_raw()
        remaining = [c for c in connectors if c.get("id") != connector_id]
        if len(remaining) == len(connectors):
            return False
        self._save_raw(remaining)
        self._cache.pop(connector_id, None)
        return True

    # ---- presentation ----
    @staticmethod
    def _public(cfg: dict) -> dict:
        """Strip/mask secrets before returning a config to the client."""
        ctype = cfg.get("type")
        out = {
            "id": cfg.get("id"),
            "type": ctype,
            "name": cfg.get("name"),
            "enabled": cfg.get("enabled", True),
            "label": CONNECTOR_TYPES.get(ctype, {}).get("label", ctype),
        }
        for fielddef in CONNECTOR_TYPES.get(ctype, {}).get("fields", []):
            key = fielddef["key"]
            val = cfg.get(key)
            if fielddef.get("type") == "secret":
                out[key + "_set"] = bool(val)
                out[key + "_hint"] = (f"…{str(val)[-4:]}" if val and len(str(val)) >= 4 else "")
            elif val is not None:
                out[key] = val
        return out

    def list_public(self) -> dict[str, Any]:
        return {
            "types": [
                {"id": k, **{kk: vv for kk, vv in v.items()}} for k, v in CONNECTOR_TYPES.items()
            ],
            "connectors": [self._public(c) for c in self.all_configs()],
        }

    # ---- fetching ----
    def fetch(self, connector_id: str, use_cache: bool = True) -> dict[str, Any]:
        cfg = self.get(connector_id)
        if not cfg:
            raise ConnectorError(f"Connector '{connector_id}' not found.")
        if not cfg.get("enabled", True):
            raise ConnectorError(f"Connector '{cfg.get('name')}' is disabled.")

        if use_cache:
            cached = self._cache.get(connector_id)
            if cached and (time.time() - cached[0]) < CACHE_TTL:
                return cached[1]

        fetcher = _FETCHERS.get(cfg["type"])
        if not fetcher:
            raise ConnectorError(f"No fetcher for type '{cfg['type']}'.")

        events = fetcher(cfg)
        result = {
            "connector": self._public(cfg),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "events": [asdict(e) for e in events],
            "stats": _summarise(events),
        }
        self._cache[connector_id] = (time.time(), result)
        return result

    def test(self, connector_id: str) -> dict[str, Any]:
        try:
            result = self.fetch(connector_id, use_cache=False)
            return {
                "ok": True,
                "event_count": len(result["events"]),
                "message": f"Fetched {len(result['events'])} live events.",
            }
        except ConnectorError as e:
            return {"ok": False, "message": str(e)}


registry = ConnectorRegistry()
