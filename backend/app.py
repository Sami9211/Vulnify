"""Flask API for Vulnify."""
from __future__ import annotations

import io
import os
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from pipeline.connectors import ConnectorError
from pipeline.loader import data_status
from pipeline.service import (
    delete_connector,
    fetch_connector_live,
    get_dashboard_analytics,
    get_nexus_analytics,
    get_nexus_filter_options,
    get_nexus_live_stream,
    list_connectors,
    run_analysis,
    save_connector,
    test_connector,
)


def _env_flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

NEXUS_FILTER_KEYS = (
    "industry",
    "org_type",
    "vendor",
    "country",
    "severity",
    "status",
    "threat_type",
    "date_from",
    "date_to",
    "search",
)


def _nexus_filters_from_request():
    return {k: v for k in NEXUS_FILTER_KEYS if (v := request.args.get(k))}

app = Flask(__name__)
CORS(app)

SAMPLE_ASSETS = Path(__file__).resolve().parents[1] / "data" / "sample_asset_list.txt"


@app.route("/api/health")
def health():
    status = data_status()
    return jsonify({"status": "ok", "data": status})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    asset_text = body.get("assets", "")
    year = body.get("year")
    if not isinstance(asset_text, str) or not asset_text.strip():
        return jsonify({"success": False, "error": "No asset list provided"}), 400
    try:
        result = run_analysis(asset_text, year=year)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/analyze/sample")
def analyze_sample():
    if not SAMPLE_ASSETS.exists():
        return jsonify({"success": False, "error": "Sample file missing"}), 404
    text = SAMPLE_ASSETS.read_text(encoding="utf-8")
    try:
        return jsonify(run_analysis(text))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/analyze/export", methods=["POST"])
def export_csv():
    body = request.get_json(silent=True) or {}
    asset_text = body.get("assets", "")
    try:
        result = run_analysis(asset_text)
        if not result.get("success"):
            return jsonify(result), 400
        rows = result["results"]
        if not rows:
            return jsonify({"error": "No results to export"}), 400
        df = pd.DataFrame(rows)
        cols = [
            "rank",
            "cve_id",
            "affected_asset",
            "status",
            "severity",
            "cvss",
            "trust_score",
            "epss",
            "epss_percentile",
            "kev_flag",
            "weakness",
            "risk_summary",
            "mitigation",
            "cve_url",
        ]
        df = df[[c for c in cols if c in df.columns]]
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        buf.seek(0)
        return send_file(
            io.BytesIO(buf.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name="cve_priority_report.csv",
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/dashboard")
def dashboard():
    year = request.args.get("year", type=int)
    try:
        return jsonify(get_dashboard_analytics(year=year))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/nexus")
def nexus_dashboard():
    try:
        return jsonify(get_nexus_analytics(_nexus_filters_from_request()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/nexus/filters")
def nexus_filters():
    try:
        return jsonify(get_nexus_filter_options())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/nexus/stream")
def nexus_stream():
    batch = request.args.get("batch", default=8, type=int)
    try:
        return jsonify(get_nexus_live_stream(batch_size=batch))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sample-assets")
def sample_assets():
    if SAMPLE_ASSETS.exists():
        return jsonify({"content": SAMPLE_ASSETS.read_text(encoding="utf-8")})
    return jsonify({"content": ""})


# --- live threat-intel connectors -------------------------------------------
@app.route("/api/connectors")
def connectors_list():
    try:
        return jsonify(list_connectors())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/connectors", methods=["POST"])
def connectors_save():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify({"success": True, "connector": save_connector(body)})
    except ConnectorError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/connectors/<connector_id>", methods=["DELETE"])
def connectors_delete(connector_id):
    try:
        ok = delete_connector(connector_id)
        return jsonify({"success": ok}), (200 if ok else 404)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/connectors/<connector_id>/test", methods=["POST"])
def connectors_test(connector_id):
    try:
        return jsonify(test_connector(connector_id))
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.route("/api/connectors/<connector_id>/live")
def connectors_live(connector_id):
    """Live events from a connector. Falls back to the demo feed on failure
    when ?fallback=demo is set, so the dashboard always has something to show."""
    fallback = request.args.get("fallback") == "demo"
    try:
        return jsonify(fetch_connector_live(connector_id))
    except ConnectorError as e:
        if fallback and connector_id != "demo":
            data = fetch_connector_live("demo")
            data["degraded"] = True
            data["degraded_reason"] = str(e)
            return jsonify(data)
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Debug mode is opt-in via VULNIFY_DEBUG. The Werkzeug debugger allows
    # arbitrary code execution, so it must never default to on while binding
    # to 0.0.0.0. Host/port are configurable for flexible deployment.
    debug = _env_flag("VULNIFY_DEBUG", False)
    host = os.environ.get("VULNIFY_HOST", "127.0.0.1")
    port = int(os.environ.get("VULNIFY_PORT", "5001"))
    app.run(host=host, port=port, debug=debug)
