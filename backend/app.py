"""Flask API for Vulnify."""
from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from pipeline.loader import data_status
from pipeline.service import (
    get_dashboard_analytics,
    get_nexus_analytics,
    get_nexus_filter_options,
    get_nexus_live_stream,
    run_analysis,
)

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
    if not asset_text.strip():
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
