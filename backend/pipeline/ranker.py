"""Rank matched CVEs and enrich with trust, mitigation, and reference links."""
from __future__ import annotations

from typing import Any

from .config import CVSS_WEIGHT, EPSS_WEIGHT, KEV_BOOST

CWE_LABELS = {
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-787": "Out-of-bounds Write",
    "CWE-125": "Out-of-bounds Read",
    "CWE-416": "Use After Free",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Information Disclosure",
    "CWE-287": "Improper Authentication",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Insecure Deserialization",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-269": "Privilege Escalation",
    "CWE-400": "Uncontrolled Resource Consumption",
}


def epss_risk_label(epss: float) -> str:
    if epss >= 0.5:
        return "high"
    if epss >= 0.1:
        return "moderate"
    return "low"


def severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "Unscored"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def cwe_label(cwe_id: str) -> str:
    return CWE_LABELS.get(cwe_id, cwe_id)


def build_risk_summary(
    product: str,
    epss: float,
    in_kev: bool,
    cvss: float | None,
    weakness: str | None,
) -> str:
    sev = severity_label(cvss)
    weakness_part = f"a {weakness} flaw" if weakness else "a security weakness"
    if in_kev:
        impact = (
            "It is being actively exploited in the wild, so an unpatched system "
            "is at immediate risk of compromise."
        )
    elif sev in ("Critical", "High"):
        impact = (
            "Successful exploitation could let an attacker compromise the affected "
            "system, leading to data loss or service disruption."
        )
    elif sev == "Medium":
        impact = "Exploitation could degrade security but typically needs specific conditions."
    else:
        impact = "Impact is limited, but it should still be tracked for completeness."
    likelihood = epss_risk_label(epss)
    return (
        f"{product} is affected by {weakness_part}. {impact} "
        f"Real-world exploitation likelihood is {likelihood} (EPSS {epss:.2%})."
    )


def build_mitigation(
    in_kev: bool,
    cvss: float | None,
    kev_detail: dict | None,
    weakness: str | None,
) -> str:
    if in_kev and kev_detail and kev_detail.get("requiredAction"):
        action = kev_detail["requiredAction"].strip().rstrip(".")
        due = kev_detail.get("dueDate")
        due_part = f" CISA remediation due date: {due}." if due else ""
        return f"{action}.{due_part} Apply the vendor patch and verify on all affected hosts."

    sev = severity_label(cvss)
    base = "Apply the latest vendor security update for the affected product"
    if sev == "Critical":
        urgency = " immediately and prioritise internet-facing systems"
    elif sev == "High":
        urgency = " as a priority during the next patch cycle"
    else:
        urgency = " during routine patching"

    weakness_hint = ""
    if weakness == "SQL Injection":
        weakness_hint = " Use parameterised queries and validate all input."
    elif weakness == "Cross-Site Scripting":
        weakness_hint = " Apply output encoding and a strict Content-Security-Policy."
    elif weakness in ("Out-of-bounds Write", "Use After Free", "Out-of-bounds Read"):
        weakness_hint = " Restrict exposure until patched; memory-safety bugs are often exploitable."
    elif weakness == "Improper Authentication":
        weakness_hint = " Enforce MFA and review access controls until patched."

    return (
        f"{base}{urgency}. Where no patch is available, restrict network exposure, "
        f"apply vendor workarounds, and monitor for indicators of compromise.{weakness_hint}"
    )


def compute_trust_score(
    cpe_precision: str | None,
    normalization_method: str | None,
    normalization_score: float | None,
    in_kev: bool,
    has_cvss: bool,
    has_epss: bool,
) -> int:
    """Confidence (0-100) that this finding genuinely applies to the asset."""
    score = 0.0
    # CPE match precision is the strongest signal
    if cpe_precision == "exact":
        score += 45
    elif cpe_precision == "wildcard":
        score += 18

    # How confidently we mapped the asset name to a CPE
    if normalization_method == "exact":
        score += 30
    elif normalization_method == "fuzzy":
        score += 0.25 * (normalization_score or 0)  # up to ~25

    if has_cvss:
        score += 10
    if has_epss:
        score += 5
    if in_kev:
        score += 10  # KEV confirms it is a real, exploited vulnerability

    return max(0, min(100, round(score)))


def finding_status(trust: int) -> str:
    if trust >= 75:
        return "confirmed"
    if trust >= 50:
        return "review"
    return "false_positive"


def urgency_score(epss: float, in_kev: bool, cvss: float | None) -> float:
    cvss_val = cvss if cvss is not None else 0.0
    return (KEV_BOOST if in_kev else 0) + epss * EPSS_WEIGHT + cvss_val * CVSS_WEIGHT


def enrich_and_rank(
    matches: list[dict[str, Any]],
    kev_set: set[str],
    epss_map: dict[str, dict[str, float]],
    kev_detail_map: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    kev_detail_map = kev_detail_map or {}
    enriched: list[dict[str, Any]] = []

    for m in matches:
        cve_id = m["cve_id"]
        epss_data = epss_map.get(cve_id)
        has_epss = epss_data is not None
        epss = epss_data["epss"] if epss_data else 0.0
        percentile = epss_data["percentile"] if epss_data else 0.0
        in_kev = cve_id in kev_set
        cvss = m.get("cvss")
        cwes = m.get("cwes") or []
        weakness = cwe_label(cwes[0]) if cwes else None
        kev_detail = kev_detail_map.get(cve_id)

        trust = compute_trust_score(
            cpe_precision=m.get("cpe_precision"),
            normalization_method=m.get("normalization_method"),
            normalization_score=m.get("normalization_score"),
            in_kev=in_kev,
            has_cvss=cvss is not None,
            has_epss=has_epss,
        )

        row = {
            "cve_id": cve_id,
            "affected_asset": m["affected_asset"],
            "original_asset": m.get("original_asset"),
            "vendor": m.get("vendor"),
            "product": m.get("product"),
            "cvss": cvss,
            "severity": severity_label(cvss),
            "epss": round(epss, 6),
            "epss_percentile": round(percentile, 4),
            "kev": in_kev,
            "kev_flag": "yes" if in_kev else "no",
            "ransomware": (kev_detail or {}).get("knownRansomwareCampaignUse", "Unknown")
            if in_kev
            else None,
            "weakness": weakness,
            "weakness_id": cwes[0] if cwes else None,
            "trust_score": trust,
            "status": finding_status(trust),
            "urgency_score": urgency_score(epss, in_kev, cvss),
            "risk_summary": build_risk_summary(
                m["affected_asset"], epss, in_kev, cvss, weakness
            ),
            "mitigation": build_mitigation(in_kev, cvss, kev_detail, weakness),
            "cve_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "mitre_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "references": m.get("references") or [],
            "description": m.get("description"),
        }
        enriched.append(row)

    enriched.sort(key=lambda x: (-x["urgency_score"], -x["epss"]))
    for i, row in enumerate(enriched, start=1):
        row["rank"] = i

    return enriched
