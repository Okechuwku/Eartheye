from __future__ import annotations
from collections import Counter
from typing import Any

class TriageModule:
    """
    Triage and Scoring Engine.

    Eartheye prioritizes findings rather than just listing them. Scores
    are computed from six weighted dimensions:

      1. Severity        – intrinsic risk of the finding type
      2. Confidence      – how certain we are (tool + heuristic quality)
      3. Exposure Level  – how publicly reachable the asset is
      4. Asset Importance – estimated business criticality of the host
      5. Repeat Occurrences – same class found multiple times raises priority
      6. Exploitability  – likelihood of manual exploitation based on keywords

    Output priority tiers:
      Critical (≥80)  → Immediate manual investigation required
      High     (≥60)  → Should be reviewed before pentest begins
      Medium   (≥40)  → Review during pentest prep
      Low      (<40)  → Informational / backlog

    This is detective/recon-only. No exploit is automated.
    """

    # ── Dimension weight tables ─────────────────────────────────────────────
    _SEVERITY_SCORES = {
        "critical": 35, "high": 25, "medium": 15, "low": 5,
        "info": 2, "informational": 2, "unknown": 3,
    }
    _CONFIDENCE_SCORES  = {"High": 15, "Medium": 8, "Low": 3}
    _EXPOSURE_SCORES    = {"Public": 15, "High": 12, "Medium": 7, "Low": 2}
    _ASSET_SCORES       = {"critical": 15, "high": 10, "medium": 5, "low": 2}

    # Keywords that raise exploitability score
    _EXPLOIT_KEYWORDS = {
        "idor": 10, "ssrf": 10, "sqli": 10, "sql": 10, "rce": 12, "xxe": 10,
        "access control": 8, "broken auth": 8, "bypass": 8, "privilege": 7,
        "exposure": 6, "leak": 6, "key": 5, "token": 5, "credentials": 8,
        "hardcoded": 9, "aws": 7, "secret": 8, "password": 7,
        "database": 6, "backup": 5, "config": 5, "graphql introspection": 9,
    }

    @staticmethod
    def _exploit_score(text: str) -> int:
        text_l = text.lower()
        score = 0
        for kw, pts in TriageModule._EXPLOIT_KEYWORDS.items():
            if kw in text_l:
                score += pts
        return min(score, 15)  # cap at 15

    @staticmethod
    def _repeat_bonus(occurrence_count: int) -> int:
        """Repeated occurrences of the same class raise priority."""
        if occurrence_count >= 5:  return 5
        if occurrence_count >= 3:  return 3
        if occurrence_count >= 2:  return 1
        return 0

    @staticmethod
    def score_finding(
        severity: str,
        description: str,
        confidence: str = "Medium",
        exposure_level: str = "High",
        asset_importance: str = "medium",
        occurrence_count: int = 1,
    ) -> dict[str, Any]:
        """
        Score a single finding. Returns enriched metadata dict ready for DB storage.
        """
        sev_score  = TriageModule._SEVERITY_SCORES.get(severity.lower(), 3)
        conf_score = TriageModule._CONFIDENCE_SCORES.get(confidence, 8)
        exp_score  = TriageModule._EXPOSURE_SCORES.get(exposure_level, 7)
        asset_score = TriageModule._ASSET_SCORES.get(asset_importance.lower(), 5)
        exploit_score = TriageModule._exploit_score(description)
        repeat_bonus  = TriageModule._repeat_bonus(occurrence_count)

        total = sev_score + conf_score + exp_score + asset_score + exploit_score + repeat_bonus

        if total >= 80:
            priority = "Critical"
        elif total >= 60:
            priority = "High"
        elif total >= 40:
            priority = "Medium"
        else:
            priority = "Low"

        # Manual review is warranted if score ≥ High or exploit keywords hit
        manual_review = total >= 60 or exploit_score >= 8

        return {
            "confidence":            confidence,
            "exposure_level":        exposure_level,
            "priority":              priority,
            "triage_score":          total,
            "manual_review_required": manual_review,
            "exploit_indicators":    exploit_score > 0,
        }

    @staticmethod
    def triage_finding_list(
        findings: list[dict[str, Any]],
        exposure_level: str = "High",
        asset_importance: str = "medium",
    ) -> list[dict[str, Any]]:
        """
        Batch-triage a list of raw finding dicts.

        Each finding dict should contain at minimum:
          - "severity"    (str)
          - "description" (str)
        Optional keys: "confidence", "exposure_level", "asset_importance"

        Returns the same list with triage metadata injected into each item,
        sorted by triage_score descending so highest-priority items are first.
        """
        # Count occurrences per finding class for repeat bonus
        desc_counts = Counter(f.get("description", "").lower() for f in findings)

        enriched = []
        for finding in findings:
            sev  = finding.get("severity", "unknown")
            desc = finding.get("description", "")
            conf = finding.get("confidence", "Medium")
            exp  = finding.get("exposure_level", exposure_level)
            asset = finding.get("asset_importance", asset_importance)
            occ  = desc_counts.get(desc.lower(), 1)

            scores = TriageModule.score_finding(
                severity=sev,
                description=desc,
                confidence=conf,
                exposure_level=exp,
                asset_importance=asset,
                occurrence_count=occ,
            )
            enriched.append({**finding, **scores})

        enriched.sort(key=lambda x: x.get("triage_score", 0), reverse=True)
        return enriched
