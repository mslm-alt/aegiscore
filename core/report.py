from __future__ import annotations
"""
core/report.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Raporlama Modülü

Günlük / haftalık istatistik üretir.
DB'den sorgular, JSON/HTML formatında döndürür.

Not: Tüm DB erişimi db.get_report_stats() üzerinden yapılır.
     Hiçbir private metod (_read, _read_one) doğrudan çağrılmaz.
"""

import time
import json
import logging
from html import escape
from pathlib import Path
from typing import Dict, List, Any
from core.language import normalize_language, system_text

logger = logging.getLogger(__name__)


class ReportEngine:

    def __init__(self, db, alert_explainer=None, alert_explanation_limit: int = 5, language: str = "tr"):
        self.db = db
        self.alert_explainer = alert_explainer
        self.alert_explanation_limit = max(1, int(alert_explanation_limit or 5))
        self.language = normalize_language(language, default="tr")

    def daily_report(self, days_back: int = 1) -> Dict:
        since = time.time() - (days_back * 86400)
        return self._build_report(since, label=system_text("last_n_days", self.language, days=days_back))

    def weekly_report(self) -> Dict:
        since = time.time() - (7 * 86400)
        return self._build_report(since, label=system_text("last_7_days", self.language))

    def _build_report(self, since: float, label: str = "") -> Dict:
        try:
            stats = self.db.get_report_stats(since)
            if not stats:
                return {}

            by_severity    = stats.get("by_severity", {})
            top_rules      = stats.get("top_rules", [])
            top_ips        = stats.get("top_entities", [])
            top_users      = stats.get("top_users", [])
            top_hosts      = stats.get("top_hosts", [])
            by_hour        = stats.get("by_hour", {})
            recent_incidents = stats.get("recent_incidents", [])
            recent_ip_reputation = self._recent_ip_reputation()
            explanation_block = self._recent_alert_explanations(since)

        except Exception as e:
            logger.error(f"[AegisCore:Report] Sorgu hatası: {e}")
            return {}

        return {
            "label":            label,
            "generated_at":     time.strftime("%Y-%m-%d %H:%M:%S"),
            "since":            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since)),
            "total_alerts":     stats.get("total_alerts", 0),
            "total_incidents":  stats.get("incident_total", 0),
            "by_severity":      by_severity,
            "top_rules":        top_rules,
            "top_ips":          top_ips,
            "top_users":        top_users,
            "top_hosts":        top_hosts,
            "by_hour":          by_hour,
            "critical":         by_severity.get("critical", 0),
            "high":             by_severity.get("high", 0),
            "top_rule":         top_rules[0][0] if top_rules else "",
            "top_ip":           top_ips[0][0] if top_ips else "",
            "recent_incidents": recent_incidents,
            "recent_ip_reputation": recent_ip_reputation,
            "recent_alert_explanations": explanation_block.get("items", []),
            "recent_alert_explanations_source": explanation_block.get("source", "empty"),
        }

    def _recent_ip_reputation(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        if not hasattr(self.db, "get_ip_block_suggestions"):
            return rows
        try:
            pending = self.db.get_ip_block_suggestions(reviewed=False, limit=limit) or []
            reviewed = self.db.get_ip_block_suggestions(reviewed=True, limit=limit) or []
            combined = [dict(r) for r in pending] + [dict(r) for r in reviewed]
            filtered = [
                r for r in combined
                if str(r.get("source", "") or "").strip().lower() == "abuseipdb"
            ]
            filtered.sort(key=lambda r: float(r.get("suggested_at", 0) or 0), reverse=True)
            for row in filtered[:limit]:
                rows.append({
                    "id": row.get("id"),
                    "ip": row.get("ip", ""),
                    "abuse_score": row.get("abuse_score"),
                    "abuse_reports": row.get("abuse_reports"),
                    "abuse_country": row.get("abuse_country", ""),
                    "alert_id": row.get("alert_id"),
                    "reviewed": bool(row.get("reviewed", False)),
                    "action": row.get("action", "") or "",
                    "source": row.get("source", "") or "",
                })
        except Exception as e:
            logger.debug(f"[AegisCore:Report] IP reputation bölümü atlandı: {e}")
        return rows

    def _recent_alert_explanations(self, since: float) -> Dict[str, Any]:
        if not self.alert_explainer or not hasattr(self.db, "get_recent_alerts"):
            return {"items": [], "source": "disabled"}
        hours = max(1.0, (time.time() - float(since or time.time())) / 3600.0)
        try:
            alerts = self.db.get_recent_alerts(limit=self.alert_explanation_limit, hours=hours) or []
            source = "report_window"
            if not alerts:
                alerts = self.db.get_recent_alerts(limit=self.alert_explanation_limit, hours=24 * 365 * 50) or []
                source = "all_alerts" if alerts else "empty"
        except Exception as e:
            logger.debug(f"[AegisCore:Report] Alert explanation bölümü atlandı: {e}")
            return {"items": [], "source": "error"}
        return {
            "items": self._build_report_explanation_rows(alerts),
            "source": source,
        }

    def _build_report_explanation_rows(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for alert in alerts[:self.alert_explanation_limit]:
            payload = dict(alert or {})
            try:
                explanation = dict(self.alert_explainer(payload) or {})
            except Exception as e:
                logger.debug(f"[AegisCore:Report] Alert explanation fallback kullanıldı: {e}")
                explanation = {}
            rows.append(self._coerce_report_explanation(payload, explanation))
        return rows

    def _coerce_report_explanation(self, alert: Dict[str, Any], explanation: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(explanation.get("kind", "") or "").strip().lower()
        if kind not in {"rule", "ml"}:
            kind = "ml" if str(alert.get("rule_id", "") or "").strip().upper().startswith("ML-") else "rule"
        rule_id = str(explanation.get("rule_id", alert.get("rule_id", "")) or "").strip() or system_text("unknown", self.language)
        severity = str(explanation.get("severity", alert.get("severity", "")) or "").strip() or "unknown"
        entity = str(explanation.get("entity", alert.get("entity", "")) or "").strip() or system_text("unspecified", self.language)
        why_default = (
            explanation.get("why_triggered", "") or system_text("manual_validate_context", self.language)
            if kind == "ml"
            else str(explanation.get("why_triggered", "") or "").strip() or system_text("manual_validate_context", self.language)
        )
        result = {
            "kind": kind,
            "alert_id": explanation.get("alert_id", alert.get("id", alert.get("alert_id", ""))),
            "rule_id": rule_id,
            "severity": severity,
            "risk_score": float(explanation.get("risk_score", alert.get("risk_score", 0.0)) or 0.0),
            "entity": entity,
            "why_triggered": str(explanation.get("why_triggered", "") or "").strip() or why_default,
            "evidence_fields": dict(explanation.get("evidence_fields", {}) or {}),
            "review_steps": list(explanation.get("review_steps", []) or []),
            "metadata_missing": bool(explanation.get("metadata_missing", False)),
        }
        if kind == "rule":
            result["key_evidence"] = list(explanation.get("key_evidence", []) or [])
            return result
        ml_meta = dict(explanation.get("ml_metadata", {}) or {})
        result.update({
            "ml_family": str(ml_meta.get("ml_family", "") or "").strip() or system_text("unknown", self.language),
            "ml_label": str(ml_meta.get("ml_label", "") or "").strip() or system_text("unknown", self.language),
            "model_score": float(ml_meta.get("model_score", 0.0) or 0.0),
            "confidence": float(ml_meta.get("confidence", 0.0) or 0.0),
            "top_features": list(ml_meta.get("top_features", []) or []),
            "time_context": dict(ml_meta.get("time_context", {}) or {}),
            "baseline_deviation": dict(ml_meta.get("baseline_deviation", {}) or {}),
            "no_action_contract": bool(ml_meta.get("no_action_contract", True)),
            "action_taken": bool(ml_meta.get("action_taken", False)),
        })
        return result

    def to_html(self, report: Dict) -> str:
        def h(value: Any) -> str:
            return escape(str(value), quote=True)

        def bar(val, max_val, color="#0d6efd"):
            pct = int((val / max(max_val, 1)) * 100)
            return f'<div style="background:{color};height:16px;width:{pct}%;border-radius:3px"></div>'

        sev_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#0dcaf0", "info": "#6c757d"
        }

        sev_rows = ""
        for sev, cnt in sorted(report.get("by_severity", {}).items(),
                                key=lambda x: ["info","low","medium","high","critical"].index(x[0])
                                if x[0] in ["info","low","medium","high","critical"] else 0,
                                reverse=True):
            color = sev_colors.get(sev, "#6c757d")
            sev_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{h(sev.upper())}</span></td>
                <td>{h(cnt)}</td>
                <td style="width:200px">{bar(cnt, report.get('total_alerts',1), color)}</td>
            </tr>"""

        rule_rows = ""
        for rule, cnt in report.get("top_rules", [])[:10]:
            rule_rows += f"<tr><td><code>{h(rule)}</code></td><td>{h(cnt)}</td></tr>"

        ip_rows = ""
        for ip, cnt in report.get("top_ips", [])[:10]:
            ip_rows += f"<tr><td><code>{h(ip)}</code></td><td>{h(cnt)}</td></tr>"

        user_rows = ""
        for user, cnt in report.get("top_users", [])[:10]:
            user_rows += f"<tr><td><code>{h(user)}</code></td><td>{h(cnt)}</td></tr>"

        hour_data = report.get("by_hour", {})
        max_hour  = max(hour_data.values()) if hour_data else 1
        hour_bars = ""
        for hour in range(24):
            cnt = hour_data.get(hour, 0)
            pct = int((cnt / max_hour) * 60)
            hour_bars += f"""
            <div style="display:inline-block;text-align:center;width:3.8%;margin:0 0.1%">
                <div style="background:#0d6efd;height:{pct}px;min-height:2px;border-radius:2px 2px 0 0"></div>
                <div style="font-size:10px;color:#999">{hour:02d}</div>
            </div>"""

        incident_rows = ""
        for inc in report.get("recent_incidents", []):
            sev   = inc.get("severity", "")
            color = sev_colors.get(sev, "#6c757d")
            reopened = f" (#{inc['reopen_count']})" if inc.get("reopen_count", 0) > 0 else ""
            ts_str = time.strftime("%H:%M", time.localtime(inc.get("ts_start", 0)))
            risk_score_text = f"{float(inc.get('risk_score', 0) or 0.0):.0f}"
            status_text = f"{inc.get('status', '')}{reopened}"
            incident_rows += (
                f"<tr>"
                f"<td>{h(ts_str)}</td>"
                f"<td>{h(inc.get('title','')[:60])}</td>"
                f"<td style='color:{color};font-weight:bold'>{h(sev.upper())}</td>"
                f"<td>{h(risk_score_text)}</td>"
                f"<td><code>{h(inc.get('entity','')[:30])}</code></td>"
                f"<td>{h(status_text)}</td>"
                f"</tr>"
            )

        reputation_rows = ""
        for item in report.get("recent_ip_reputation", [])[:10]:
            suggestion_status = item.get("action", "") if item.get("reviewed") else "pending"
            reputation_rows += (
                f"<tr>"
                f"<td><code>{h(item.get('ip',''))}</code></td>"
                f"<td>{h(item.get('abuse_score', ''))}</td>"
                f"<td>{h(item.get('abuse_reports', ''))}</td>"
                f"<td>{h(item.get('abuse_country', ''))}</td>"
                f"<td>{h(item.get('alert_id', ''))}</td>"
                f"<td>{h(suggestion_status)}</td>"
                f"</tr>"
            )

        explanation_rows = ""
        for item in report.get("recent_alert_explanations", [])[:self.alert_explanation_limit]:
            risk_score_text = f"{float(item.get('risk_score', 0.0) or 0.0):.2f}"
            summary_parts = [
                f"<span><strong>Rule ID:</strong> <code>{h(item.get('rule_id', ''))}</code></span>",
                f"<span><strong>Severity:</strong> {h(item.get('severity', ''))}</span>",
                f"<span><strong>Risk score:</strong> {h(risk_score_text)}</span>",
                f"<span><strong>Entity:</strong> <code>{h(item.get('entity', ''))}</code></span>",
            ]
            evidence = dict(item.get("evidence_fields", {}) or {})
            evidence_html = "".join(
                f"<li><strong>{h(key)}:</strong> <code>{h(value)}</code></li>"
                for key, value in evidence.items()
            ) or f"<li>{h(system_text('no_important_fields', self.language))}</li>"
            review_steps = "".join(
                f"<li>{h(step)}</li>"
                for step in list(item.get("review_steps", []) or [])
            ) or f"<li>{h(system_text('manual_validate_context', self.language))}</li>"
            extra_block = ""
            if item.get("kind") == "ml":
                top_features_html = "".join(f"<li><code>{h(feature)}</code></li>" for feature in item.get("top_features", [])) or f"<li>{h(system_text('no_top_feature_info', self.language))}</li>"
                time_context_html = "".join(f"<li><strong>{h(key)}:</strong> {h(value)}</li>" for key, value in dict(item.get("time_context", {}) or {}).items()) or f"<li>{h(system_text('no_time_context', self.language))}</li>"
                baseline_html = "".join(f"<li><strong>{h(key)}:</strong> {h(value)}</li>" for key, value in dict(item.get("baseline_deviation", {}) or {}).items()) or f"<li>{h(system_text('no_baseline_info', self.language))}</li>"
                score_confidence_text = f"{float(item.get('model_score', 0.0) or 0.0):.2f} / {float(item.get('confidence', 0.0) or 0.0):.2f}"
                extra_block = f"""
                <div class="alert-ml-grid">
                  <div><strong>ML family:</strong> {h(item.get('ml_family', ''))}</div>
                  <div><strong>ML label:</strong> {h(item.get('ml_label', ''))}</div>
                  <div><strong>score/confidence:</strong> {h(score_confidence_text)}</div>
                  <div><strong>no_action_contract:</strong> {h(item.get('no_action_contract', True))}</div>
                  <div><strong>action_taken:</strong> {h(item.get('action_taken', False))}</div>
                </div>
                <div class="alert-subgrid">
                  <div><strong>top_features</strong><ul>{top_features_html}</ul></div>
                  <div><strong>time_context</strong><ul>{time_context_html}</ul></div>
                  <div><strong>baseline_deviation</strong><ul>{baseline_html}</ul></div>
                </div>
                """
            else:
                key_evidence_html = "".join(f"<li><code>{h(evidence_item)}</code></li>" for evidence_item in item.get("key_evidence", [])) or f"<li>{h(system_text('key_evidence', self.language))}: -</li>"
                extra_block = f"<div><strong>{h(system_text('key_evidence', self.language))}</strong><ul>{key_evidence_html}</ul></div>"
            fallback_note = ""
            if item.get("metadata_missing"):
                fallback_note = f"<p class='note'>{h(system_text('metadata_missing_short', self.language))}</p>"
            explanation_rows += f"""
            <div class="alert-card">
              <div class="alert-summary">{''.join(summary_parts)}</div>
              <p><strong>{h(system_text('why_triggered', self.language))}</strong> {h(item.get('why_triggered', ''))}</p>
              <div class="alert-subgrid">
                <div><strong>{h(system_text('important_evidence_fields', self.language))}</strong><ul>{evidence_html}</ul></div>
                <div><strong>{h(system_text('control_recommendations', self.language))}</strong><ul>{review_steps}</ul></div>
              </div>
              {extra_block}
              {fallback_note}
            </div>
            """
        explanation_source = str(report.get("recent_alert_explanations_source", "empty") or "empty")
        explanation_intro = system_text("explanation_intro_recent", self.language, limit=h(self.alert_explanation_limit))
        if explanation_source == "all_alerts":
            explanation_intro = system_text("explanation_intro_fallback", self.language)
        elif explanation_source == "empty":
            explanation_intro = system_text("no_alerts_to_explain", self.language)

        return f"""<!DOCTYPE html>
<html lang="{h(self.language)}">
<head>
<meta charset="UTF-8">
<title>{h(system_text('report_title', self.language))} — {h(report.get('label',''))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0f1117; color: #e0e0e0; margin: 0; padding: 20px; }}
  h1, h2 {{ color: #fff; }}
  .card {{ background: #1a1d27; border-radius: 10px; padding: 20px;
            margin-bottom: 20px; border: 1px solid #2a2d3a; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px; margin-bottom: 20px; }}
  .stat {{ background: #1a1d27; border-radius: 10px; padding: 16px;
            text-align: center; border: 1px solid #2a2d3a; }}
  .stat .num {{ font-size: 2em; font-weight: bold; color: #fff; }}
  .stat .lbl {{ color: #888; font-size: 0.85em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #2a2d3a; padding: 10px; text-align: left; color: #aaa; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #2a2d3a; }}
  tr:hover td {{ background: #2a2d3a22; }}
  code {{ background: #2a2d3a; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
  .alert-card {{ border: 1px solid #2a2d3a; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #141824; }}
  .alert-summary {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 10px; color: #c8d1dc; }}
  .alert-subgrid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
  .alert-ml-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin: 12px 0; }}
  .note {{ color: #f0ad4e; font-size: 0.92em; margin: 8px 0 0; }}
  ul {{ margin: 8px 0 0 18px; padding: 0; }}
  li {{ margin-bottom: 4px; }}
</style>
</head>
<body>
<h1>🛡️ AegisCore — {h(report.get('label',''))}</h1>
<p style="color:#888">{h(system_text('generated_at', self.language))}: {h(report.get('generated_at',''))} | {h(system_text('since', self.language))}: {h(report.get('since',''))}</p>

<div class="grid">
  <div class="stat"><div class="num">{h(report.get('total_alerts',0))}</div><div class="lbl">{h(system_text('total_alerts', self.language))}</div></div>
  <div class="stat"><div class="num">{h(report.get('total_incidents',0))}</div><div class="lbl">{h(system_text('incident', self.language))}</div></div>
  <div class="stat"><div class="num" style="color:#dc3545">{h(report.get('critical',0))}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#fd7e14">{h(report.get('high',0))}</div><div class="lbl">High</div></div>
</div>

<div class="card">
  <h2>{h(system_text('severity_distribution', self.language))}</h2>
  <table><tr><th>{h(system_text('severity', self.language))}</th><th>{h(system_text('count', self.language))}</th><th>{h(system_text('distribution', self.language))}</th></tr>{sev_rows}</table>
</div>

<div class="card">
  <h2>{h(system_text('hourly_distribution', self.language))}</h2>
  <div style="display:flex;align-items:flex-end;height:80px;padding-top:10px">
    {hour_bars}
  </div>
</div>

<div class="card">
  <h2>{h(system_text('ip_reputation', self.language))}</h2>
  {f'<table><tr><th>IP</th><th>Score</th><th>{h(system_text("reports", self.language))}</th><th>{h(system_text("country", self.language))}</th><th>Alert ID</th><th>{h(system_text("suggestion_status", self.language))}</th></tr>' + reputation_rows + '</table>' if reputation_rows else f'<p style="color:#666">{h(system_text("no_reputation", self.language))}</p>'}
</div>

<div class="card">
  <h2>{h(system_text('alert_explanations', self.language))}</h2>
  <p style="color:#888">{h(explanation_intro)}</p>
  {explanation_rows if explanation_rows else f'<p style="color:#666">{h(system_text("no_alerts_to_explain", self.language))}</p>'}
</div>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px">
  <div class="card">
    <h2>{h(system_text('top_triggered_rules', self.language))}</h2>
    <table><tr><th>{h(system_text('rule', self.language))}</th><th>{h(system_text('count', self.language))}</th></tr>{rule_rows}</table>
    <h2>{h(system_text('recent_incidents', self.language))}</h2>
    {f'<table><tr><th>{h(system_text("time", self.language))}</th><th>{h(system_text("title", self.language))}</th><th>{h(system_text("severity", self.language))}</th><th>{h(system_text("risk_score", self.language))}</th><th>{h(system_text("entity", self.language))}</th><th>{h(system_text("status", self.language))}</th></tr>' + incident_rows + '</table>' if incident_rows else f'<p style="color:#666">{h(system_text("no_incidents_yet", self.language))}</p>'}
  </div>
  <div class="card">
    <h2>{h(system_text('most_active_entities', self.language))}</h2>
    <table><tr><th>{h(system_text('ip_or_user', self.language))}</th><th>{h(system_text('count', self.language))}</th></tr>{ip_rows}</table>
  </div>
  <div class="card">
    <h2>{h(system_text('most_active_users', self.language))}</h2>
    <table><tr><th>{h(system_text('user', self.language))}</th><th>{h(system_text('count', self.language))}</th></tr>{user_rows}</table>
  </div>
</div>
</body></html>"""

    def save_html(self, report: Dict, path: str = "data/report.html"):
        try:
            Path(path).write_text(self.to_html(report), encoding="utf-8")
            logger.info(f"[AegisCore:Report] HTML kaydedildi: {path}")
        except Exception as e:
            logger.error(f"[AegisCore:Report] HTML kayıt hatası: {e}")
