"""Renders the decision chip + risk bar shown under each assistant turn."""


def render_risk_meter(risk_score: float, decision: str) -> str:
    pct = max(0, min(100, round(risk_score * 100)))
    decision_class = "allow" if decision == "ALLOW" else "block"
    fill_color = "#10B981" if decision == "ALLOW" else "#dc2626"

    return f"""
<div class="decision-chip {decision_class}">● {decision}</div>
<div class="risk-meter">
  risk
  <div class="risk-track"><div class="risk-fill" style="width:{pct}%; background:{fill_color};"></div></div>
  {risk_score:.2f}
</div>
"""
