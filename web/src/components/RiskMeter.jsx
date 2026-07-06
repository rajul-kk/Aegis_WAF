import './RiskMeter.css'

export default function RiskMeter({ riskScore, decision }) {
  const pct = Math.max(0, Math.min(100, Math.round(riskScore * 100)))
  const decisionClass = decision === 'ALLOW' ? 'allow' : 'block'
  const fillColor = decision === 'ALLOW' ? 'var(--aegis-primary)' : 'var(--aegis-block)'

  return (
    <>
      <div className={`decision-chip ${decisionClass}`}>● {decision}</div>
      <div className="risk-meter">
        risk
        <div className="risk-track">
          <div className="risk-fill" style={{ width: `${pct}%`, background: fillColor }} />
        </div>
        {riskScore.toFixed(2)}
      </div>
    </>
  )
}
