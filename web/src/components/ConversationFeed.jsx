import RiskMeter from './RiskMeter'
import DecisionTrace from './DecisionTrace'

export default function ConversationFeed({ conversation }) {
  if (conversation.length === 0) {
    return <div className="aegis-empty">No requests yet — send a message below.</div>
  }

  return (
    <div className="aegis-feed">
      {conversation.map((turn, i) => {
        if (turn.role === 'user') {
          return (
            <div className="aegis-msg" key={i}>
              <span className="who">YOU</span>
              {turn.content}
            </div>
          )
        }

        const result = turn.content
        if (result.error) {
          return (
            <div className="aegis-msg" key={i}>
              <span className="who">AEGIS</span>
              Request failed: {result.error}
            </div>
          )
        }

        const decision = result.blocked ? 'BLOCK' : 'ALLOW'
        return (
          <div className="aegis-msg" key={i}>
            <span className="who">AEGIS</span>
            <RiskMeter riskScore={result.risk_score || 0} decision={decision} />
            {result.response === '[LLM not configured - set GROQ_API_KEY in .env]' ? (
              <p className="assistant-response">LLM response generation is disabled (no API key set) — showing WAF decision only.</p>
            ) : result.response ? (
              <p className="assistant-response">{result.response}</p>
            ) : null}
            <DecisionTrace wafResult={result.waf_result || {}} />
          </div>
        )
      })}
    </div>
  )
}
