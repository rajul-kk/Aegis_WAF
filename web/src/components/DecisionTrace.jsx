import './DecisionTrace.css'

export default function DecisionTrace({ wafResult }) {
  const explanation = wafResult.explanation || {}
  const scan = wafResult.scan || {}
  const council = wafResult.council || {}
  const latency = wafResult.latency_ms || {}

  const patterns = (scan.patterns_matched || []).join(', ') || 'none'
  const decodings = (scan.decodings || []).join(', ') || 'none'
  const evidence = (explanation.evidence || []).join('; ') || 'none'
  const votes = council.votes || []

  return (
    <details className="aegis-trace-details">
      <summary>Decision trace</summary>
      <div className="aegis-trace">
        <b>reason_code</b> {explanation.reason_code || 'N/A'}<br />
        <b>route</b> {wafResult.route || 'N/A'}<br />
        <b>patterns</b> {patterns}<br />
        <b>decodings</b> {decodings}<br />
        <b>evidence</b> {evidence}<br />
        <b>latency</b> fast_scan={latency.fast_scan || 0}ms &middot;{' '}
        classify={latency.intent_classification || 0}ms &middot;{' '}
        council={latency.camel_verification || 0}ms &middot;{' '}
        total={latency.total || 0}ms
        {votes.length > 0 && (
          <>
            <br /><b>council votes</b><br />
            {votes.map((v, i) => (
              <span key={i}>
                {v.agent || '?'}: {v.decision || '?'} ({(v.confidence || 0).toFixed(2)})
                <br />
              </span>
            ))}
          </>
        )}
      </div>
    </details>
  )
}
