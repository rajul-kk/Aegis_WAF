export async function fetchExamples() {
  const resp = await fetch('/api/examples')
  if (!resp.ok) return []
  return resp.json()
}

export async function sendChat(prompt, sessionId, context) {
  const resp = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, session_id: sessionId, context }),
  })
  return resp.json()
}
