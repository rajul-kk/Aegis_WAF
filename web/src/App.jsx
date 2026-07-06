import { useEffect, useState } from 'react'
import './App.css'
import ConversationFeed from './components/ConversationFeed'
import ExamplePicker from './components/ExamplePicker'
import ChatInput from './components/ChatInput'
import { fetchExamples, sendChat } from './api'

function newSessionId() {
  return crypto.randomUUID()
}

function getOrCreateSessionId() {
  const stored = localStorage.getItem('aegis_session_id')
  if (stored) return stored
  const fresh = newSessionId()
  localStorage.setItem('aegis_session_id', fresh)
  return fresh
}

function App() {
  const [sessionId, setSessionId] = useState(getOrCreateSessionId)
  const [conversation, setConversation] = useState([])
  const [examples, setExamples] = useState([])
  const [prompt, setPrompt] = useState('')
  const [context, setContext] = useState('')
  const [sending, setSending] = useState(false)

  useEffect(() => {
    fetchExamples().then(setExamples)
  }, [])

  const handleNewSession = () => {
    const fresh = newSessionId()
    localStorage.setItem('aegis_session_id', fresh)
    setSessionId(fresh)
    setConversation([])
  }

  const handleSelectExample = (ex) => {
    setPrompt(ex.prompt)
    setContext(ex.context || '')
  }

  const handleSend = async () => {
    const trimmed = prompt.trim()
    if (!trimmed || sending) return

    setSending(true)
    setConversation((c) => [...c, { role: 'user', content: trimmed }])
    setPrompt('')
    setContext('')

    let result
    try {
      result = await sendChat(trimmed, sessionId, context)
    } catch (e) {
      result = { error: String(e) }
    }

    setConversation((c) => [...c, { role: 'assistant', content: result }])
    setSending(false)
  }

  return (
    <div className="aegis-app">
      <div className="aegis-nav">
        🛡️ Aegis WAF
        <span className="session-id">session {sessionId.slice(0, 8)}</span>
      </div>

      <div className="aegis-toolbar">
        <button className="aegis-btn" onClick={handleNewSession}>
          New Session
        </button>
      </div>

      <ConversationFeed conversation={conversation} />

      <div className="aegis-composer">
        <ExamplePicker examples={examples} onSelect={handleSelectExample} />
        <ChatInput
          prompt={prompt}
          context={context}
          onPromptChange={setPrompt}
          onContextChange={setContext}
          onSend={handleSend}
          sending={sending}
        />
      </div>
    </div>
  )
}

export default App
