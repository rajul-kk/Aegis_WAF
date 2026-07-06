export default function ChatInput({ prompt, context, onPromptChange, onContextChange, onSend, sending }) {
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      onSend()
    }
  }

  return (
    <>
      <div className="field">
        <label>Message</label>
        <input
          type="text"
          value={prompt}
          onChange={(e) => onPromptChange(e.target.value)}
          onKeyDown={handleKeyDown}
        />
      </div>
      <div className="field">
        <label>Optional: retrieved context / tool output</label>
        <textarea
          rows={3}
          value={context}
          onChange={(e) => onContextChange(e.target.value)}
        />
      </div>
      <div className="aegis-composer-row">
        <button
          className="aegis-btn primary"
          onClick={onSend}
          disabled={sending || !prompt.trim()}
        >
          {sending ? 'Sending…' : 'Send'}
        </button>
      </div>
    </>
  )
}
