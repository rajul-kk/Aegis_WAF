const NO_EXAMPLE = '(none - type your own)'

export default function ExamplePicker({ examples, onSelect }) {
  const handleChange = (e) => {
    const label = e.target.value
    if (label === NO_EXAMPLE) {
      onSelect({ prompt: '', context: '' })
      return
    }
    const selected = examples.find((ex) => ex.label === label)
    if (selected) onSelect(selected)
  }

  return (
    <div className="field">
      <label>Load an example prompt</label>
      <select defaultValue={NO_EXAMPLE} onChange={handleChange}>
        <option>{NO_EXAMPLE}</option>
        {examples.map((ex) => (
          <option key={ex.label} value={ex.label}>
            {ex.label}
          </option>
        ))}
      </select>
    </div>
  )
}
