import '@testing-library/jest-dom/vitest'

// jsdom has no WebSocket, and the alert feed opens one on mount. A stub keeps the
// component tests focused on rendering; the hook's own behaviour is tested directly.
class StubWebSocket {
  static instances = []

  constructor(url) {
    this.onopen = null
    this.onclose = null
    this.onerror = null
    this.onmessage = null
    this.closed = false
    this.url = url
    StubWebSocket.instances.push(this)
  }

  close() {
    this.closed = true
    this.onclose?.()
  }

  /** Test helper: deliver a frame as the server would. */
  emit(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }
}

Object.defineProperty(globalThis, 'WebSocket', {
  writable: true,
  value: StubWebSocket,
})

export { StubWebSocket }
