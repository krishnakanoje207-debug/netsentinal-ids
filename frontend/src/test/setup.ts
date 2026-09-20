import '@testing-library/jest-dom/vitest'

// jsdom has no WebSocket, and the alert feed opens one on mount. A stub keeps the
// component tests focused on rendering; the hook's own behaviour is tested directly.
class StubWebSocket {
  static instances: StubWebSocket[] = []
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: { data: string }) => void) | null = null
  readonly url: string
  closed = false

  constructor(url: string) {
    this.url = url
    StubWebSocket.instances.push(this)
  }

  close(): void {
    this.closed = true
    this.onclose?.()
  }

  /** Test helper: deliver a frame as the server would. */
  emit(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }
}

Object.defineProperty(globalThis, 'WebSocket', {
  writable: true,
  value: StubWebSocket,
})

export { StubWebSocket }
