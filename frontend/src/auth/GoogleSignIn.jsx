import { useEffect, useRef, useState } from 'react'

import { api } from '../api/client'
import { useAuth } from './AuthContext'

export function GoogleSignIn() {
  const { signInWithGoogle } = useAuth()
  const container = useRef(null)
  const [message, setMessage] = useState('Checking Google sign-in availability…')

  useEffect(() => {
    let cancelled = false
    let script
    function render(clientId) {
      if (cancelled) return
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: ({ credential }) => {
          if (!cancelled) signInWithGoogle(credential).catch(() => {})
        },
      })
      window.google.accounts.id.renderButton(container.current, {
        theme: 'outline', size: 'large', text: 'signin_with',
      })
      setMessage(null)
    }
    api.googleConfig().then(({ client_id: clientId }) => {
      if (cancelled) return
      if (!clientId) {
        setMessage('Google sign-in is not configured yet. Use your local account below.')
        return
      }
      if (window.google?.accounts?.id) {
        render(clientId)
        return
      }
      script = document.createElement('script')
      script.src = 'https://accounts.google.com/gsi/client'
      script.async = true
      script.onload = () => render(clientId)
      script.onerror = () => {
        if (!cancelled) setMessage('Google sign-in is unavailable. Use your local account below.')
      }
      document.head.appendChild(script)
    }).catch(() => {
      if (!cancelled) setMessage('Google sign-in is unavailable. Use your local account below.')
    })
    return () => {
      cancelled = true
      script?.remove()
    }
  }, [signInWithGoogle])

  return (
    <div className="mb-5">
      <div ref={container} />
      {message && <p className="text-sm text-ink-dim">{message}</p>}
    </div>
  )
}
