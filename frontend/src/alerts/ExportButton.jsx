/**
 * Take the feed away as a file.
 *
 * Decisions that shaped this control:
 *
 * - It exports what the filters currently show, never everything. The button sits
 *   next to the filters and the file matches them, because an export that silently
 *   differs from the screen it was taken from is evidence nobody can reproduce.
 * - A truncated file is announced. The server caps the rows and says so in both a
 *   header and the filename; this says it on screen too, while the analyst is still
 *   looking at the list they thought they had exported.
 * - The saved name is the server's, not the browser's. It carries the timestamp and
 *   the word "truncated", and both have to survive onto the disk.
 */

import { useMutation } from '@tanstack/react-query'

import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'

/**
 * Hand the blob to the browser as a download.
 *
 * Exported so the component can be tested without jsdom having to implement a
 * download, and because this is the one piece here that touches the DOM directly.
 *
 * @param {Blob} blob
 * @param {string} filename
 */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // Revoked straight away: the download has already started, and an object URL
  // that is never released holds the whole file in memory until the tab closes.
  URL.revokeObjectURL(url)
}

/** @param {{status: string, severity: string, save?: typeof saveBlob}} props */
export function ExportButton({ status, severity, save = saveBlob }) {
  const { token } = useAuth()

  const exportAlerts = useMutation({
    mutationFn: () =>
      api.exportAlerts(token, { status: status || undefined, severity: severity || undefined }),
    onSuccess: (result) => save(result.blob, result.filename),
  })

  return (
    <div className="flex flex-col items-end">
      <button
        type="button"
        disabled={exportAlerts.isPending}
        onClick={() => exportAlerts.mutate()}
        className="rounded border border-[var(--color-line)] bg-[var(--color-panel)] px-2.5 py-1 text-xs disabled:opacity-50"
      >
        {exportAlerts.isPending ? 'Exporting...' : 'Export CSV'}
      </button>

      {exportAlerts.data?.truncated && (
        <p
          role="status"
          data-testid="export-truncated"
          className="mt-1 max-w-[16rem] text-right text-[11px] text-[var(--color-sev-medium)]"
        >
          The export hit the server's row cap, so the file is partial. Narrow the filters
          and export again.
        </p>
      )}

      {exportAlerts.isError && (
        <p className="mt-1 text-[11px] text-[var(--color-sev-high)]" role="alert">
          {exportAlerts.error.message}
        </p>
      )}
    </div>
  )
}
