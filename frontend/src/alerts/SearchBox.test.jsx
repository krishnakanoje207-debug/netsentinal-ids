/**
 * The search box commits on submit rather than on every keystroke. Half a typed
 * address is not an address, and a box that refuses "203", "203.0" and "203.0.11"
 * on the way to "203.0.113.9" is one people stop reading.
 */

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { SearchBox } from './AlertFeed'

function setup(value = '') {
  const onSearch = vi.fn()
  const view = render(<SearchBox value={value} onSearch={onSearch} />)
  return { onSearch, view, user: userEvent.setup() }
}

const field = () => screen.getByLabelText('Search by address, network or technique')

describe('SearchBox', () => {
  it('says what it accepts before anything is typed', () => {
    setup()
    // Three examples beat a label reading "Search".
    expect(field()).toHaveAttribute('placeholder', '203.0.113.9, 10.0.0.0/8, T1046')
  })

  it('does not search while an address is still being typed', async () => {
    const { user, onSearch } = setup()
    await user.type(field(), '203.0.11')

    expect(onSearch).not.toHaveBeenCalled()
  })

  it('searches once the analyst submits', async () => {
    const { user, onSearch } = setup()
    await user.type(field(), '203.0.113.9{Enter}')

    expect(onSearch).toHaveBeenCalledWith('203.0.113.9')
  })

  it('submits from the button as well as the keyboard', async () => {
    const { user, onSearch } = setup()
    await user.type(field(), '10.0.0.0/8')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    expect(onSearch).toHaveBeenCalledWith('10.0.0.0/8')
  })

  it('trims what was typed, so a stray space is not a different search', async () => {
    const { user, onSearch } = setup()
    await user.type(field(), '  T1046  {Enter}')

    expect(onSearch).toHaveBeenCalledWith('T1046')
  })

  it('reports an emptied box, so clearing it restores the whole feed', async () => {
    const { user, onSearch } = setup('T1046')
    await user.clear(field())
    await user.click(screen.getByRole('button', { name: 'Search' }))

    expect(onSearch).toHaveBeenCalledWith('')
  })

  it('follows a search that was changed elsewhere', () => {
    const { view } = setup('T1046')
    expect(field()).toHaveValue('T1046')

    // A filter cleared from outside, or a restored session: the field has to show
    // what is actually being searched for.
    view.rerender(<SearchBox value="" onSearch={vi.fn()} />)
    expect(field()).toHaveValue('')
  })
})
