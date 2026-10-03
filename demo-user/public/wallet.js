const readyStatus = document.querySelector('#readyStatus')
const invitationForm = document.querySelector('#invitationForm')
const invitationUrl = document.querySelector('#invitationUrl')
const formMessage = document.querySelector('#formMessage')
const credentialOffers = document.querySelector('#credentialOffers')
const proofRequests = document.querySelector('#proofRequests')
const activityFeed = document.querySelector('#activityFeed')
const offerCount = document.querySelector('#offerCount')
const proofCount = document.querySelector('#proofCount')

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {'Content-Type': 'application/json'},
    ...options,
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || 'Request failed')
  return data
}

function pretty(value) {
  return JSON.stringify(value, null, 2)
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function formatDateTime(value) {
  if (!value) return 'Not available'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Not available'
  return date.toLocaleString()
}

function shortValue(value, fallback = 'Not available') {
  if (!value) return fallback
  if (value.length <= 52) return value
  return `${value.slice(0, 24)}...${value.slice(-18)}`
}

function displayResource(value) {
  if (!value) return 'Not available'
  try {
    const url = new URL(value)
    return `${url.origin}${url.pathname}`
  } catch (error) {
    return value
  }
}

function describeProofRequester(proof) {
  const connection = proof.connection || {}
  return connection.label || connection.did || connection.invitationDid || proof.id || 'Not available'
}

// Renders the human-readable "what is being requested" summary instead of a raw JSON dump -
// this is what was previously missing here (unlike the wallet browser extension).
function renderProofRequestSummary(proof) {
  const acpRequest = proof.acpRequest || {}

  return `
    <section class="request-summary">
      <div class="request-summary-header">
        <strong>What is being requested</strong>
        <span>Review these details before sharing a proof.</span>
      </div>
      <dl class="request-summary-grid">
        <div class="request-summary-item">
          <dt>Requested by</dt>
          <dd>${escapeHtml(shortValue(describeProofRequester(proof)))}</dd>
        </div>
        <div class="request-summary-item">
          <dt>Proof holder</dt>
          <dd>${escapeHtml(shortValue(acpRequest.agent))}</dd>
        </div>
        <div class="request-summary-item">
          <dt>Resource owner</dt>
          <dd>${escapeHtml(shortValue(acpRequest.owner))}</dd>
        </div>
        <div class="request-summary-item">
          <dt>Credential issuer</dt>
          <dd>${escapeHtml(shortValue(acpRequest.issuer))}</dd>
        </div>
      </dl>
    </section>
  `
}

function renderTagList(items = []) {
  if (!Array.isArray(items) || items.length === 0) return ''
  return `
    <div class="tag-list">
      ${items.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join('')}
    </div>
  `
}

function credentialTypes(credential) {
  const type = credential?.type
  return Array.isArray(type) ? type.filter((t) => t !== 'VerifiableCredential') : []
}

function renderCredentialOffers(offers) {
  const items = Object.values(offers)
  offerCount.textContent = `${items.length} pending`
  if (items.length === 0) {
    credentialOffers.className = 'stack empty-state'
    credentialOffers.textContent = 'No credential offer yet.'
    return
  }

  credentialOffers.className = 'stack'
  credentialOffers.innerHTML = items.map((offer) => `
    <article class="item">
      <div class="item-header">
        <div>
          <strong>Credential Offer</strong>
          <span class="item-id">${escapeHtml(offer.id)}</span>
        </div>
        <span class="pill pill-warn">Pending</span>
      </div>
      <dl class="meta-grid">
        <div>
          <dt>Issuer</dt>
          <dd>${escapeHtml(shortValue(offer.credential?.issuer?.id || offer.credential?.issuer))}</dd>
        </div>
        <div>
          <dt>Received</dt>
          <dd>${escapeHtml(formatDateTime(offer.createdAt))}</dd>
        </div>
      </dl>
      ${renderTagList(credentialTypes(offer.credential))}
      <details class="details-block">
        <summary>Credential data</summary>
        <pre>${escapeHtml(pretty(offer.credential))}</pre>
      </details>
      <div class="actions">
        <button data-action="accept-credential" data-id="${offer.id}">Accept</button>
        <button class="danger" data-action="decline-credential" data-id="${offer.id}">Decline</button>
      </div>
    </article>
  `).join('')
}

function renderProofRequests(proofs) {
  const items = Object.values(proofs)
  proofCount.textContent = `${items.length} pending`
  if (items.length === 0) {
    proofRequests.className = 'stack empty-state'
    proofRequests.textContent = 'No proof request yet.'
    return
  }

  proofRequests.className = 'stack'
  proofRequests.innerHTML = items.map((proof) => {
    const availableCredentials = Array.isArray(proof.availableCredentials) ? proof.availableCredentials : []
    const options = availableCredentials.map((credential) => `
      <option value="${credential.id}">${escapeHtml(credential.id)}</option>
    `).join('')
    const acceptDisabled = availableCredentials.length === 0 ? 'disabled' : ''

    return `
      <article class="item proof-item">
        <div class="item-header">
          <div>
            <strong>Proof Request</strong>
            <span class="item-id">${escapeHtml(proof.id)}</span>
          </div>
          <span class="pill ${availableCredentials.length > 0 ? 'pill-ok' : 'pill-warn'}">
            ${availableCredentials.length > 0 ? 'Ready' : 'No matching credential'}
          </span>
        </div>

        <div class="proof-hero">
          <div class="proof-hero-item">
            <span class="proof-hero-label">Resource</span>
            <strong class="proof-hero-value">${escapeHtml(displayResource(proof.acpRequest?.target))}</strong>
          </div>
          <div class="proof-hero-item">
            <span class="proof-hero-label">Requested by app</span>
            <strong class="proof-hero-value">${escapeHtml(shortValue(proof.acpRequest?.client))}</strong>
          </div>
        </div>

        ${renderProofRequestSummary(proof)}

        <label class="input-label" for="proof-select-${proof.id}">Credential to share</label>
        <select id="proof-select-${proof.id}" data-proof-select="${proof.id}" ${acceptDisabled}>
          ${options}
        </select>

        <details class="details-block">
          <summary>Request payload</summary>
          <pre>${escapeHtml(pretty(proof.acpRequest))}</pre>
        </details>

        <div class="actions">
          <button data-action="accept-proof" data-id="${proof.id}" ${acceptDisabled}>Share Credential</button>
          <button class="danger" data-action="decline-proof" data-id="${proof.id}">Decline</button>
        </div>
      </article>
    `
  }).join('')
}

function renderActivity(activities) {
  if (activities.length === 0) {
    activityFeed.className = 'activity-feed empty-state'
    activityFeed.textContent = 'Waiting for wallet events.'
    return
  }

  activityFeed.className = 'activity-feed'
  activityFeed.innerHTML = activities.map((activity) => `
    <article class="activity">
      <strong>${escapeHtml(activity.message)}</strong>
      <time>${escapeHtml(formatDateTime(activity.createdAt))}</time>
    </article>
  `).join('')
}

async function refreshState() {
  const state = await api('/api/state')
  readyStatus.textContent = state.ready ? 'Ready' : 'Starting'
  renderCredentialOffers(state.credentialOffers || {})
  renderProofRequests(state.proofRequests || {})
  renderActivity(state.activities || [])
}

invitationForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  formMessage.textContent = 'Connecting...'
  try {
    await api('/api/invitations', {
      method: 'POST',
      body: JSON.stringify({invitationUrl: invitationUrl.value}),
    })
    invitationUrl.value = ''
    formMessage.textContent = 'Invitation submitted.'
    await refreshState()
  } catch (error) {
    formMessage.textContent = error.message
  }
})

const BUSY_LABELS = {
  'accept-credential': 'Accepting...',
  'decline-credential': 'Declining...',
  'accept-proof': 'Sharing credential...',
  'decline-proof': 'Declining...',
}

function showButtonProgress(button) {
  const bar = document.createElement('div')
  bar.className = 'inline-progress'
  button.closest('.actions')?.insertAdjacentElement('afterend', bar)
  return bar
}

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]')
  if (!button) return

  const {action, id} = button.dataset
  const originalLabel = button.textContent
  button.disabled = true
  button.textContent = BUSY_LABELS[action] || 'Working...'
  const progressBar = showButtonProgress(button)
  try {
    if (action === 'accept-credential') {
      await api(`/api/credentials/${id}/accept`, {method: 'POST'})
    }
    if (action === 'decline-credential') {
      await api(`/api/credentials/${id}/decline`, {method: 'POST'})
    }
    if (action === 'accept-proof') {
      const select = document.querySelector(`[data-proof-select="${id}"]`)
      await api(`/api/proofs/${id}/accept`, {
        method: 'POST',
        body: JSON.stringify({credentialRecordId: select.value}),
      })
    }
    if (action === 'decline-proof') {
      await api(`/api/proofs/${id}/decline`, {method: 'POST'})
    }
    await refreshState()
  } catch (error) {
    formMessage.textContent = error.message
  } finally {
    progressBar.remove()
    button.disabled = false
    button.textContent = originalLabel
  }
})

refreshState()
setInterval(refreshState, 2000)
