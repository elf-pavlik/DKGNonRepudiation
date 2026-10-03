const API_BASE = 'http://localhost:3007'

const readyStatus = document.querySelector('#readyStatus')
const walletUpdatedAt = document.querySelector('#walletUpdatedAt')
const walletOverview = document.querySelector('#walletOverview')
const invitationForm = document.querySelector('#invitationForm')
const invitationUrl = document.querySelector('#invitationUrl')
const requestCredentialButton = document.querySelector('#requestCredentialButton')
const message = document.querySelector('#message')
const credentialCount = document.querySelector('#credentialCount')
const pendingCount = document.querySelector('#pendingCount')
const activityCount = document.querySelector('#activityCount')
const credentials = document.querySelector('#credentials')
const pending = document.querySelector('#pending')
const activityFeed = document.querySelector('#activityFeed')
const LAUNCHED_INVITATION_URL_KEY = 'launchedInvitationUrl'
const LAUNCHED_INVITATION_AUTO_CONNECT_KEY = 'launchedInvitationAutoConnect'
const launchParams = new URLSearchParams(window.location.search)
const launchedInvitationUrl = launchParams.get('invitationUrl')
const shouldAutoConnectInvitation = launchParams.get('autoConnect') === '1'
let hasHandledLaunchedInvitation = false

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {'Content-Type': 'application/json'},
    ...options,
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || 'Request failed')
  return data
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function pretty(value) {
  return JSON.stringify(value, null, 2)
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
        <div class="request-summary-item">
          <dt>Proof creator</dt>
          <dd>${escapeHtml(shortValue(acpRequest.creator))}</dd>
        </div>
      </dl>
    </section>
  `
}

function credentialTitle(credentialOption) {
  const types = Array.isArray(credentialOption.summary?.types) ? credentialOption.summary.types : []
  return types[0] || credentialOption.type || 'Credential'
}

function credentialSubtitle(credentialOption) {
  const parts = []
  const descriptors = Array.isArray(credentialOption.descriptors) ? credentialOption.descriptors : []
  if (credentialOption.summary?.issuer) parts.push(shortValue(credentialOption.summary.issuer))
  if (descriptors.length > 0) {
    parts.push(descriptors.map((descriptor) => descriptor.name || descriptor.id).join(', '))
  }
  return parts.join(' • ') || credentialOption.id
}

function renderTagList(items = []) {
  if (!Array.isArray(items) || items.length === 0) return ''
  return `
    <div class="tag-list">
      ${items.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join('')}
    </div>
  `
}

function renderWalletOverview(state) {
  const currentConnection = state.currentConnection || {}
  const stats = state.stats || {}

  walletOverview.className = 'meta-grid overview-grid'
  walletOverview.innerHTML = `
    <div>
      <dt>Wallet DID</dt>
      <dd class="mono">${escapeHtml(shortValue(state.did))}</dd>
    </div>
    <div>
      <dt>Connection</dt>
      <dd>${escapeHtml(currentConnection.label || shortValue(currentConnection.invitationDid || currentConnection.id))}</dd>
    </div>
    <div>
      <dt>Stored</dt>
      <dd>${escapeHtml(String(stats.credentials ?? 0))} credentials</dd>
    </div>
    <div>
      <dt>Pending</dt>
      <dd>${escapeHtml(String((stats.pendingOffers ?? 0) + (stats.pendingProofs ?? 0)))} actions</dd>
    </div>
  `
}

function renderCredentialOffers(offers) {
  return offers.map((offer) => `
    <article class="item">
      <div class="item-header">
        <div>
          <strong>Credential Offer</strong>
          <small>${escapeHtml(offer.credentialId || offer.recordId || offer.id)}</small>
        </div>
        <span class="pill">Pending</span>
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
      ${renderTagList(Array.isArray(offer.credential?.type) ? offer.credential.type.filter((type) => type !== 'VerifiableCredential') : [])}
      <details class="details-block">
        <summary>Credential data</summary>
        <pre>${escapeHtml(pretty(offer.credential))}</pre>
      </details>
      <div class="actions">
        <button data-action="accept-credential" data-id="${offer.recordId || offer.id}">Accept</button>
        <button class="danger" data-action="decline-credential" data-id="${offer.recordId || offer.id}">Decline</button>
      </div>
    </article>
  `)
}

function renderProofRequests(proofs) {
  return proofs.map((proof) => {
    const availableCredentials = Array.isArray(proof.availableCredentials) ? proof.availableCredentials : []
    const isLoadingCredentials = proof.isLoadingCredentials === true
    const credentialsLoadError = proof.credentialsLoadError
    const options = availableCredentials.map((credential) => `
      <option value="${credential.id}">
        ${escapeHtml(credentialTitle(credential))} - ${escapeHtml(credentialSubtitle(credential))}
      </option>
    `).join('')

    const credentialCards = availableCredentials.map((credential) => {
      const descriptors = Array.isArray(credential.descriptors) ? credential.descriptors : []

      return `
      <article class="credential-card">
        <div class="credential-card-header">
          <strong>${escapeHtml(credentialTitle(credential))}</strong>
          <span class="item-id">${escapeHtml(credential.id)}</span>
        </div>
        <p class="supporting-text">${escapeHtml(credentialSubtitle(credential))}</p>
        <div class="tag-list">
          ${descriptors.map((descriptor) => `<span class="tag">${escapeHtml(descriptor.name || descriptor.id)}</span>`).join('')}
        </div>
      <details class="details-block">
        <summary>Credential preview</summary>
          <pre>${escapeHtml(pretty(credential.credential))}</pre>
        </details>
      </article>
    `
    }).join('')

    const acceptDisabled = isLoadingCredentials || availableCredentials.length === 0 ? 'disabled' : ''
    const requestType = Array.isArray(proof.acpRequest?.type) ? proof.acpRequest.type.join(', ') : proof.acpRequest?.type
    const pillClass = isLoadingCredentials ? 'pill-warn' : (proof.areRequirementsSatisfied ? 'pill-ok' : 'pill-warn')
    const pillLabel = isLoadingCredentials ? 'Checking wallet' : (proof.areRequirementsSatisfied ? 'Ready' : 'Needs review')

    return `
      <article class="item proof-item">
        <div class="item-header">
          <div>
            <strong>Proof Request</strong>
            <small>${proof.connection?.label || proof.connection?.invitationDid || proof.id}</small>
          </div>
          <span class="pill ${pillClass}">
            ${pillLabel}
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

        <dl class="meta-grid">
          <div>
            <dt>Request Type</dt>
            <dd>${escapeHtml(requestType || 'ACPContext')}</dd>
          </div>
          <div>
            <dt>Received</dt>
            <dd>${escapeHtml(formatDateTime(proof.createdAt))}</dd>
          </div>
          <div>
            <dt>Matches</dt>
            <dd>${escapeHtml(String(availableCredentials.length))} credentials</dd>
          </div>
        </dl>

        <details class="details-block" open>
          <summary>Matching credentials</summary>
          ${isLoadingCredentials ? `
            <p class="empty-copy">Checking wallet credentials for this request...</p>
          ` : credentialsLoadError ? `
            <p class="empty-copy">${escapeHtml(credentialsLoadError)}</p>
          ` : availableCredentials.length > 0 ? `
            <label class="input-label" for="proof-select-${proof.id}">Credential to share</label>
            <select id="proof-select-${proof.id}" data-proof-select="${proof.id}">
              ${options}
            </select>
            <div class="credential-list">
              ${credentialCards}
            </div>
          ` : `
            <p class="empty-copy">No matching credential found for this request.</p>
          `}
        </details>

        <details class="details-block">
          <summary>Request payload</summary>
          <pre>${escapeHtml(pretty({
            acpRequest: proof.acpRequest,
            requirements: proof.requirements,
          }))}</pre>
        </details>

        <div class="actions">
          <button data-action="accept-proof" data-id="${proof.id}" ${acceptDisabled}>Accept</button>
          <button class="danger" data-action="decline-proof" data-id="${proof.id}">Decline</button>
        </div>
      </article>
    `
  })
}

function renderStoredCredentials(storedCredentials) {
  credentialCount.textContent = `${storedCredentials.length} stored`

  if (storedCredentials.length === 0) {
    credentials.className = 'empty-state'
    credentials.textContent = 'No stored credential yet.'
    return
  }

  credentials.className = 'stack'
  credentials.innerHTML = storedCredentials.map((record) => `
    <article class="item">
      <div class="item-header">
        <div>
          <strong>${escapeHtml(record.types?.[0] || 'Credential')}</strong>
          <small>${escapeHtml(record.credentialId || record.id)}</small>
        </div>
        <span class="pill pill-ok">Stored</span>
      </div>
      <dl class="meta-grid">
        <div>
          <dt>Issuer</dt>
          <dd>${escapeHtml(shortValue(record.issuer))}</dd>
        </div>
        <div>
          <dt>Subject</dt>
          <dd class="mono">${escapeHtml(shortValue(record.subjectId))}</dd>
        </div>
        <div>
          <dt>Stored At</dt>
          <dd>${escapeHtml(formatDateTime(record.createdAt))}</dd>
        </div>
        <div>
          <dt>Record</dt>
          <dd class="mono">${escapeHtml(shortValue(record.recordId || record.id))}</dd>
        </div>
      </dl>
      ${renderTagList(record.types || [])}
      <details class="details-block">
        <summary>Credential data</summary>
        <pre>${escapeHtml(pretty(record.credential))}</pre>
      </details>
    </article>
  `).join('')
}

function renderActivity(activities) {
  activityCount.textContent = `${activities.length} events`

  if (activities.length === 0) {
    activityFeed.className = 'empty-state'
    activityFeed.textContent = 'Waiting for wallet events.'
    return
  }

  activityFeed.className = 'stack'
  activityFeed.innerHTML = activities.slice(0, 12).map((activity) => `
    <article class="item activity-item">
      <div class="item-header">
        <div>
          <strong>${escapeHtml(activity.message)}</strong>
          <small>${escapeHtml(formatDateTime(activity.createdAt))}</small>
        </div>
        <span class="tag">${escapeHtml(activity.type || 'event')}</span>
      </div>
      ${activity.details ? `
        <details class="details-block">
          <summary>Details</summary>
          <pre>${escapeHtml(pretty(activity.details))}</pre>
        </details>
      ` : ''}
    </article>
  `).join('')
}

async function submitInvitation(invitation) {
  await api('/api/invitations', {
    method: 'POST',
    body: JSON.stringify({invitationUrl: invitation}),
  })
}

async function connectInvitation(invitation, successMessage = 'Invitation submitted.') {
  message.textContent = 'Connecting...'
  await submitInvitation(invitation)
  invitationUrl.value = ''
  message.textContent = successMessage
  await refresh()
}

function clearLaunchParams() {
  const cleanUrl = `${window.location.pathname}${window.location.hash || ''}`
  window.history.replaceState(null, document.title, cleanUrl)
}

async function readStoredLaunchInvitation() {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return null

  const values = await chrome.storage.local.get([
    LAUNCHED_INVITATION_URL_KEY,
    LAUNCHED_INVITATION_AUTO_CONNECT_KEY,
  ])

  if (!values[LAUNCHED_INVITATION_URL_KEY]) return null

  return {
    invitationUrl: values[LAUNCHED_INVITATION_URL_KEY],
    autoConnect: values[LAUNCHED_INVITATION_AUTO_CONNECT_KEY] !== false,
    source: 'storage',
  }
}

async function clearStoredLaunchInvitation() {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return

  await chrome.storage.local.remove([
    LAUNCHED_INVITATION_URL_KEY,
    LAUNCHED_INVITATION_AUTO_CONNECT_KEY,
  ])
}

async function getLaunchedInvitation() {
  if (launchedInvitationUrl) {
    return {
      invitationUrl: launchedInvitationUrl,
      autoConnect: shouldAutoConnectInvitation,
      source: 'query',
    }
  }

  return readStoredLaunchInvitation()
}

async function clearLaunchedInvitation(source) {
  if (source === 'query') clearLaunchParams()
  await clearStoredLaunchInvitation()
}

async function handleLaunchedInvitation() {
  if (hasHandledLaunchedInvitation) return

  const launchedInvitation = await getLaunchedInvitation()
  if (!launchedInvitation) return

  hasHandledLaunchedInvitation = true
  invitationUrl.value = launchedInvitation.invitationUrl

  if (!launchedInvitation.autoConnect) {
    message.textContent = 'Invitation received from the app.'
    await clearLaunchedInvitation(launchedInvitation.source)
    return
  }

  try {
    await connectInvitation(launchedInvitation.invitationUrl, 'Invitation received from the app.')
  } catch (error) {
    message.textContent = `Automatic connection failed: ${error.message}`
  } finally {
    await clearLaunchedInvitation(launchedInvitation.source)
  }
}

async function refresh() {
  const state = await api('/api/state')
  readyStatus.textContent = state.ready ? 'Ready' : 'Starting'
  requestCredentialButton.disabled = !state.ready
  walletUpdatedAt.textContent = state.updatedAt ? formatDateTime(state.updatedAt) : 'Waiting'
  renderWalletOverview(state)

  const offers = Object.entries(state.credentialOffers || {}).map(([recordId, offer]) => ({
    ...offer,
    id: offer?.id || recordId,
    recordId: offer?.recordId || recordId,
    credentialId: offer?.credentialId || offer?.credential?.id,
  }))
  const proofs = Object.entries(state.proofRequests || {}).map(([proofRecordId, proof]) => ({
    ...proof,
    id: proof?.id || proofRecordId,
  }))
  const storedCredentials = Array.isArray(state.credentials) ? state.credentials : []
  renderStoredCredentials(storedCredentials)
  renderActivity(Array.isArray(state.activities) ? state.activities : [])

  const sections = [
    ...renderCredentialOffers(offers),
    ...renderProofRequests(proofs),
  ]
  pendingCount.textContent = `${sections.length} pending`

  if (sections.length === 0) {
    pending.className = 'empty-state'
    pending.textContent = state.ready ? 'No pending wallet actions.' : 'Wallet is starting.'
    return
  }

  pending.className = 'stack'
  pending.innerHTML = sections.join('')

  return state
}

invitationForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  try {
    await connectInvitation(invitationUrl.value)
  } catch (error) {
    message.textContent = error.message
  }
})

requestCredentialButton.addEventListener('click', async () => {
  requestCredentialButton.disabled = true
  message.textContent = 'Requesting credential...'

  try {
    await api('/api/issuer/request-credential', {
      method: 'POST',
      body: JSON.stringify({}),
    })
    message.textContent = 'Credential request sent. Wait for the issuer offer.'
    await refresh()
  } catch (error) {
    message.textContent = error.message
  } finally {
    requestCredentialButton.disabled = false
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
  message.textContent = ''

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
        body: JSON.stringify({credentialRecordId: select?.value}),
      })
    }

    if (action === 'decline-proof') {
      await api(`/api/proofs/${id}/decline`, {method: 'POST'})
    }

    await refresh()
  } catch (error) {
    message.textContent = error.message
  } finally {
    progressBar.remove()
    button.disabled = false
    button.textContent = originalLabel
  }
})

refresh()
  .then(() => handleLaunchedInvitation())
  .catch((error) => {
    message.textContent = error.message
  })
setInterval(() => {
  refresh().catch((error) => {
    message.textContent = error.message
  })
}, 2000)
