const ALLOWED_APP_ORIGINS = new Set([
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://localhost:8081',
  'http://127.0.0.1:8081',
  'http://localhost:8082',
  'http://127.0.0.1:8082',
])

const INVITATION_URL_KEY = 'launchedInvitationUrl'
const INVITATION_AUTO_CONNECT_KEY = 'launchedInvitationAutoConnect'

function isAllowedSenderUrl(senderUrl) {
  try {
    return ALLOWED_APP_ORIGINS.has(new URL(senderUrl).origin)
  } catch (error) {
    return false
  }
}

async function openWalletPopup(invitationUrl, autoConnect) {
  await chrome.storage.local.set({
    [INVITATION_URL_KEY]: invitationUrl,
    [INVITATION_AUTO_CONNECT_KEY]: autoConnect,
  })

  await chrome.action.openPopup()
}

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (message?.type !== 'open-wallet-popup') return

  if (!isAllowedSenderUrl(sender.url)) {
    sendResponse({ok: false, error: 'Sender not allowed.'})
    return
  }

  if (typeof message.invitationUrl !== 'string' || message.invitationUrl.length === 0) {
    sendResponse({ok: false, error: 'Invitation URL is required.'})
    return
  }

  void openWalletPopup(message.invitationUrl, message.autoConnect !== false)
    .then(() => {
      sendResponse({ok: true})
    })
    .catch((error) => {
      sendResponse({ok: false, error: error.message})
    })

  return true
})
