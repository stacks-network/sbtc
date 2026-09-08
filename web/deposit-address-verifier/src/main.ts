import {
  computeDepositAddress,
  fetchSignersPublicKey,
  findWalletValues,
  normalizeXOnlyPublicKey,
  scriptToAsm,
  type NetworkName,
} from './deposit'
import { connectWallet } from './wallet'

const REPOSITORY_URL = 'https://github.com/stacks-sbtc/sbtc'
const BRIDGE_URL = 'https://sbtc.stacks.co/'

const app = document.querySelector<HTMLDivElement>('#app')!
let cleanupVerifier: (() => void) | undefined

function fieldLabel(label: string, description: string, detail?: string): string {
  return `<span class="field-label"><span>${label}${detail ? ` <small>${detail}</small>` : ''}</span><span class="tooltip" tabindex="0" aria-label="${description}" data-tooltip="${description}">?</span></span>`
}

function pageShell(content: string): string {
  return `
    <header class="site-header">
      <a class="brand" href="#/" aria-label="sBTC address constructor home">
        <img src="./icons/sbtc.svg" alt="" aria-hidden="true" />
        <span>sBTC address constructor</span>
      </a>
      <nav aria-label="Primary navigation">
        <a href="#/" data-nav="verify">Construct</a>
        <a href="#/about" data-nav="about">About</a>
        <a href="${REPOSITORY_URL}" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
      </nav>
    </header>
    <main>${content}</main>
    <footer>
      <span>Open-source, client-side verification.</span>
      <span><a href="${REPOSITORY_URL}" target="_blank" rel="noopener noreferrer">Source code</a> · <a href="${BRIDGE_URL}" target="_blank" rel="noopener noreferrer">Official sBTC Bridge</a></span>
    </footer>`
}

function renderVerifier(): void {
  app.innerHTML = pageShell(`
    <section class="intro" aria-labelledby="page-title">
      <h1 id="page-title">Compute an sBTC deposit address</h1>
    </section>

    <section class="workspace">
      <form id="verifier-form" class="panel form-panel" novalidate>
        <div class="wallet-row">
          <div>
            <span class="step-label">Optional</span>
            <strong id="wallet-status">Connect a wallet to fill in your address and public key</strong>
          </div>
          <button class="button button-secondary" id="connect-wallet" type="button">Connect wallet</button>
        </div>

        <div class="divider"></div>

        <label class="field">
          ${fieldLabel('Stacks recipient', 'The Stacks principal that will receive the minted sBTC. It may be a standard principal or a smart contract principal.')}
          <input id="recipient" name="recipient" type="text" placeholder="SP… or SM…" spellcheck="false" autocomplete="off" required />
        </label>

        <div id="public-key-fields">
          <label class="field">
            ${fieldLabel('Reclaim public key', 'The secp256k1 public key controlling the reclaim path after its configured lock time expires. Use a key whose private key you control.', 'x-only or compressed hex')}
            <input id="reclaim-key" name="reclaimKey" type="text" placeholder="02… / 03… / 32-byte x-only key" spellcheck="false" autocomplete="off" required />
          </label>
        </div>

        <button class="advanced-toggle" id="advanced-toggle" type="button" aria-expanded="false" aria-controls="advanced-fields">
          <span>Advanced options</span><span aria-hidden="true">＋</span>
        </button>
        <div id="advanced-fields" class="advanced-fields" hidden>
          <div class="advanced-parameter-grid">
            <label class="field">
              ${fieldLabel('Network', 'Select the sBTC network. Stacks testnet deposits use Bitcoin regtest addresses.')}
              <select id="network" name="network">
                <option value="mainnet" selected>Mainnet</option>
                <option value="testnet">Testnet (Bitcoin regtest)</option>
              </select>
            </label>
            <label class="field">
              ${fieldLabel('Stacks API URL', 'The Stacks API queried for the current signer aggregate public key from the network’s sBTC registry contract.')}
              <input id="stacks-api" name="stacksApi" type="url" value="https://api.hiro.so" spellcheck="false" required />
            </label>
          </div>
          <div class="advanced-parameter-grid">
            <label class="field">
              ${fieldLabel('Maximum L1 sweep fee', 'The most the sBTC signers may deduct for the Bitcoin L1 fee when sweeping this deposit. The official bridge currently uses 80,000 sats.', 'sats')}
              <input id="max-fee" name="maxFee" type="number" value="80000" min="0" step="1" inputmode="numeric" required />
            </label>
            <label class="field" id="advanced-lock-time-field">
              ${fieldLabel('Reclaim lock time', 'The number of Bitcoin blocks that must be mined after the deposit is confirmed before the standard reclaim path can be spent. The official bridge currently uses 950 blocks.', 'blocks')}
              <input id="lock-time" name="lockTime" type="number" value="950" min="0" max="65535" step="1" inputmode="numeric" required />
            </label>
          </div>
          <fieldset class="mode-field">
            <legend><span>Reclaim path</span><span class="tooltip" tabindex="0" aria-label="Choose the standard public-key reclaim path or provide every byte of an advanced reclaim script." data-tooltip="Choose the standard public-key reclaim path or provide every byte of an advanced reclaim script.">?</span></legend>
            <label><input type="radio" name="reclaimMode" value="key" checked /> Public key + lock time</label>
            <label><input type="radio" name="reclaimMode" value="script" /> Complete reclaim script</label>
          </fieldset>
          <label class="field" id="script-field" hidden>
            ${fieldLabel('Complete reclaim script', 'The complete Taproot reclaim leaf in hexadecimal, including its lock-time prefix.', 'hex')}
            <textarea id="reclaim-script" name="reclaimScript" rows="4" placeholder="Include the lock-time prefix…" spellcheck="false"></textarea>
            <small>These exact bytes become the reclaim Taproot leaf. This advanced input is not checked for spendability.</small>
          </label>
          <label class="field">
            ${fieldLabel('Signers’ aggregate public key', 'The current x-only aggregate public key controlled by the sBTC signer set. Supplying it skips the Stacks API request.', 'optional override')}
            <input id="signers-key" name="signersKey" type="text" placeholder="Fetched from the sBTC registry when blank" spellcheck="false" autocomplete="off" />
          </label>
        </div>

        <p class="form-error" id="form-error" role="alert" hidden></p>
        <button class="button button-primary" id="compute" type="submit"><span>Compute deposit address</span><span aria-hidden="true">→</span></button>
      </form>

      <aside class="panel result-panel" aria-live="polite">
        <div id="empty-result" class="empty-result">
          <img class="result-symbol" src="./icons/stx.svg" alt="" aria-hidden="true" />
          <p class="eyebrow">Your result</p>
          <h2>Ready when<br />you are.</h2>
          <p>Each sBTC deposit address is constructed for a specific sender and Stacks recipient. Independently construct the address before sending bitcoin. Connect a wallet to fill in your recipient and reclaim key, or enter both manually.</p>
        </div>
        <div id="result" hidden>
          <div class="result-heading">
            <h2>The deposit address</h2>
            <span class="network-chip" id="result-network"></span>
          </div>
          <div class="deposit-warning" role="alert">
            <span class="deposit-warning-icon" aria-hidden="true">!</span>
            <div>
              <strong>Do not send BTC directly to this address</strong>
              <p>This tool only constructs the address. Unless the deposit is correctly registered in the sBTC system, you will not receive sBTC. <a href="${BRIDGE_URL}" target="_blank" rel="noopener noreferrer">Use the official sBTC Bridge to deposit safely ↗</a></p>
            </div>
          </div>
          <div class="address-box">
            <code id="deposit-address"></code>
            <button class="copy-button" type="button" data-copy="deposit-address">Copy</button>
          </div>
          <details>
            <summary><span>Construction details</span><span class="details-indicator" aria-hidden="true"></span></summary>
            <div class="detail-block"><span>Signers’ aggregate public key</span><code id="result-signers-key"></code></div>
            <div class="detail-block">
              <span>Deposit script ASM</span><code id="deposit-script-asm"></code>
              <span>Deposit script hex</span><code id="deposit-script"></code>
            </div>
            <div class="detail-block">
              <span>Reclaim script ASM</span><code id="reclaim-script-asm"></code>
              <span>Reclaim script hex</span><code id="result-reclaim-script"></code>
            </div>
          </details>
          <div class="result-actions">
            <a class="button button-primary" href="${BRIDGE_URL}" target="_blank" rel="noopener noreferrer">Open the official bridge ↗</a>
          </div>
        </div>
      </aside>
    </section>
  `)

  document.querySelector('[data-nav="verify"]')?.setAttribute('aria-current', 'page')
  bindVerifier()
}

function renderAbout(): void {
  app.innerHTML = pageShell(`
    <article class="about">
      <p class="eyebrow">About this tool</p>
      <h1>Verify the address yourself.</h1>
      <p class="about-lead">This small, open-source website lets you independently reproduce an sBTC deposit address from the same inputs used by the protocol.</p>
      <div class="about-grid">
        <section><span>01</span><h2>What it does</h2><p>It combines a Stacks recipient, the signers’ aggregate public key, a maximum L1 sweep fee, and your reclaim path into a deterministic Bitcoin Taproot address.</p></section>
        <section><span>02</span><h2>What it does not do</h2><p>It does not create, sign, broadcast, or track a deposit transaction. Connecting a wallet only reads public addresses and the public key for its P2WPKH payment address. Address construction happens in your browser. The site never requests a signature or sends a transaction.</p></section>
        <section><span>03</span><h2>Where to deposit</h2><p>Use the <a href="${BRIDGE_URL}" target="_blank" rel="noopener noreferrer">official sBTC Bridge</a> to make an actual deposit. This site is an additional verification tool, not a replacement for the bridge.</p></section>
      </div>
      <div class="about-callout">
        <div><p class="eyebrow">Inspect every step</p><h2>Built in the open.</h2></div>
        <a class="button button-secondary" href="${REPOSITORY_URL}" target="_blank" rel="noopener noreferrer">View the repository ↗</a>
      </div>
    </article>
  `)
  document.querySelector('[data-nav="about"]')?.setAttribute('aria-current', 'page')
}

function bindVerifier(): void {
  const form = document.querySelector<HTMLFormElement>('#verifier-form')!
  const advancedFields = document.querySelector<HTMLElement>('#advanced-fields')!
  const resultPanel = document.querySelector<HTMLElement>('.result-panel')!
  const network = document.querySelector<HTMLSelectElement>('#network')!
  const recipient = document.querySelector<HTMLInputElement>('#recipient')!
  const reclaimKey = document.querySelector<HTMLInputElement>('#reclaim-key')!
  const lockTime = document.querySelector<HTMLInputElement>('#lock-time')!
  const maxFee = document.querySelector<HTMLInputElement>('#max-fee')!
  const stacksApi = document.querySelector<HTMLInputElement>('#stacks-api')!
  const signersKey = document.querySelector<HTMLInputElement>('#signers-key')!
  const reclaimScript = document.querySelector<HTMLTextAreaElement>('#reclaim-script')!
  const error = document.querySelector<HTMLParagraphElement>('#form-error')!
  const compute = document.querySelector<HTMLButtonElement>('#compute')!
  const connectButton = document.querySelector<HTMLButtonElement>('#connect-wallet')!

  document.querySelector('#advanced-toggle')!.addEventListener('click', event => {
    const button = event.currentTarget as HTMLButtonElement
    const expanded = button.getAttribute('aria-expanded') === 'true'
    button.setAttribute('aria-expanded', String(!expanded))
    button.lastElementChild!.textContent = expanded ? '＋' : '−'
    advancedFields.hidden = expanded
  })

  document.querySelectorAll<HTMLInputElement>('input[name="reclaimMode"]').forEach(radio => {
    radio.addEventListener('change', () => {
      const scriptMode = radio.value === 'script' && radio.checked
      if (!radio.checked) return
      document.querySelector<HTMLElement>('#public-key-fields')!.hidden = scriptMode
      document.querySelector<HTMLElement>('#advanced-lock-time-field')!.hidden = scriptMode
      document.querySelector<HTMLElement>('#script-field')!.hidden = !scriptMode
      reclaimKey.required = !scriptMode
      lockTime.required = !scriptMode
      reclaimScript.required = scriptMode
    })
  })

  network.addEventListener('change', () => {
    const isMainnet = network.value === 'mainnet'
    stacksApi.value = isMainnet ? 'https://api.hiro.so' : 'https://api.testnet.hiro.so'
    recipient.placeholder = isMainnet ? 'SP… or SM…' : 'ST… or SN…'
  })

  const syncCollapsedPanelHeight = () => {
    if (window.matchMedia('(max-width: 860px)').matches) {
      resultPanel.style.removeProperty('height')
    } else if (advancedFields.hidden) {
      resultPanel.style.height = `${form.offsetHeight}px`
    }
  }
  const formObserver = new ResizeObserver(syncCollapsedPanelHeight)
  formObserver.observe(form)
  window.addEventListener('resize', syncCollapsedPanelHeight)
  cleanupVerifier = () => {
    formObserver.disconnect()
    window.removeEventListener('resize', syncCollapsedPanelHeight)
  }

  connectButton.addEventListener('click', async () => {
    error.hidden = true
    connectButton.disabled = true
    connectButton.textContent = 'Opening wallet…'
    try {
      const addresses = await connectWallet()
      const values = findWalletValues(addresses, network.value as NetworkName)
      recipient.value = values.recipient
      reclaimKey.value = values.reclaimPublicKey
      document.querySelector('#wallet-status')!.textContent = 'Wallet details added'
      connectButton.textContent = 'Reconnect'
    } catch (cause) {
      showError(error, cause)
      connectButton.textContent = 'Connect wallet'
    } finally {
      connectButton.disabled = false
    }
  })

  form.addEventListener('submit', async event => {
    event.preventDefault()
    error.hidden = true
    if (!form.reportValidity()) return
    compute.disabled = true
    compute.firstElementChild!.textContent = signersKey.value.trim()
      ? 'Computing…'
      : 'Fetching signer key…'

    try {
      const selectedNetwork = network.value as NetworkName
      const aggregateKey = signersKey.value.trim()
        ? signersKey.value
        : await fetchSignersPublicKey(selectedNetwork, stacksApi.value)
      const scriptMode =
        document.querySelector<HTMLInputElement>('input[name="reclaimMode"]:checked')!.value ===
        'script'
      const result = computeDepositAddress({
        network: selectedNetwork,
        recipient: recipient.value,
        maxFee: parseInteger(maxFee.value, 'Maximum fee'),
        signersPublicKey: aggregateKey,
        ...(scriptMode
          ? { reclaimScript: reclaimScript.value }
          : {
              reclaimPublicKey: reclaimKey.value,
              lockTime: parseInteger(lockTime.value, 'Lock time'),
            }),
      })

      document.querySelector<HTMLElement>('#empty-result')!.hidden = true
      document.querySelector<HTMLElement>('#result')!.hidden = false
      document.querySelector('#result-network')!.textContent = selectedNetwork
      document.querySelector('#deposit-address')!.textContent = result.address
      document.querySelector('#result-signers-key')!.textContent =
        normalizeXOnlyPublicKey(aggregateKey)
      document.querySelector('#deposit-script')!.textContent = result.depositScript
      document.querySelector('#result-reclaim-script')!.textContent = result.reclaimScript
      document.querySelector('#deposit-script-asm')!.textContent = scriptToAsm(result.depositScript)
      document.querySelector('#reclaim-script-asm')!.textContent = scriptToAsm(result.reclaimScript)
    } catch (cause) {
      showError(error, cause)
    } finally {
      compute.disabled = false
      compute.firstElementChild!.textContent = 'Compute deposit address'
    }
  })

  document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach(button => {
    button.addEventListener('click', async () => {
      const target = document.querySelector(`#${button.dataset.copy}`)?.textContent ?? ''
      button.disabled = true
      try {
        await navigator.clipboard.writeText(target)
        button.textContent = 'Copied'
      } catch {
        button.textContent = 'Copy failed'
      } finally {
        window.setTimeout(() => {
          button.textContent = 'Copy'
          button.disabled = false
        }, 1400)
      }
    })
  })
}

function parseInteger(value: string, label: string): number {
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative whole number.`)
  }
  return parsed
}

function showError(element: HTMLElement, cause: unknown): void {
  element.textContent = cause instanceof Error ? cause.message : 'Something went wrong. Please check the inputs.'
  element.hidden = false
}

function renderRoute(): void {
  cleanupVerifier?.()
  cleanupVerifier = undefined
  if (window.location.hash === '#/about') renderAbout()
  else renderVerifier()
}

window.addEventListener('hashchange', renderRoute)
renderRoute()
