import {
  computeDepositAddress,
  fetchSignersPublicKey,
  findWalletValues,
  normalizeXOnlyPublicKey,
  scriptToAsm,
  type NetworkName,
} from "./deposit";
import { connectWallet } from "./wallet";

function bindVerifier(): void {
  const form = document.querySelector<HTMLFormElement>("#verifier-form")!;
  const advancedFields = document.querySelector<HTMLElement>("#advanced-fields")!;
  const advancedToggle = document.querySelector<HTMLButtonElement>("#advanced-toggle")!;
  const resultPanel = document.querySelector<HTMLElement>(".result-panel")!;
  const network = document.querySelector<HTMLSelectElement>("#network")!;
  const recipient = document.querySelector<HTMLInputElement>("#recipient")!;
  const reclaimKey = document.querySelector<HTMLInputElement>("#reclaim-key")!;
  const lockTime = document.querySelector<HTMLInputElement>("#lock-time")!;
  const maxFee = document.querySelector<HTMLInputElement>("#max-fee")!;
  const stacksApi = document.querySelector<HTMLInputElement>("#stacks-api")!;
  const signersKey = document.querySelector<HTMLInputElement>("#signers-key")!;
  const reclaimScript = document.querySelector<HTMLTextAreaElement>("#reclaim-script")!;
  const error = document.querySelector<HTMLParagraphElement>("#form-error")!;
  const compute = document.querySelector<HTMLButtonElement>("#compute")!;
  const connectButton = document.querySelector<HTMLButtonElement>("#connect-wallet")!;
  let active = true;
  let revision = 0;
  const invalidateResult = () => {
    revision += 1;
    resultPanel.querySelector<HTMLElement>("#result")!.hidden = true;
    resultPanel.querySelector<HTMLElement>("#empty-result")!.hidden = false;
    error.hidden = true;
    compute.disabled = false;
    compute.firstElementChild!.textContent = "Compute deposit address";
  };
  form.addEventListener("input", invalidateResult);
  form.addEventListener("change", invalidateResult);

  const setAdvancedExpanded = (expanded: boolean): void => {
    advancedToggle.setAttribute("aria-expanded", String(expanded));
    advancedToggle.lastElementChild!.textContent = expanded ? "−" : "＋";
    advancedFields.hidden = !expanded;
  };
  advancedToggle.addEventListener("click", () =>
    setAdvancedExpanded(Boolean(advancedFields.hidden)),
  );

  const reportFormValidity = (): boolean => {
    if (form.checkValidity()) return true;
    const invalidFields = form.querySelectorAll<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >("input:invalid, select:invalid, textarea:invalid");
    if (Array.from(invalidFields).some((field) => advancedFields.contains(field))) {
      setAdvancedExpanded(true);
    }
    const firstInvalid = invalidFields[0];
    if (firstInvalid) showError(error, new Error(firstInvalid.validationMessage));
    form.reportValidity();
    return false;
  };

  document.querySelectorAll<HTMLInputElement>('input[name="reclaimMode"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      const scriptMode = radio.value === "script" && radio.checked;
      if (!radio.checked) return;
      document.querySelector<HTMLElement>("#public-key-fields")!.hidden = scriptMode;
      document.querySelector<HTMLElement>("#advanced-lock-time-field")!.hidden = scriptMode;
      document.querySelector<HTMLElement>("#script-field")!.hidden = !scriptMode;
      reclaimKey.required = !scriptMode;
      lockTime.required = !scriptMode;
      reclaimScript.required = scriptMode;
      reclaimKey.disabled = scriptMode;
      lockTime.disabled = scriptMode;
      reclaimScript.disabled = !scriptMode;
    });
  });

  network.addEventListener("change", () => {
    const isMainnet = network.value === "mainnet";
    stacksApi.value = isMainnet ? "https://api.hiro.so" : "https://api.testnet.hiro.so";
    recipient.placeholder = isMainnet ? "SP… or SM…" : "ST… or SN…";
  });

  window.addEventListener("pagehide", () => {
    active = false;
    revision += 1;
  });
  window.addEventListener("pageshow", () => {
    active = true;
    invalidateResult();
  });

  connectButton.addEventListener("click", async () => {
    error.hidden = true;
    connectButton.disabled = true;
    connectButton.textContent = "Opening wallet…";
    try {
      const addresses = await connectWallet();
      if (!active) return;
      const values = findWalletValues(addresses, network.value as NetworkName);
      invalidateResult();
      recipient.value = values.recipient;
      reclaimKey.value = values.reclaimPublicKey;
      document.querySelector("#wallet-status")!.textContent = "Wallet details added";
      connectButton.textContent = "Reconnect";
    } catch (cause) {
      if (!active) return;
      showError(error, cause);
      connectButton.textContent = "Connect wallet";
    } finally {
      connectButton.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    invalidateResult();
    if (!reportFormValidity()) return;
    const submittedRevision = revision;
    const isCurrent = () => active && revision === submittedRevision;
    compute.disabled = true;
    compute.firstElementChild!.textContent = signersKey.value.trim()
      ? "Computing…"
      : "Fetching signer key…";

    try {
      const selectedNetwork = network.value as NetworkName;
      const scriptMode =
        form.querySelector<HTMLInputElement>('input[name="reclaimMode"]:checked')!.value ===
        "script";
      const inputs = {
        network: selectedNetwork,
        recipient: recipient.value,
        maxFee: parseInteger(maxFee.value, "Maximum fee"),
        ...(scriptMode
          ? { reclaimScript: reclaimScript.value }
          : {
              reclaimPublicKey: reclaimKey.value,
              lockTime: parseInteger(lockTime.value, "Lock time"),
            }),
      };
      const aggregateKey = signersKey.value.trim()
        ? signersKey.value
        : await fetchSignersPublicKey(selectedNetwork, stacksApi.value);
      if (!isCurrent()) return;
      const result = computeDepositAddress({ ...inputs, signersPublicKey: aggregateKey });

      document.querySelector<HTMLElement>("#empty-result")!.hidden = true;
      document.querySelector<HTMLElement>("#result")!.hidden = false;
      document.querySelector("#result-network")!.textContent = selectedNetwork;
      document.querySelector("#deposit-address")!.textContent = result.address;
      document.querySelector("#result-signers-key")!.textContent =
        normalizeXOnlyPublicKey(aggregateKey);
      document.querySelector("#deposit-script")!.textContent = result.depositScript;
      document.querySelector("#result-reclaim-script")!.textContent = result.reclaimScript;
      document.querySelector("#deposit-script-asm")!.textContent = scriptToAsm(
        result.depositScript,
      );
      document.querySelector("#reclaim-script-asm")!.textContent = scriptToAsm(
        result.reclaimScript,
      );
    } catch (cause) {
      if (isCurrent()) showError(error, cause);
    } finally {
      if (isCurrent()) {
        compute.disabled = false;
        compute.firstElementChild!.textContent = "Compute deposit address";
      }
    }
  });

  document.querySelectorAll<HTMLButtonElement>("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.querySelector(`#${button.dataset.copy}`)?.textContent ?? "";
      button.disabled = true;
      try {
        await navigator.clipboard.writeText(target);
        button.textContent = "Copied";
      } catch {
        button.textContent = "Copy failed";
      } finally {
        window.setTimeout(() => {
          button.textContent = "Copy";
          button.disabled = false;
        }, 1400);
      }
    });
  });
}

function parseInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative whole number.`);
  }
  return parsed;
}

function showError(element: HTMLElement, cause: unknown): void {
  element.textContent =
    cause instanceof Error ? cause.message : "Something went wrong. Please check the inputs.";
  element.hidden = false;
}

bindVerifier();
