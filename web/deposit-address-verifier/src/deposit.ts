import * as btc from "@scure/btc-signer";
import { PubT, validatePubkey } from "@scure/btc-signer/utils.js";
import {
  MAINNET,
  REGTEST,
  SbtcApiClientMainnet,
  SbtcApiClientTestnet,
  UNSPENDABLE_PUB,
  buildSbtcDepositAddress,
  buildSbtcDepositScript,
} from "sbtc";

export type NetworkName = "mainnet" | "testnet";

export const SBTC_DEPLOYERS: Record<NetworkName, string> = {
  mainnet: "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4",
  testnet: "SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1",
};

interface ComputeDepositBase {
  network: NetworkName;
  recipient: string;
  maxFee: number;
  signersPublicKey: string;
}

export type ComputeDepositInput = ComputeDepositBase &
  (
    | {
        reclaimPublicKey: string;
        lockTime: number;
        reclaimScript?: never;
      }
    | {
        reclaimScript: string;
        reclaimPublicKey?: never;
        lockTime?: never;
      }
  );

export interface DepositResult {
  address: string;
  depositScript: string;
  reclaimScript: string;
}

export function normalizeHex(value: string): string {
  return value.trim().replace(/^0x/i, "").toLowerCase();
}

export function normalizeXOnlyPublicKey(value: string): string {
  const key = normalizeHex(value);
  if (!/^(?:[0-9a-f]{64}|(?:02|03)[0-9a-f]{64})$/.test(key)) {
    throw new Error("Enter a 32-byte x-only or 33-byte compressed public key in hex.");
  }
  const xOnly = key.length === 66 ? key.slice(2) : key;
  try {
    validatePubkey(hexToBytes(xOnly), PubT.schnorr);
  } catch {
    throw new Error("Enter a valid secp256k1 public key.");
  }
  return xOnly;
}

export function hexToBytes(value: string): Uint8Array {
  const hex = normalizeHex(value);
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) {
    throw new Error("Enter a complete, even-length hexadecimal script.");
  }
  return Uint8Array.from(hex.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function scriptToAsm(script: string): string {
  try {
    const bytes = hexToBytes(script);
    const operations: string[] = [];
    let offset = 0;

    const readLength = (byteCount: number): number => {
      if (offset + byteCount > bytes.length) throw new Error("Truncated push length");
      let length = 0;
      for (let index = 0; index < byteCount; index += 1) {
        length += bytes[offset + index]! * 2 ** (8 * index);
      }
      offset += byteCount;
      return length;
    };

    const readPush = (length: number): void => {
      if (offset + length > bytes.length) throw new Error("Truncated push data");
      operations.push(bytesToHex(bytes.slice(offset, offset + length)));
      offset += length;
    };

    while (offset < bytes.length) {
      const opcode = bytes[offset]!;
      offset += 1;

      if (opcode >= 1 && opcode <= 75) {
        operations.push(`OP_PUSHBYTES_${opcode}`);
        readPush(opcode);
        continue;
      }
      if (opcode === btc.OP.PUSHDATA1) {
        operations.push("OP_PUSHDATA1");
        readPush(readLength(1));
        continue;
      }
      if (opcode === btc.OP.PUSHDATA2) {
        operations.push("OP_PUSHDATA2");
        readPush(readLength(2));
        continue;
      }
      if (opcode === btc.OP.PUSHDATA4) {
        operations.push("OP_PUSHDATA4");
        readPush(readLength(4));
        continue;
      }

      const name = Object.entries(btc.OP).find(([, value]) => value === opcode)?.[0];
      if (!name) throw new Error("Unknown opcode");
      operations.push(name.startsWith("OP_") ? name : `OP_${name}`);
    }

    return operations.join(" ");
  } catch {
    return "Unable to decode script";
  }
}

export function computeDepositAddress(input: ComputeDepositInput): DepositResult {
  const signersPublicKey = normalizeXOnlyPublicKey(input.signersPublicKey);
  const network = input.network === "mainnet" ? MAINNET : REGTEST;
  const recipient = input.recipient.trim();
  const expectedPrefix = input.network === "mainnet" ? /^(SP|SM)/ : /^(ST|SN)/;
  if (!expectedPrefix.test(recipient)) {
    throw new Error(`Enter a ${input.network} Stacks recipient.`);
  }
  // The SDK checks the address checksum, but splits contract principals at
  // periods without validating the name or rejecting trailing components.
  if (!/^(?:SP|SM|ST|SN)[0-9A-Z]+(?:\.[a-zA-Z][a-zA-Z0-9_-]{0,39})?$/.test(recipient)) {
    throw new Error("Enter a valid Stacks principal, including a valid contract name if supplied.");
  }
  if (!Number.isSafeInteger(input.maxFee) || input.maxFee < 0) {
    throw new Error("Maximum fee must be a non-negative whole number.");
  }

  if (input.reclaimScript !== undefined) {
    const reclaimScript = hexToBytes(input.reclaimScript);
    const depositScript = buildSbtcDepositScript({
      maxSignerFee: input.maxFee,
      stacksAddress: recipient,
      signersPublicKey,
    });
    const output = btc.p2tr(
      UNSPENDABLE_PUB,
      [{ script: depositScript }, { script: reclaimScript }],
      network,
      true,
    );
    if (!output.address) throw new Error("The Taproot deposit address could not be constructed.");
    return {
      address: output.address,
      depositScript: bytesToHex(depositScript),
      reclaimScript: bytesToHex(reclaimScript),
    };
  }

  if (!input.reclaimPublicKey) throw new Error("Enter a reclaim public key.");
  if (!Number.isInteger(input.lockTime) || input.lockTime < 0 || input.lockTime > 65_535) {
    throw new Error("Lock time must be a whole number from 0 through 65,535 blocks.");
  }
  const result = buildSbtcDepositAddress({
    network,
    stacksAddress: recipient,
    signersPublicKey,
    maxSignerFee: input.maxFee,
    reclaimLockTime: input.lockTime,
    reclaimPublicKey: normalizeXOnlyPublicKey(input.reclaimPublicKey),
  });
  return {
    address: result.address,
    depositScript: result.depositScript,
    reclaimScript: result.reclaimScript,
  };
}

export async function fetchSignersPublicKey(
  network: NetworkName,
  stacksApiUrl: string,
): Promise<string> {
  const config = {
    stxApiUrl: stacksApiUrl.trim().replace(/\/$/, ""),
    sbtcContract: SBTC_DEPLOYERS[network],
  };
  const client =
    network === "mainnet" ? new SbtcApiClientMainnet(config) : new SbtcApiClientTestnet(config);
  return normalizeXOnlyPublicKey(await client.fetchSignersPublicKey());
}

export function findWalletValues(
  addresses: Array<{ address: string; publicKey: string; symbol?: string; purpose?: string }>,
  network: NetworkName,
): { recipient: string; reclaimPublicKey: string } {
  const stacksPrefix = network === "mainnet" ? /^(SP|SM)/ : /^(ST|SN)/;
  const bitcoinPrefixes = network === "mainnet" ? ["bc1q"] : ["tb1q", "bcrt1q"];
  const recipient = addresses.find((entry) => stacksPrefix.test(entry.address));
  const isP2wpkh = (entry: (typeof addresses)[number]) =>
    bitcoinPrefixes.some((prefix) => entry.address.toLowerCase().startsWith(prefix));
  const payment =
    addresses.find((entry) => entry.purpose === "payment" && isP2wpkh(entry)) ??
    addresses.find(isP2wpkh);

  if (!recipient) throw new Error(`The wallet did not return a ${network} Stacks address.`);
  if (!payment?.publicKey) {
    throw new Error(`The wallet did not return a ${network} P2WPKH address and public key.`);
  }
  return {
    recipient: recipient.address,
    reclaimPublicKey: normalizeXOnlyPublicKey(payment.publicKey),
  };
}
