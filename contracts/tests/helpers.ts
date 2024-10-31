import { mapGet, rov, varGet } from "@clarigen/test";
import { project, accounts } from "./clarigen-types";
import { cvToValue, projectFactory, projectErrors } from "@clarigen/core";
import { poxAddressToTuple, poxAddressToBtcAddress } from "@stacks/stacking";
import { c32ToB58 } from "c32check";
import {
  AddressHashMode,
  AddressVersion,
  addressFromPublicKeys,
  addressToString,
  bufferCV,
  createStacksPublicKey,
  tupleCV,
} from "@stacks/transactions";
import * as secp from "@noble/secp256k1";
import { hex } from "@scure/base";

export const contracts = projectFactory(project, "simnet");

export const deployer = accounts.deployer.address;
export const alice = accounts.wallet_1.address;
export const bob = accounts.wallet_2.address;
export const charlie = accounts.wallet_3.address;

export const registry = contracts.sbtcRegistry;
export const deposit = contracts.sbtcDeposit;
export const signers = contracts.sbtcBootstrapSigners;
export const withdrawal = contracts.sbtcWithdrawal;
export const token = contracts.sbtcToken;

export const controllerId = `${accounts.deployer.address}.controller`;

const _errors = projectErrors(project);

export const errors = {
  registry: _errors.sbtcRegistry,
  deposit: _errors.sbtcDeposit,
  signers: _errors.sbtcBootstrapSigners,
  withdrawal: _errors.sbtcWithdrawal,
  token: _errors.sbtcToken,
};

export function getLastWithdrawalRequestId() {
  return varGet(
    registry.identifier,
    registry.variables.lastWithdrawalRequestId
  );
}

export function getWithdrawalRequest(id: number | bigint) {
  return mapGet(registry.identifier, registry.maps.withdrawalRequests, id);
}

export function currentSignerAddr() {
  return rov(registry.getCurrentSignerPrincipal());
}

/**
 * Helper function to convert a BTC address string to a PoX address
 * in the "JS Native" format
 */
export function btcAddressToPoxAddress(addr: string): {
  version: Uint8Array;
  hashbytes: Uint8Array;
} {
  const cv = poxAddressToTuple(addr);
  return cvToValue(cv);
}

/**
 * Convert a STX address string to a BTC address.
 * Mainly a helper function for generating BTC addresses.
 */
export function stxAddrToBtcAddr(stxAddr: string, version?: number) {
  return c32ToB58(stxAddr, version);
}

/**
 * Helper function to convert a PoX address in the "JS Native" format
 * to a BTC address string
 */
export function poxAddrToBtcAddress(poxAddr: {
  version: Uint8Array;
  hashbytes: Uint8Array;
}) {
  const cv = tupleCV({
    version: bufferCV(poxAddr.version),
    hashbytes: bufferCV(poxAddr.hashbytes),
  });
  return poxAddressToBtcAddress(cv, "mainnet");
}

/**
 * Convert a STX address (string) to a pox address
 */
export function stxAddressToPoxAddress(stxAddr: string) {
  return btcAddressToPoxAddress(stxAddrToBtcAddr(stxAddr, 0));
}

export const { randomPrivateKey } = secp.utils;

/**
 * Get a random public key
 */
export function randomPublicKey() {
  return secp.getPublicKey(randomPrivateKey(), true);
}

/**
 * Generate a list of random public keys
 */
export function randomPublicKeys(n = 15) {
  return Array.from({ length: n }, () => randomPublicKey());
}

/**
 * Given a list of public keys and a threshold,
 * construct a multisig Stacks principal
 */
export function constructMultisigAddress(
  pubkeys: Uint8Array[],
  m: number | bigint,
  isTestnet = true
) {
  return addressToString(
    addressFromPublicKeys(
      isTestnet
        ? AddressVersion.TestnetMultiSig
        : AddressVersion.MainnetMultiSig,
      AddressHashMode.SerializeP2SH,
      Number(m),
      pubkeys.map((k) => createStacksPublicKey(hex.encode(k)))
    )
  );
}

export function getCurrentBurnInfo() {
  if (simnet.blockHeight === 1) {
    simnet.mineEmptyBlocks(1);
  }
  const burnHeight = simnet.blockHeight - 1;
  const burnHash = rov(deposit.getBurnHeader(burnHeight));
  if (burnHash === null) {
    throw new Error("No burn header found for current height");
  }
  return { burnHeight: burnHeight, burnHash };
}
