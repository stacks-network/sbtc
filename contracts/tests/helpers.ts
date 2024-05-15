import { mapGet, varGet } from "@clarigen/test";
import { project, accounts } from "./clarigen-types";
import { cvToValue, projectFactory } from "@clarigen/core";
import { poxAddressToTuple, poxAddressToBtcAddress } from "@stacks/stacking";
import { c32ToB58 } from "c32check";
import { bufferCV, tupleCV } from "@stacks/transactions";

export const contracts = projectFactory(project, "simnet");

export const alice = accounts.wallet_1.address;
export const bob = accounts.wallet_2.address;
export const charlie = accounts.wallet_3.address;

export const registry = contracts.sbtcRegistry;
export const deposit = contracts.sbtcDeposit;
export const signers = contracts.sbtcBootstrapSigners;

export const controllerId = `${accounts.deployer.address}.controller`;

export function getLastWithdrawalRequestId() {
  return varGet(
    registry.identifier,
    registry.variables.lastWithdrawalRequestId
  );
}

export function getWithdrawalRequest(id: number | bigint) {
  return mapGet(registry.identifier, registry.maps.withdrawalRequests, id);
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
