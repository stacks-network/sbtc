import { CoreNodeEventType, cvToValue } from "@clarigen/core";
import { filterEvents, rov, rovOk, txErr, txOk } from "@clarigen/test";
import { describe, expect, test } from "vitest";
import {
  alice,
  bob,
  deployer,
  deposit,
  errors,
  getCurrentBurnInfo,
  getLastWithdrawalRequestId,
  getWithdrawalRequest,
  registry,
  signers,
  stxAddressToPoxAddress,
  token,
  withdrawal,
} from "./helpers";

const alicePoxAddr = stxAddressToPoxAddress(alice);
const bobPoxAddr = stxAddressToPoxAddress(bob);

describe("sBTC registry contract", () => {
  describe("withdrawal requests", () => {
    test("Last request ID is zero", () => {
      const lastId = getLastWithdrawalRequestId();
      expect(lastId).toEqual(0n);
    });

    test("Storing a new withdrawal request", () => {
      const recipient = alicePoxAddr;
      const defaultAmount = 1000n;
      const defaultMaxFee = 10n;
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: defaultAmount + defaultMaxFee,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      expect(rovOk(token.getBalance(alice))).toEqual(
        defaultAmount + defaultMaxFee
      );
      txOk(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: alicePoxAddr,
          maxFee: defaultMaxFee,
        }),
        alice
      );
      const request = getWithdrawalRequest(1n);
      if (!request) {
        throw new Error("Request not stored");
      }
      expect(request.sender).toEqual(alice);
      expect(request.amount).toEqual(defaultAmount);
      expect(request.maxFee).toEqual(10n);
      expect(request.recipient).toEqual(recipient);
      expect(request.blockHeight).toEqual(BigInt(simnet.burnBlockHeight));
      const lastId = getLastWithdrawalRequestId();
      expect(lastId).toEqual(1n);
    });

    test("emitted events when a new withdrawal is stored", () => {
      const recipient = bobPoxAddr;
      const defaultAmount = 1000n;
      const defaultMaxFee = 10n;
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: defaultAmount + defaultMaxFee,
          recipient: bob,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      const receipt = txOk(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: recipient,
          maxFee: defaultMaxFee,
        }),
        bob
      );
      const prints = filterEvents(
        receipt.events,
        CoreNodeEventType.ContractEvent
      );
      expect(prints.length).toEqual(1);
      const [print] = prints;
      const printData = cvToValue<{
        sender: string;
        recipient: { version: Uint8Array; hashbytes: Uint8Array };
        amount: bigint;
        maxFee: bigint;
        blockHeight: bigint;
        topic: string;
      }>(print.data.value);

      const request = getWithdrawalRequest(1n);
      if (!request) {
        throw new Error("Request not stored");
      }
      expect(printData).toStrictEqual({
        sender: bob,
        recipient: recipient,
        amount: defaultAmount,
        maxFee: 10n,
        blockHeight: request.blockHeight,
        topic: "withdrawal-create",
        requestId: 1n,
      });
    });

    test("get-withdrawal-request includes status", () => {
      const defaultAmount = 1000n;
      const defaultMaxFee = 10n;
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: defaultAmount + defaultMaxFee,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      expect(rovOk(token.getBalance(alice))).toEqual(
        defaultAmount + defaultMaxFee
      );
      txOk(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: alicePoxAddr,
          maxFee: defaultMaxFee,
        }),
        alice
      );
      const request = rov(registry.getWithdrawalRequest(1n));
      if (!request) {
        throw new Error("Request not found");
      }
      expect(request.status).toEqual(null);
      expect(request).toEqual({
        sender: alice,
        recipient: alicePoxAddr,
        amount: defaultAmount,
        maxFee: 10n,
        blockHeight: BigInt(2n),
        status: null,
      });
    });
  });
  describe("sBTC bootstrap signer contract", () => {
    test("Rotate keys wrapper correctly", () => {
      expect(rov(registry.getCurrentSignerPrincipal())).toBe(deployer);
      const receipt = txOk(
        signers.rotateKeysWrapper({
          newKeys: [new Uint8Array(33).fill(0), new Uint8Array(33).fill(0)],
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold: 2n,
        }),
        deployer
      );
      expect(receipt.value).toEqual(true);
      expect(rov(registry.getCurrentSignerPrincipal())).toBe(
        "SN3N8ATTRKWKK2N8TTSBNW5CRH2CSV2A0NYF7HHDF"
      );
    });
    test("Rotate keys wrapper incorrect signer key size", () => {
      const receipt = txErr(
        signers.rotateKeysWrapper({
          newKeys: [new Uint8Array(33).fill(0), new Uint8Array(31).fill(0)],
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold: 2n,
        }),
        deployer
      );
      expect(receipt.value).toEqual(errors.signers.ERR_KEY_SIZE_PREFIX + 11n);
    });
    test("Rotate keys wrapper incorrect aggregate key size", () => {
      const receipt = txErr(
        signers.rotateKeysWrapper({
          newKeys: [new Uint8Array(33).fill(0), new Uint8Array(33).fill(0)],
          newAggregatePubkey: new Uint8Array(31).fill(0),
          newSignatureThreshold: 2n,
        }),
        deployer
      );
      expect(receipt.value).toEqual(errors.signers.ERR_KEY_SIZE);
    });
  });
});
