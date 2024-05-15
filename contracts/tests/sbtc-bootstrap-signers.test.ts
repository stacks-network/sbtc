import {
    alice,
    bob,
    getLastWithdrawalRequestId,
    getWithdrawalRequest,
    registry,
    signers,
    stxAddressToPoxAddress,
  } from "./helpers";
  import { test, expect, describe } from "vitest";
  import { txOk, filterEvents, rov, txErr } from "@clarigen/test";
  import { CoreNodeEventType, cvToValue } from "@clarigen/core";
  
  const alicePoxAddr = stxAddressToPoxAddress(alice);
  const bobPoxAddr = stxAddressToPoxAddress(bob);
  
  describe("sBTC bootstrap signers contract", () => {
    describe("Rotate keys tests", () => {
      test("Rotate keys wrapper correctly", () => {
        const receipt = txOk(
          signers.rotateKeysWrapper({
            newKeys: [new Uint8Array(32).fill(0),new Uint8Array(32).fill(0)],
            multiSigAddress: alice,
            newAggregatePubkey: new Uint8Array(32).fill(0),
            sender: alice,
            height: simnet.blockHeight,
          }),
          alice
        );
        expect(receipt.value).toEqual(true);
      });
      test("Rotate keys wrapper incorrect signer key size", () => {
        const receipt = txErr(
          signers.rotateKeysWrapper({
            newKeys: [new Uint8Array(32).fill(0),new Uint8Array(31).fill(0)],
            multiSigAddress: alice,
            newAggregatePubkey: new Uint8Array(32).fill(0),
            sender: alice,
            height: simnet.blockHeight,
          }),
          alice
        );
        expect(receipt.value).toEqual(211n);
      });
      test("Rotate keys wrapper incorrect aggregate key size", () => {
        const receipt = txErr(
          signers.rotateKeysWrapper({
            newKeys: [new Uint8Array(32).fill(0),new Uint8Array(32).fill(0)],
            multiSigAddress: alice,
            newAggregatePubkey: new Uint8Array(31).fill(0),
            sender: alice,
            height: simnet.blockHeight,
          }),
          alice
        );
        expect(receipt.value).toEqual(signers.constants.ERR_KEY_SIZE.value);
      });
    });
    
  });
  