import {
  alice,
  bob,
  getLastWithdrawalRequestId,
  getWithdrawalRequest,
  registry,
  stxAddressToPoxAddress,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

const alicePoxAddr = stxAddressToPoxAddress(alice);
const bobPoxAddr = stxAddressToPoxAddress(bob);

describe("sBTC registry contract", () => {
  describe("setup", () => {

    test("Testing placeholder deposit function", () => {
      const recipient = alicePoxAddr;
      const receipt = txOk(
        registry.createWithdrawalRequest({
          amount: 100n,
          recipient,
          maxFee: 10n,
          sender: alice,
          height: simnet.blockHeight,
        }),
        alice
      );
      expect(receipt.value).toEqual(1n);

      const request = getWithdrawalRequest(1n);
      if (!request) {
        throw new Error("Request not stored");
      }
      expect(request.sender).toEqual(alice);
      expect(request.amount).toEqual(100n);
      expect(request.maxFee).toEqual(10n);
      expect(request.recipient).toEqual(recipient);
      expect(request.blockHeight).toEqual(BigInt(simnet.blockHeight - 1));

      // ensure last-id is updated
      const lastId = getLastWithdrawalRequestId();
      expect(lastId).toEqual(1n);
    });
  });
});
