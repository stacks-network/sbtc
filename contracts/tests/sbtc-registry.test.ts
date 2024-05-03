import {
  alice,
  btcAddressToPoxAddress,
  getLastWithdrawalRequestId,
  getWithdrawalRequest,
  registry,
  stxAddrToBtcAddr,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk } from "@clarigen/test";

describe("sBTC registry contract", () => {
  test("Last request ID is zero", () => {
    const lastId = getLastWithdrawalRequestId();
    expect(lastId).toEqual(0n);
  });

  test("Storing a new withdrawal request", () => {
    const recipient = stxAddrToBtcAddr(alice, 0);
    const receipt = txOk(
      registry.createWithdrawalRequest({
        amount: 100n,
        recipient: btcAddressToPoxAddress(recipient),
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
    expect(request.recipient).toEqual(btcAddressToPoxAddress(recipient));
    expect(request.blockHeight).toEqual(BigInt(simnet.blockHeight - 1));

    // ensure last-id is updated
    const lastId = getLastWithdrawalRequestId();
    expect(lastId).toEqual(1n);
  });
});
