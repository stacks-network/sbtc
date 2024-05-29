import {
  alice,
  deposit,
  errors,
  registry,
  stxAddressToPoxAddress,
  token,
  withdrawal,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr, rovOk, rovErr } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

const alicePoxAddr = stxAddressToPoxAddress(alice);

function newPoxAddr(version: number, hashbytes: Uint8Array) {
  return {
    version: new Uint8Array([version]),
    hashbytes,
  };
}

describe("Validating recipient address", () => {
  test("Should be valid for all different address types", () => {
    function expectValidAddr(bytesLen: number, version: number) {
      const recipient = newPoxAddr(version, new Uint8Array(bytesLen).fill(0));
      expect(rovOk(withdrawal.validateRecipient(recipient))).toEqual(true);
    }
    expectValidAddr(20, 0);
    expectValidAddr(20, 1);
    expectValidAddr(20, 2);
    expectValidAddr(20, 3);
    expectValidAddr(20, 4);
    expectValidAddr(32, 5);
    expectValidAddr(32, 6);
  });

  test("should not support incorrect versions", () => {
    expect(
      rovErr(withdrawal.validateRecipient(newPoxAddr(7, new Uint8Array(32))))
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_VERSION);
    expect(
      rovErr(withdrawal.validateRecipient(newPoxAddr(8, new Uint8Array(32))))
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_VERSION);
  });

  test("should not support incorrect byte lengths", async () => {
    function expectInvalidAddr(bytesLen: number, version: number) {
      const recipient = newPoxAddr(version, new Uint8Array(bytesLen).fill(0));
      expect(rovErr(withdrawal.validateRecipient(recipient))).toEqual(
        errors.withdrawal.ERR_INVALID_ADDR_HASHBYTES
      );
    }
    // Test a bunch of lengths other than 20
    for (let i = 0; i < 34; i++) {
      if (i === 20) continue;
      for (let v = 0; v <= 4; v++) {
        expectInvalidAddr(i, v);
      }
    }
    // Test a bunch of lengths other than 32
    for (let i = 0; i < 50; i++) {
      if (i === 32) continue;
      for (let v = 5; v <= 6; v++) {
        expectInvalidAddr(i, v);
      }
    }
  });
});

describe("initiating a withdrawal request", () => {
  test("alice can initiate a request", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 1000n,
        recipient: alice,
      }),
      alice
    );
    const receipt = txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: 1000n,
        recipient: alicePoxAddr,
        maxFee: 10n,
      }),
      alice
    );

    expect(receipt.value).toEqual(1n);

    // The request was stored correctly

    const request = rov(registry.getWithdrawalRequest(1n));
    if (!request) {
      throw new Error("Request not stored");
    }
    expect(request).toStrictEqual({
      sender: alice,
      recipient: alicePoxAddr,
      amount: 1000n,
      maxFee: 10n,
      blockHeight: 2n,
      status: null,
    });

    // An event is emitted properly

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

    expect(printData).toStrictEqual({
      sender: alice,
      recipient: alicePoxAddr,
      amount: 1000n,
      maxFee: 10n,
      blockHeight: 2n,
      topic: "withdrawal-request",
      requestId: 1n,
    });
  });

  test("Tokens are converted to locked sBTC", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 1000n,
        recipient: alice,
      }),
      alice
    );
    expect(rovOk(token.getBalance(alice))).toEqual(1000n);
    const receipt = txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: 1000n,
        recipient: alicePoxAddr,
        maxFee: 10n,
      }),
      alice
    );
    const lockedBalance = rovOk(token.getBalanceLocked(alice));
    expect(lockedBalance).toEqual(1000n);
    const [mintEvent] = filterEvents(
      receipt.events,
      CoreNodeEventType.FtMintEvent
    );
    expect(mintEvent.data.asset_identifier).toEqual(
      `${token.identifier}::${token.fungible_tokens[1].name}`
    );
    expect(mintEvent.data.amount).toEqual(1000n.toString());
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);
  });

  test("recipient is validated when iniating an address", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 4000n,
        recipient: alice,
      }),
      alice
    );
    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: 1000n,
          recipient: newPoxAddr(7, new Uint8Array(32)),
          maxFee: 10n,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_VERSION);

    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: 1000n,
          recipient: newPoxAddr(2, new Uint8Array(32)),
          maxFee: 10n,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_HASHBYTES);

    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: 1000n,
          recipient: newPoxAddr(6, new Uint8Array(20)),
          maxFee: 10n,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_HASHBYTES);
  });

  test("Cannot try and withdrawal less than or equal to the dust limit", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 4000n,
        recipient: alice,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.initiateWithdrawalRequest({
        amount: withdrawal.constants.dustLimit,
        recipient: alicePoxAddr,
        maxFee: 10n,
      }),
      alice
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_DUST_LIMIT);
  });
});
