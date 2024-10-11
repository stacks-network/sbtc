import {
  alice,
  bob,
  deployer,
  deposit,
  errors,
  getCurrentBurnInfo,
  randomPublicKeys,
  registry,
  stxAddressToPoxAddress,
  token,
  withdrawal,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr, rovOk, rovErr } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

const alicePoxAddr = stxAddressToPoxAddress(alice);
const defaultAmount = 1000n;
const defaultMaxFee = 10n;

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
        amount: defaultAmount + (defaultMaxFee + 1n),
        recipient: alice,
      }),
      deployer
    );
    const receipt = txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
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
      amount: defaultAmount,
      maxFee: defaultMaxFee,
      blockHeight: BigInt(simnet.blockHeight - 2),
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
      amount: defaultAmount,
      maxFee: defaultMaxFee,
      blockHeight: BigInt(simnet.blockHeight - 2),
      topic: "withdrawal-create",
      requestId: 1n,
    });
  });

  test("Tokens are converted to locked sBTC", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    expect(rovOk(token.getBalance(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    const receipt = txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const lockedBalance = rovOk(token.getBalanceLocked(alice));
    expect(lockedBalance).toEqual(defaultAmount + defaultMaxFee);
    const [mintEvent] = filterEvents(
      receipt.events,
      CoreNodeEventType.FtMintEvent
    );
    expect(mintEvent.data.asset_identifier).toEqual(
      `${token.identifier}::${token.fungible_tokens[1].name}`
    );
    expect(mintEvent.data.amount).toEqual(
      (defaultAmount + defaultMaxFee).toString()
    );
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);
  });

  test("Recipient is validated when initiating an address", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 4000n,
        recipient: alice,
      }),
      deployer
    );
    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: newPoxAddr(7, new Uint8Array(32)),
          maxFee: defaultMaxFee,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_VERSION);

    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: newPoxAddr(2, new Uint8Array(32)),
          maxFee: defaultMaxFee,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_HASHBYTES);

    expect(
      txErr(
        withdrawal.initiateWithdrawalRequest({
          amount: defaultAmount,
          recipient: newPoxAddr(6, new Uint8Array(20)),
          maxFee: defaultMaxFee,
        }),
        alice
      ).value
    ).toEqual(errors.withdrawal.ERR_INVALID_ADDR_HASHBYTES);
  });

  test("withdrawal amount of less than or equal to dust limit is rejected", () => {
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: 4000n,
        recipient: alice,
      }),
      deployer
    );
    const receipt = txErr(
      withdrawal.initiateWithdrawalRequest({
        amount: withdrawal.constants.DUST_LIMIT,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_DUST_LIMIT);
  });
});

test("max-fee must be accounted for", () => {
  txOk(
    deposit.completeDepositWrapper({
      txid: new Uint8Array(32).fill(0),
      voutIndex: 0,
      amount: 4000n,
      recipient: alice,
    }),
    deployer
  );
  // We're going to try to initate a withdrawal request where amount +
  // maxFee is greater than the available balance in the account (which in
  // this case is just amount). This should error.
  expect(rovOk(token.getBalanceAvailable(alice))).toEqual(4000n);
  const receipt = txErr(
    withdrawal.initiateWithdrawalRequest({
      amount: 4000n,
      recipient: alicePoxAddr,
      maxFee: 1n,
    }),
    alice
  );
  // Under the hood `initiate-withdrawal-request` attempts `ft-burn?`
  // amount + max-fee for the `tx-sender`, so if the transaction sender
  // does not have enough in their account then `(err u1)` is returned in
  // the response.
  expect(receipt.value).toEqual(1n);
});

describe("Accepting a withdrawal request", () => {
  test("Fails with non-existant request-id", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.acceptWithdrawalRequest({
        requestId: 2n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 1n,
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_REQUEST);
  });
  test("Fails when called by non-signer", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 1n,
      }),
      alice
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_CALLER);
  });
  test("Fails when replay is attempted", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 1n,
      }),
      deployer
    );
    const receipt = txErr(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 1n,
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_ALREADY_PROCESSED);
  });
  test("Fails when fee is too high", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 11n,
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_FEE_TOO_HIGH);
  });
  test("Request is successfully accepted with max fee", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + (defaultMaxFee + 10n),
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee + 10n,
      }),
      alice
    );
    const receipt = txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 2n,
        outputIndex: 10n,
        fee: defaultMaxFee + 10n,
      }),
      deployer
    );
    expect(rovOk(token.getBalance(alice))).toEqual(0n);
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);

    // An event is emitted properly
    const prints = filterEvents(
      receipt.events,
      CoreNodeEventType.ContractEvent
    );
    expect(prints.length).toEqual(1);
    const [print] = prints;
    const printData = cvToValue<{
      requestId: bigint;
      bitcoinTxid: Uint8Array;
      signerBitmap: bigint;
      outputIndex: bigint;
      topic: string;
      fee: bigint;
    }>(print.data.value);

    expect(printData).toStrictEqual({
      requestId: 1n,
      bitcoinTxid: new Uint8Array(32).fill(0),
      signerBitmap: 2n,
      outputIndex: 10n,
      topic: "withdrawal-accept",
      fee: defaultMaxFee + 10n,
    });
  });
  test("accept withdrawal sets withdrawal-status to true", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: defaultMaxFee,
      }),
      deployer
    );
    expect(rovOk(token.getBalance(alice))).toEqual(0n);
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);

    // Check that the request was stored correctly with the correct status
    const request = rov(registry.getWithdrawalRequest(1n));
    if (!request) {
      throw new Error("Request not stored");
    }
    expect(request).toStrictEqual({
      sender: alice,
      recipient: alicePoxAddr,
      amount: defaultAmount,
      maxFee: defaultMaxFee,
      blockHeight: BigInt(simnet.blockHeight - 3),
      status: true,
    });
  });
  test("reject withdrawal sets withdrawal-status to false", () => {
    // We start off with a balance of zero
    expect(rovOk(token.getBalance(alice))).toEqual(0n);
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);
    expect(rovOk(token.getBalanceLocked(alice))).toEqual(0n);
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    expect(rovOk(token.getBalance(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    expect(rovOk(token.getBalanceLocked(alice))).toEqual(0n);
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    // Initiating a withdrawal request doesn't change the "balance", but
    // does change how much is available.
    expect(rovOk(token.getBalance(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(0n);
    expect(rovOk(token.getBalanceLocked(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    const receipt = txOk(
      withdrawal.rejectWithdrawalRequest({
        requestId: 1n,
        signerBitmap: 1234567n,
      }),
      deployer
    );
    // This is the original balance, rejecting the request restores it.
    expect(rovOk(token.getBalance(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    expect(rovOk(token.getBalanceAvailable(alice))).toEqual(
      defaultAmount + defaultMaxFee
    );
    expect(rovOk(token.getBalanceLocked(alice))).toEqual(0n);

    // Check that the request was stored correctly with the correct status
    const request = rov(registry.getWithdrawalRequest(1n));
    if (!request) {
      throw new Error("Request not stored");
    }
    expect(request).toStrictEqual({
      sender: alice,
      recipient: alicePoxAddr,
      amount: defaultAmount,
      maxFee: defaultMaxFee,
      blockHeight: BigInt(simnet.blockHeight - 3),
      status: false,
    });

    // An event is emitted properly
    const prints = filterEvents(
      receipt.events,
      CoreNodeEventType.ContractEvent
    );
    expect(prints.length).toEqual(1);
    const [print] = prints;
    const printData = cvToValue<{
      requestId: bigint;
      bitcoinTxid: Uint8Array;
      signerBitmap: bigint;
      outputIndex: bigint;
      topic: string;
      fee: bigint;
    }>(print.data.value);

    expect(printData).toStrictEqual({
      requestId: 1n,
      signerBitmap: 1234567n,
      topic: "withdrawal-reject",
    });
  });
  test("Request is successfully accepted with fee less than max", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 9n,
      }),
      deployer
    );
    expect(rovOk(token.getBalance(alice))).toEqual(1n);
  });
});

describe("Reject a withdrawal request", () => {
  test("Fails with non-existant request-id", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.rejectWithdrawalRequest({
        requestId: 2n,
        signerBitmap: 0n,
      }),
      alice
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_REQUEST);
  });
  test("Fails when called by a non-signer", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.rejectWithdrawalRequest({
        requestId: 1n,
        signerBitmap: 0n,
      }),
      alice
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_CALLER);
  });
  test("Fails when request id is replayed", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: 10n,
      }),
      deployer
    );
    const receipt = txErr(
      withdrawal.rejectWithdrawalRequest({
        requestId: 1n,
        signerBitmap: 0n,
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_ALREADY_PROCESSED);
  });
  test("Fails when Bitcoin forks", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: 1000n,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txErr(
      withdrawal.completeWithdrawals({
        withdrawals: [
          {
            requestId: 1n,
            status: true,
            signerBitmap: 1n,
            bitcoinTxid: new Uint8Array(32).fill(1),
            outputIndex: 10n,
            fee: 10n,
          },
        ],
        burnHeight: 10n,
        burnHash: new Uint8Array(32).fill(0),
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_BURN_HASH);
  });
  test("Successfully reject a requested withdrawal", () => {
    // Alice initiates withdrawalrequest
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    const receipt = txOk(
      withdrawal.acceptWithdrawalRequest({
        requestId: 1n,
        bitcoinTxid: new Uint8Array(32).fill(0),
        signerBitmap: 0n,
        outputIndex: 10n,
        fee: defaultMaxFee,
      }),
      deployer
    );
    expect(receipt.value).toEqual(true);
  });
});

describe("Complete multiple withdrawals", () => {
  test("Successfully pass in two withdrawals, one accept, one reject", () => {
    // Alice setup
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0,
        amount: defaultAmount + defaultMaxFee,
        recipient: alice,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      alice
    );
    // Bob setup
    txOk(
      deposit.completeDepositWrapper({
        txid: new Uint8Array(32).fill(1),
        voutIndex: 1,
        amount: defaultAmount + defaultMaxFee,
        recipient: bob,
      }),
      deployer
    );
    txOk(
      withdrawal.initiateWithdrawalRequest({
        amount: defaultAmount,
        recipient: alicePoxAddr,
        maxFee: defaultMaxFee,
      }),
      bob
    );
    //
    const receipt = txErr(
      withdrawal.completeWithdrawals({
        withdrawals: [
          {
            requestId: 1n,
            status: true,
            signerBitmap: 1n,
            bitcoinTxid: new Uint8Array(32).fill(1),
            outputIndex: 10n,
            fee: defaultMaxFee,
          },
          {
            requestId: 2n,
            status: false,
            signerBitmap: 1n,
            bitcoinTxid: null,
            outputIndex: null,
            fee: null,
          },
        ],
        burnHeight: 10n,
        burnHash: new Uint8Array(32).fill(0),
      }),
      deployer
    );
    expect(receipt.value).toEqual(errors.withdrawal.ERR_INVALID_BURN_HASH);
  });
});

describe("optimization tests for completing withdrawals", () => {
  test("maximizing the number of withdrawal completions in one tx", () => {
    const totalAmount = 1000000n;
    const runs = 300;
    const perAmount = totalAmount / BigInt(runs);
    const maxFee = 10n;
    const txids = randomPublicKeys(runs).map((pk) => pk.slice(0, 32));
    for (let index = 0; index < runs; index++) {
      const txid = txids[index];
      txOk(
        deposit.completeDepositWrapper({
          txid,
          voutIndex: 0,
          amount: perAmount + maxFee,
          recipient: alice,
        }),
        deployer
      );
      txOk(
        withdrawal.initiateWithdrawalRequest({
          amount: perAmount,
          recipient: alicePoxAddr,
          maxFee: maxFee,
        }),
        alice
      );
    }
    const { burnHeight, burnHash } = getCurrentBurnInfo();
    txOk(
      withdrawal.completeWithdrawals({
        withdrawals: txids.map((txid, index) => {
          return {
            requestId: BigInt(index + 1),
            status: true,
            signerBitmap: 1n,
            bitcoinTxid: txid,
            outputIndex: 0n,
            fee: 10n,
          };
        }),
        burnHeight,
        burnHash: burnHash!,
      }),
      deployer
    );
  });
});
