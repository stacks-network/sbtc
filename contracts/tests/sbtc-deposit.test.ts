import {
  alice,
  deployer,
  deposit,
  errors,
  randomPublicKeys,
  registry,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

describe("sBTC deposit contract", () => {
  describe("complete deposit contract setup (err 300)", () => {
    test("Fail complete-deposit-wrapper invalid txid length", () => {
      const receipt = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(31).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
        }),
        deployer
      );
      expect(receipt.value).toEqual(errors.deposit.ERR_TXID_LEN);
    });

    test("Fail complete-deposit-wrapper invalid low amount", () => {
      const receipt = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 10n,
          recipient: deployer,
        }),
        deployer
      );
      expect(receipt.value).toEqual(
        deposit.constants.ERR_LOWER_THAN_DUST.value
      );
    });

    test("Fail complete-deposit-wrapper replay deposit (err 301)", () => {
      const receipt0 = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
        }),
        deployer
      );
      expect(receipt0.value).toEqual(true);
      const receipt1 = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
        }),
        deployer
      );
      expect(receipt1.value).toEqual(errors.deposit.ERR_DEPOSIT_REPLAY);
    });

    test("Call complete-deposit-wrapper placeholder, check print", () => {
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
        }),
        deployer
      );
      const printEvents = filterEvents(
        receipt.events,
        CoreNodeEventType.ContractEvent
      );
      const [print] = printEvents;
      const printData = cvToValue<{
        topic: string;
        txid: string;
        voutIndex: bigint;
        amount: bigint;
      }>(print.data.value);
      expect(printData).toStrictEqual({
        topic: "completed-deposit",
        bitcoinTxid: new Uint8Array(32).fill(0),
        outputIndex: 0n,
        amount: 1000n,
      });
    });

    test("Call get-complete-deposit placeholder", () => {
      txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
        }),
        deployer
      );
      const receipt1 = rov(
        registry.getCompletedDeposit({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
        }),
        deployer
      );
      expect(receipt1).toStrictEqual({
        amount: 1000n,
        recipient: deployer,
      });
    });
  });
  describe("complete many deposits", () => {
    test("fail multiple deposits, first one fails due to txid length", () => {
      const receipt = txErr(
        deposit.completeDepositsWrapper({
          deposits: [
            {
              txid: new Uint8Array(31).fill(0),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
            {
              txid: new Uint8Array(32).fill(1),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
          ],
        }),
        deployer
      );
      // fold err prefix is "u303" + 10, first item errs so should be 313
      expect(receipt.value).toEqual(313n);
    });
    test("fail multiple deposits, second one fails due to low amount", () => {
      const receipt = txErr(
        deposit.completeDepositsWrapper({
          deposits: [
            {
              txid: new Uint8Array(32).fill(0),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
            {
              txid: new Uint8Array(32).fill(1),
              voutIndex: 0,
              amount: 100n,
              recipient: deployer,
            },
          ],
        }),
        deployer
      );
      // fold err prefix is "u303" + 10, first item errs so should be 314
      expect(receipt.value).toEqual(314n);
    });
    test("fail multiple deposits, third one fails due to invalid caller", () => {
      const receipt = txErr(
        deposit.completeDepositsWrapper({
          deposits: [
            {
              txid: new Uint8Array(32).fill(0),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
            {
              txid: new Uint8Array(32).fill(1),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
            {
              txid: new Uint8Array(32).fill(2),
              voutIndex: 0,
              amount: 100n,
              recipient: alice,
            },
          ],
        }),
        deployer
      );
      // fold err prefix is "u303" + 10, third item errs so should be 315
      expect(receipt.value).toEqual(315n);
    });
    test("complete multiple deposits successfully", () => {
      const receipt = txOk(
        deposit.completeDepositsWrapper({
          deposits: [
            {
              txid: new Uint8Array(32).fill(0),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
            {
              txid: new Uint8Array(32).fill(1),
              voutIndex: 0,
              amount: 1000n,
              recipient: deployer,
            },
          ],
        }),
        deployer
      );
      expect(receipt.value).toEqual(2n);
    });
  });
});

describe("optimization tests", () => {
  test("test maximum deposts that can be processed", () => {
    const totalAmount = 1000000n;
    const runs = 650;
    const txids = randomPublicKeys(runs).map((pk) => pk.slice(0, 32));
    txOk(
      deposit.completeDepositsWrapper({
        deposits: txids.map((txid) => ({
          txid,
          voutIndex: 0,
          amount: totalAmount / BigInt(runs),
          recipient: deployer,
        })),
      }),
      deployer
    );
  });
});
