import {
  alice,
  deposit,
  registry,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr } from "@clarigen/test";


describe("sBTC deposit contract", () => {
  describe("complete deposit contract setup (err 300)", () => {

    test("Fail complete-deposit-wrapper invalid txid length", () => {
      const receipt = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(31).fill(0),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      expect(receipt.value).toEqual(300n);
    });

    test("Fail complete-deposit-wrapper replay deposit (err 301)", () => {
      const receipt0 = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      expect(receipt0.value).toEqual(true);
      const receipt1 = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      expect(receipt1.value).toEqual(301n);
    });
    
    test("Call complete-deposit-wrapper placeholder", () => {
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      expect(receipt.value).toEqual(true);
    });

    test("Call get-complete-deposit placeholder", () => {
      const receipt0 = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      const receipt1 = rov(
        registry.getCompletedDeposit({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
        }),
        alice
      );
      expect(receipt1).toStrictEqual({
        amount: 0n,
        recipient: alice,
      });
    })

  });
});
