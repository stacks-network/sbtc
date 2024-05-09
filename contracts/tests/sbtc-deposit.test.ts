import {
  alice,
  deposit,
  registry,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov } from "@clarigen/test";


describe("sBTC deposit contract", () => {
  describe("complete deposit contract setup", () => {
    
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
