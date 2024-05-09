import {
  alice,
  deposit,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";


describe("sBTC deposit contract", () => {
  describe("complete deposit wrapper placeholder", () => {
    
    test("Call complete-deposit-wrapper", () => {
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: Uint8Array.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      expect(receipt.value).toEqual(true);
    });

  });
});
