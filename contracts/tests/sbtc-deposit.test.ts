import {
  alice,
  deposit,
  registry,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";
import { uintCV } from "../node_modules/@stacks/transactions/dist/clarity/types/intCV";
import { principalCV } from "../node_modules/@stacks/transactions/dist/clarity/types/principalCV";
import { tupleCV } from "@stacks/transactions";


describe("sBTC deposit contract", () => {
  describe("complete deposit contract setup", () => {
    
    test("Call complete-deposit-wrapper placeholder", () => {
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

    test("Call get-complete-deposit placeholder", () => {
      const receipt0 = txOk(
        deposit.completeDepositWrapper({
          txid: Uint8Array.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
          voutIndex: 0,
          amount: 0,
          recipient: alice,
        }),
        alice
      );
      const receipt1 = rov(
        registry.getCompletedDeposit({
          txid: Uint8Array.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
          voutIndex: 0,
        }),
        alice
      );
      expect(JSON.stringify(receipt1)).toEqual('{"amount":"0","recipient":"ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5"}');
    })

  });
});
