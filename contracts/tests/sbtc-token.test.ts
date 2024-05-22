import {
  alice,
  deposit,
  registry,
  token,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from '@clarigen/core';


describe("sBTC token contract", () => {
  describe("token basics", () => {
    
    test("Mint sbtc token, check balance", () => {
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
        }),
        alice
      );
      const printEvents = filterEvents(receipt.events, CoreNodeEventType.ContractEvent);
      const [print] = printEvents;
      const printData = cvToValue<{
        topic: string;
        txid: string;
        voutIndex: bigint;
        amount: bigint;
      }>(print.data.value);
      expect(printData).toStrictEqual({
        topic: "completed-deposit",
        txid: new Uint8Array(32).fill(0),
        voutIndex: 0n,
        amount: 1000n,
      });
      const receipt1 = rov(
        token.getBalance({
          who: alice,
        }),
        alice
      );
      expect(receipt1.value).toEqual(1000n);
    });

  });
});
