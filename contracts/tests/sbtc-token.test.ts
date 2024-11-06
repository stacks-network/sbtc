import { alice, bob, deployer, deposit, errors, getCurrentBurnInfo, token } from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, filterEvents, rov, txErr } from "@clarigen/test";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

describe("sBTC token contract", () => {
  describe("token basics", () => {
    test("Mint sbtc token, check Alice balance", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
          burnHash,
          burnHeight,
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
        burnHash,
        burnHeight: BigInt(burnHeight),
      });
      const receipt1 = rov(
        token.getBalance({
          who: alice,
        }),
        alice
      );
      expect(receipt1.value).toEqual(1000n);
    });

    test("Mint & transfer sbtc token, check Bob balance", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
          burnHash,
          burnHeight,
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
        burnHash,
        burnHeight: BigInt(burnHeight)
      });
      const receipt1 = txOk(
        token.transfer({
          amount: 999n,
          sender: alice,
          recipient: bob,
          memo: new Uint8Array(1).fill(0),
        }),
        alice
      );
      expect(receipt1.value).toEqual(true);
      const receipt2 = rov(
        token.getBalance({
          who: bob,
        }),
        bob
      );
      expect(receipt2.value).toEqual(999n);
    });

    test("Fail a non-protocol principal calling protocol-mint", () => {
      const receipt = txErr(
        token.protocolMint({
          amount: 1000n,
          recipient: bob,
        }),
        bob
      );
      expect(receipt.value).toEqual(errors.registry.ERR_UNAUTHORIZED);
    });

    test("Fail transferring sbtc when not owner", () => {
      const receipt1 = txErr(
        token.transfer({
          amount: 999n,
          sender: alice,
          recipient: bob,
          memo: new Uint8Array(1).fill(0),
        }),
        bob
      );
      expect(receipt1.value).toEqual(errors.token.ERR_NOT_OWNER);
    });
  });
});
