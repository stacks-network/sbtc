import { CoreNodeEventType, cvToValue } from "@clarigen/core";
import {
  filterEvents,
  FtTransferEvent,
  rov,
  SmartContractEvent,
  txErr,
  txOk,
} from "@clarigen/test";
import { bufferCV } from "@stacks/transactions";
import { describe, expect, test } from "vitest";
import {
  alice,
  bob,
  charlie,
  deployer,
  deposit,
  errors,
  getCurrentBurnInfo,
  token,
  tokenTest,
} from "./helpers";

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
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
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
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
      });

      // transfer
      const memo = new Uint8Array([0]);
      const receipt1 = txOk(
        token.transfer({
          amount: 999n,
          sender: alice,
          recipient: bob,
          memo,
        }),
        alice
      );
      expect(receipt1.value).toEqual(true);

      // verify events
      expect((receipt1.events[0] as FtTransferEvent).data).toStrictEqual({
        sender: alice,
        recipient: bob,
        asset_identifier: `${token.identifier}::${token.fungible_tokens[0].name}`,
        amount: "999",
      });

      expect((receipt1.events[1] as SmartContractEvent).data).toStrictEqual({
        contract_identifier: token.identifier,
        topic: "print",
        value: bufferCV(memo),
        raw_value: "0x020000000100",
      });

      // verify balance
      const receipt2 = rov(
        token.getBalance({
          who: bob,
        }),
        bob
      );
      expect(receipt2.value).toEqual(999n);
    });

    test("Mint & transfer multiple sbtc token, standard principal", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
      });
      const receipt1 = txOk(
        token.transferMany({
          recipients: [
            {
              amount: 100n,
              sender: alice,
              to: bob,
              memo: null,
            },
            {
              amount: 200n,
              sender: alice,
              to: charlie,
              memo: null,
            },
          ],
        }),
        alice
      );
      expect(receipt1.value).toEqual(2n);
      const receipt2 = rov(
        token.getBalance({
          who: bob,
        }),
        bob
      );
      expect(receipt2.value).toEqual(100n);
      const receipt3 = rov(
        token.getBalance({
          who: charlie,
        }),
        charlie
      );
      expect(receipt3.value).toEqual(200n);
    });

    test("Mint & transfer multiple sbtc token, fail on first", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
      });
      const receipt1 = txErr(
        token.transferMany({
          recipients: [
            {
              amount: 100n,
              sender: alice,
              to: bob,
              memo: null,
            },
            {
              amount: 100n,
              sender: alice,
              to: charlie,
              memo: null,
            },
          ],
        }),
        bob
      );
      // Many-transfer errors start at 6, error happens at index 0
      expect(receipt1.value).toEqual(errors.token.ERR_TRANSFER);
    });

    test("Mint & transfer multiple sbtc token, fail on second", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
      });
      const receipt1 = txErr(
        token.transferMany({
          recipients: [
            {
              amount: 100n,
              sender: alice,
              to: bob,
              memo: null,
            },
            {
              amount: 100n,
              sender: bob,
              to: charlie,
              memo: null,
            },
          ],
        }),
        alice
      );
      // Many-transfer errors start at 6, error happens at index 1
      expect(receipt1.value).toEqual(7n);
    });

    test("Mint & transfer multiple sbtc token, contract principal", () => {
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt = txOk(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: tokenTest.identifier,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
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
        sweepTxid: new Uint8Array(32).fill(1),
      });
      const receipt1 = txOk(
        tokenTest.sendManySbtcTokens({
          recipients: [alice, bob, charlie],
        }),
        deployer
      );
      expect(receipt1.value).toEqual(3n);
      const receipt2 = rov(
        token.getBalance({
          who: alice,
        }),
        bob
      );
      expect(receipt2.value).toEqual(100n);
      const receipt3 = rov(
        token.getBalance({
          who: bob,
        }),
        charlie
      );
      expect(receipt3.value).toEqual(100n);
      const receipt4 = rov(
        token.getBalance({
          who: charlie,
        }),
        charlie
      );
      expect(receipt4.value).toEqual(100n);
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
