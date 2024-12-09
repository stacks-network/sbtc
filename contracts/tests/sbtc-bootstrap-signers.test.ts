import {
  constructMultisigAddress,
  currentSignerAddr,
  deployer,
  errors,
  randomPublicKeys,
  registry,
  signers,
  depositUpdate,
  getCurrentBurnInfo,
  deposit,
  alice,
} from "./helpers";
import { test, expect, describe } from "vitest";
import { txOk, txErr, rov, filterEvents } from "@clarigen/test";
import {
  AddressHashMode,
  AddressVersion,
  addressFromPublicKeys,
  addressToString,
  pubKeyfromPrivKey,
  serializePublicKey,
} from "@stacks/transactions";
import { p2ms, p2sh } from "@scure/btc-signer";
import { b58ToC32 } from "c32check";
import { CoreNodeEventType, cvToValue } from "@clarigen/core";

describe("sBTC bootstrap signers contract", () => {
  describe("Rotate keys tests", () => {
    test("Rotate keys wrapper correctly", () => {
      const newKeys = randomPublicKeys(2);
      const newSignatureThreshold = 2n;
      const receipt = txOk(
        signers.rotateKeysWrapper({
          newKeys,
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold,
        }),
        deployer
      );
      expect(receipt.value).toEqual(true);

      const expectedPrincipal = constructMultisigAddress(
        newKeys,
        newSignatureThreshold,
      );

      const prints = filterEvents(
        receipt.events,
        CoreNodeEventType.ContractEvent
      );
      const [print] = prints;
      const printData = cvToValue<{
        topic: string;
        newKeys: Uint8Array[];
        newAddress: string;
        newAggregatePubkey: Uint8Array;
        newSignatureThreshold: bigint;
      }>(print.data.value);
      expect(printData).toEqual({
        topic: "key-rotation",
        newKeys: newKeys,
        newAddress: expectedPrincipal,
        newAggregatePubkey: new Uint8Array(33).fill(0),
        newSignatureThreshold: newSignatureThreshold
      });

      const setAggKey = rov(registry.getCurrentAggregatePubkey());
      expect(setAggKey).toEqual(new Uint8Array(33).fill(0));

      expect(rov(registry.getCurrentSignerSet())).toStrictEqual(newKeys);
      expect(currentSignerAddr()).toEqual(expectedPrincipal);
      expect(rov(registry.getCurrentSignerData())).toStrictEqual({
        currentAggregatePubkey: new Uint8Array(33).fill(0),
        currentSignerSet: newKeys,
        currentSignerPrincipal: expectedPrincipal,
        currentSignatureThreshold: newSignatureThreshold,
      });
    });

    test("Rotate keys wrapper 3-of-5", () => {
      const receipt = txOk(
        signers.rotateKeysWrapper({
          newKeys: randomPublicKeys(5),
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold: 3n,
        }),
        deployer
      );
      expect(receipt.value).toEqual(true);
    });

    test("Rotate keys wrapper 90-of-128", () => {
      const receipt = txOk(
        signers.rotateKeysWrapper({
          newKeys: randomPublicKeys(128),
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold: 90n,
        }),
        deployer
      );
      expect(receipt.value).toEqual(true);
    });

    test("Rotate keys wrapper incorrect signer key size", () => {
      const newSignatureThreshold = 2n;
      const receipt = txErr(
        signers.rotateKeysWrapper({
          newKeys: [new Uint8Array(33).fill(0), new Uint8Array(31).fill(0)],
          newAggregatePubkey: new Uint8Array(33).fill(0),
          newSignatureThreshold,
        }),
        currentSignerAddr()
      );
      expect(receipt.value).toEqual(errors.signers.ERR_KEY_SIZE_PREFIX + 11n);
    });

    test("Rotate keys wrapper incorrect aggregate key size", () => {
      const newSignatureThreshold = 2n;
      const receipt = txErr(
        signers.rotateKeysWrapper({
          newKeys: [new Uint8Array(33).fill(0), new Uint8Array(33).fill(0)],
          newAggregatePubkey: new Uint8Array(31).fill(0),
          newSignatureThreshold,
        }),
        currentSignerAddr()
      );
      expect(receipt.value).toEqual(errors.signers.ERR_KEY_SIZE);
    });
  });

  test("Rotate keys wrapper incorrect signature threshold", () => {
    // You cannot have a threshold greater than the number of keys
    const receipt1 = txErr(
      signers.rotateKeysWrapper({
        newKeys: [new Uint8Array(33).fill(0), new Uint8Array(33).fill(0)],
        newAggregatePubkey: new Uint8Array(31).fill(0),
        newSignatureThreshold: 3n,
      }),
      currentSignerAddr()
    );
    expect(receipt1.value).toEqual(errors.signers.ERR_SIGNATURE_THRESHOLD);

    // The threshold must be greater than 50% of the number of keys
    const receipt2 = txErr(
      signers.rotateKeysWrapper({
        newKeys: [new Uint8Array(33).fill(0), new Uint8Array(33).fill(0)],
        newAggregatePubkey: new Uint8Array(31).fill(0),
        newSignatureThreshold: 1n,
      }),
      currentSignerAddr()
    );
    expect(receipt2.value).toEqual(errors.signers.ERR_SIGNATURE_THRESHOLD);
  });

  describe("Constructing a multisig from a list of keys", () => {
    describe("constructing a multisig from two fixed keys", () => {
      const stacksPubkeys = [
        pubKeyfromPrivKey(
          "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001"
        ),
        pubKeyfromPrivKey(
          "530d9f61984c888536871c6573073bdfc0058896dc1adfe9a6a10dfacadc209101"
        ),
      ];
      const pubkeys = stacksPubkeys.map((pk) => serializePublicKey(pk));

      test("principal created is the same as stacks.js", () => {
        const addr = rov(signers.pubkeysToPrincipal(pubkeys, 2));
        const stacksJsAddr = addressToString(
          addressFromPublicKeys(
            AddressVersion.TestnetMultiSig,
            AddressHashMode.SerializeP2SH,
            2,
            stacksPubkeys
          )
        );
        expect(addr).toEqual(stacksJsAddr);
      });

      // In this example, use yet another library to construct a p2sh ms
      // Bitcoin address, and then convert that to a c32 (stacks) address.
      test("principal is the same as a b58 bitcoin address", () => {
        const btcPayment = p2sh(p2ms(2, pubkeys));
        const c32Addr = b58ToC32(btcPayment.address!, 0x15);
        const addr = rov(signers.pubkeysToPrincipal(pubkeys, 2));
        expect(addr).toEqual(c32Addr);
      });
    });

    describe("Testing multisig computation with random data", () => {
      // This test generates random public keys from 1-1 to 15-15, and all
      // combinations of m-of-n multisig addresses. It then compares the
      // principal generated by the contract to the principal generated by
      // stacks.js.
      test("matching contract code to stacks.js", async () => {
        for (let n = 1; n <= 15; n++) {
          const pubkeys = randomPublicKeys(n);
          for (let m = 1; m <= 15; m++) {
            if (m > n) continue;
            const stacksJsPrincipal = constructMultisigAddress(pubkeys, m);
            const contractPrincipal = rov(
              signers.pubkeysToPrincipal(pubkeys, m)
            );
            expect(contractPrincipal).toEqual(stacksJsPrincipal);
          }
        }
      });

      test("matching multisig compared to @scure/btc-signer", () => {
        function principalFromPubkeysBtc(pubkeys: Uint8Array[], m: number) {
          return b58ToC32(p2sh(p2ms(m, pubkeys)).address!, 0x15);
        }
        for (let n = 1; n <= 15; n++) {
          const pubkeys = randomPublicKeys(n);
          for (let m = 1; m <= 15; m++) {
            if (m > n) continue;
            const scurePrincipal = principalFromPubkeysBtc(pubkeys, m);
            const contractPrincipal = rov(
              signers.pubkeysToPrincipal(pubkeys, m)
            );
            expect(contractPrincipal).toEqual(scurePrincipal);
          }
        }
      });
    });
  });
  
  describe("Update deposit contract", () => {
    test("Can update deposit contract & call into new version", () => {
      // Switch out active deposit contract
      const receipt1 = txOk(
        signers.updateProtocolContractWrapper({
          contractType: new Uint8Array(1).fill(1),
          contractAddress: depositUpdate.identifier,
        }),
        deployer
      );
      expect(receipt1.value).toEqual(true);
      // Call into the new contract
      const defaultAmount = 1000n;
      const defaultMaxFee = 10n;
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt2 = txOk(
        depositUpdate.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: defaultAmount + defaultMaxFee,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      expect(receipt2.value).toEqual(true);
    });
    test("Can not call into previous deposit contract", () => {
      // Switch out active deposit contract
      const receipt1 = txOk(
        signers.updateProtocolContractWrapper({
          contractType: new Uint8Array(1).fill(1),
          contractAddress: depositUpdate.identifier,
        }),
        deployer
      );
      expect(receipt1.value).toEqual(true);
      const { burnHeight, burnHash } = getCurrentBurnInfo();

      const receipt = txErr(
        deposit.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: 1000n,
          recipient: deployer,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      expect(receipt.value).toEqual(errors.registry.ERR_UNAUTHORIZED);
    });
    test("Can update deposit contract a second time", () => {
      // Switch out active deposit contract
      const receipt1 = txOk(
        signers.updateProtocolContractWrapper({
          contractType: new Uint8Array(1).fill(1),
          contractAddress: depositUpdate.identifier,
        }),
        deployer
      );
      expect(receipt1.value).toEqual(true);
      // Call into the new contract
      const defaultAmount = 1000n;
      const defaultMaxFee = 10n;
      const { burnHeight, burnHash } = getCurrentBurnInfo();
      const receipt2 = txOk(
        depositUpdate.completeDepositWrapper({
          txid: new Uint8Array(32).fill(0),
          voutIndex: 0,
          amount: defaultAmount + defaultMaxFee,
          recipient: alice,
          burnHash,
          burnHeight,
          sweepTxid: new Uint8Array(32).fill(1),
        }),
        deployer
      );
      expect(receipt2.value).toEqual(true);
      // Switch out active deposit contract
      const receipt3 = txOk(
        signers.updateProtocolContractWrapper({
          contractType: new Uint8Array(1).fill(1),
          contractAddress: deposit.identifier,
        }),
        deployer
      );
      expect(receipt3.value).toEqual(true);
    });
  });

});
