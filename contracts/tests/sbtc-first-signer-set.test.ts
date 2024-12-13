import { hexToBytes } from "@clarigen/core";
import { rov } from "@clarigen/test";
import { describe, expect, test } from "vitest";
import { constructMultisigAddress, signers } from "./helpers";

describe("sBTC first signer set", () => {
  test("Deployer address is same as SignerWallet address if sorted", () => {
    const signatureThreshold = 10n;
    const keys = [
      "03431638d7656f2b313776ab8e5fbffb994e0635cb53965d33cdb819384400286f",
      "0396559be1e9b88988237fb7f92f7f2b81b7f644718fc3170e3bf45d703f05e490",
      "02ce1efe968185ca9373fe0fce9e4d1a302d560201b549593830ca54f115318b9c",
      "035b1c31ee3412fb5e7e4c510b957689c6f30ab591082c425c58af77d6e593d7f1",
      "03d92e4ee96a6046c1ffb054b776631fc631b987819c98ecd2e97c79bd887fc24a",
      "024e8daf0693ad298802462873bcb3b29d2cd4eb001c55dd58dea6a004d737770d",
      "02de4e3f0df932cda285ffec2fb6e57b8c3d2c0cd5eed1e32859c704c5f5cd027a",
      "024020d254667b90161127d4197d9cecfb1e7b5a5237c34cf45391d60254d293d7",
      // "03f90225085f698bde412fa5dba346c8cc69fb0cbffaac2a92e130ac7689533be9",
      "0368d6742af52b9f7069570da3bdba120f7e760ea31c4bc0e5b96bba7a70f4d317",
      "03830690830ab2790433231521edbad02715ce7d8b6a8aa43f83cad3e2407b96c4",
      "031f53224e6250d31fd0d6a9b926402ca308e824e750daf5d5a75d5bf59d50d7b0",
      "02c14b0daa6ddb9b74869fd947372a3622d2f88a871523dcd14c5c7c7f0c6c9cc0",
      "03b5b8b594438c7101bbc5fb25d1b76c4643c713481031f7d06bde1f1668c8112d",
      "03ed8edbcbb26010ae3a992ea1e4fffab3805e1303edbd3c130307b4cbcd38a481",
    ]
      .sort() // sort the keys hex string wise
      .map((k) => hexToBytes(k));

    // testnet signer address from contract
    const currentSigner = rov(
      signers.pubkeysToPrincipal(keys, signatureThreshold)
    );
    expect(currentSigner).toEqual("SN3VDXK3WZZSA84XXFKAFAF15NNZX32CTSJV6BTWG");

    // compare with stacks.js result for testnet and mainnet
    const stacksjsTestnet = constructMultisigAddress(keys, signatureThreshold);
    const stacksjsMainnet = constructMultisigAddress(
      keys,
      signatureThreshold,
      false
    );
    expect(stacksjsTestnet).toEqual(currentSigner);

    // compare current signer with significant bytes (no prefix, no checksum)
    expect(stacksjsMainnet.substring(2, stacksjsMainnet.length - 7)).toEqual(
      currentSigner.substring(2, currentSigner.length - 7)
    );

    // expected on mainnet SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4
    expect(stacksjsMainnet).toEqual(
      "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4"
    );
  });
});
