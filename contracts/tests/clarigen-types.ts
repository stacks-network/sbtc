import type {
  TypedAbiArg,
  TypedAbiFunction,
  TypedAbiMap,
  TypedAbiVariable,
  Response,
} from "@clarigen/core";

export const contracts = {
  sbtcBootstrapSigners: {
    functions: {
      signerKeyLengthCheck: {
        name: "signer-key-length-check",
        access: "private",
        args: [
          { name: "current-key", type: { buffer: { length: 32 } } },
          {
            name: "helper-response",
            type: {
              response: {
                ok: { tuple: [{ name: "index", type: "uint128" }] },
                error: "uint128",
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: { tuple: [{ name: "index", type: "uint128" }] },
              error: "uint128",
            },
          },
        },
      } as TypedAbiFunction<
        [
          currentKey: TypedAbiArg<Uint8Array, "currentKey">,
          helperResponse: TypedAbiArg<
            Response<
              {
                index: number | bigint;
              },
              number | bigint
            >,
            "helperResponse"
          >,
        ],
        Response<
          {
            index: bigint;
          },
          bigint
        >
      >,
      rotateKeysWrapper: {
        name: "rotate-keys-wrapper",
        access: "public",
        args: [
          {
            name: "new-keys",
            type: { list: { type: { buffer: { length: 32 } }, length: 15 } },
          },
          { name: "multi-sig-address", type: "principal" },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], "newKeys">,
          multiSigAddress: TypedAbiArg<string, "multiSigAddress">,
          newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {},
    variables: {
      ERR_KEY_SIZE: {
        name: "ERR_KEY_SIZE",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_KEY_SIZE_PREFIX: {
        name: "ERR_KEY_SIZE_PREFIX",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      keySize: {
        name: "key-size",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      signatureThreshold: {
        name: "signature-threshold",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_KEY_SIZE: {
        isOk: false,
        value: 200n,
      },
      ERR_KEY_SIZE_PREFIX: 200n,
      keySize: 32n,
      signatureThreshold: 8n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch25",
    clarity_version: "Clarity2",
    contractName: "sbtc-bootstrap-signers",
  },
  sbtcDeposit: {
    functions: {
      completeDepositWrapper: {
        name: "complete-deposit-wrapper",
        access: "public",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
          { name: "amount", type: "uint128" },
          { name: "recipient", type: "principal" },
        ],
        outputs: {
          type: {
            response: {
              ok: { response: { ok: "bool", error: "uint128" } },
              error: "uint128",
            },
          },
        },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, "txid">,
          voutIndex: TypedAbiArg<number | bigint, "voutIndex">,
          amount: TypedAbiArg<number | bigint, "amount">,
          recipient: TypedAbiArg<string, "recipient">,
        ],
        Response<Response<boolean, bigint>, bigint>
      >,
    },
    maps: {},
    variables: {
      ERR_DEPOSIT_REPLAY: {
        name: "ERR_DEPOSIT_REPLAY",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_TXID_LEN: {
        name: "ERR_TXID_LEN",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      txidLength: {
        name: "txid-length",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_DEPOSIT_REPLAY: {
        isOk: false,
        value: 301n,
      },
      ERR_TXID_LEN: {
        isOk: false,
        value: 300n,
      },
      txidLength: 32n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch25",
    clarity_version: "Clarity2",
    contractName: "sbtc-deposit",
  },
  sbtcRegistry: {
    functions: {
      incrementLastWithdrawalRequestId: {
        name: "increment-last-withdrawal-request-id",
        access: "private",
        args: [],
        outputs: { type: "uint128" },
      } as TypedAbiFunction<[], bigint>,
      validateCaller: {
        name: "validate-caller",
        access: "private",
        args: [],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<[], Response<boolean, bigint>>,
      completeDeposit: {
        name: "complete-deposit",
        access: "public",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
          { name: "amount", type: "uint128" },
          { name: "recipient", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, "txid">,
          voutIndex: TypedAbiArg<number | bigint, "voutIndex">,
          amount: TypedAbiArg<number | bigint, "amount">,
          recipient: TypedAbiArg<string, "recipient">,
        ],
        Response<boolean, bigint>
      >,
      createWithdrawalRequest: {
        name: "create-withdrawal-request",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "max-fee", type: "uint128" },
          { name: "sender", type: "principal" },
          {
            name: "recipient",
            type: {
              tuple: [
                { name: "hashbytes", type: { buffer: { length: 32 } } },
                { name: "version", type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: "height", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          maxFee: TypedAbiArg<number | bigint, "maxFee">,
          sender: TypedAbiArg<string, "sender">,
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            "recipient"
          >,
          height: TypedAbiArg<number | bigint, "height">,
        ],
        Response<bigint, bigint>
      >,
      rotateKeys: {
        name: "rotate-keys",
        access: "public",
        args: [
          {
            name: "new-keys",
            type: { list: { type: { buffer: { length: 32 } }, length: 15 } },
          },
          { name: "new-address", type: "principal" },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], "newKeys">,
          newAddress: TypedAbiArg<string, "newAddress">,
          newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">,
        ],
        Response<boolean, bigint>
      >,
      getCompletedDeposit: {
        name: "get-completed-deposit",
        access: "read_only",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: "amount", type: "uint128" },
                { name: "recipient", type: "principal" },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, "txid">,
          voutIndex: TypedAbiArg<number | bigint, "voutIndex">,
        ],
        {
          amount: bigint;
          recipient: string;
        } | null
      >,
      getCurrentAggregatePubkey: {
        name: "get-current-aggregate-pubkey",
        access: "read_only",
        args: [],
        outputs: { type: { buffer: { length: 32 } } },
      } as TypedAbiFunction<[], Uint8Array>,
      getCurrentSignerData: {
        name: "get-current-signer-data",
        access: "read_only",
        args: [],
        outputs: {
          type: {
            tuple: [
              {
                name: "current-aggregate-pubkey",
                type: { buffer: { length: 32 } },
              },
              { name: "current-signer-principal", type: "principal" },
              {
                name: "current-signer-set",
                type: {
                  list: { type: { buffer: { length: 32 } }, length: 15 },
                },
              },
            ],
          },
        },
      } as TypedAbiFunction<
        [],
        {
          currentAggregatePubkey: Uint8Array;
          currentSignerPrincipal: string;
          currentSignerSet: Uint8Array[];
        }
      >,
      getCurrentSignerPrincipal: {
        name: "get-current-signer-principal",
        access: "read_only",
        args: [],
        outputs: { type: "principal" },
      } as TypedAbiFunction<[], string>,
      getWithdrawalRequest: {
        name: "get-withdrawal-request",
        access: "read_only",
        args: [{ name: "id", type: "uint128" }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: "amount", type: "uint128" },
                { name: "block-height", type: "uint128" },
                { name: "max-fee", type: "uint128" },
                {
                  name: "recipient",
                  type: {
                    tuple: [
                      { name: "hashbytes", type: { buffer: { length: 32 } } },
                      { name: "version", type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                { name: "sender", type: "principal" },
                { name: "status", type: { optional: "bool" } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [id: TypedAbiArg<number | bigint, "id">],
        {
          amount: bigint;
          blockHeight: bigint;
          maxFee: bigint;
          recipient: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          sender: string;
          status: boolean | null;
        } | null
      >,
    },
    maps: {
      aggregatePubkeys: {
        name: "aggregate-pubkeys",
        key: { buffer: { length: 32 } },
        value: "bool",
      } as TypedAbiMap<Uint8Array, boolean>,
      completedDeposits: {
        name: "completed-deposits",
        key: {
          tuple: [
            { name: "txid", type: { buffer: { length: 32 } } },
            { name: "vout-index", type: "uint128" },
          ],
        },
        value: {
          tuple: [
            { name: "amount", type: "uint128" },
            { name: "recipient", type: "principal" },
          ],
        },
      } as TypedAbiMap<
        {
          txid: Uint8Array;
          voutIndex: number | bigint;
        },
        {
          amount: bigint;
          recipient: string;
        }
      >,
      multiSigAddress: {
        name: "multi-sig-address",
        key: "principal",
        value: "bool",
      } as TypedAbiMap<string, boolean>,
      withdrawalRequests: {
        name: "withdrawal-requests",
        key: "uint128",
        value: {
          tuple: [
            { name: "amount", type: "uint128" },
            { name: "block-height", type: "uint128" },
            { name: "max-fee", type: "uint128" },
            {
              name: "recipient",
              type: {
                tuple: [
                  { name: "hashbytes", type: { buffer: { length: 32 } } },
                  { name: "version", type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: "sender", type: "principal" },
          ],
        },
      } as TypedAbiMap<
        number | bigint,
        {
          amount: bigint;
          blockHeight: bigint;
          maxFee: bigint;
          recipient: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          sender: string;
        }
      >,
      withdrawalStatus: {
        name: "withdrawal-status",
        key: "uint128",
        value: "bool",
      } as TypedAbiMap<number | bigint, boolean>,
    },
    variables: {
      ERR_AGG_PUBKEY_REPLAY: {
        name: "ERR_AGG_PUBKEY_REPLAY",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_REQUEST_ID: {
        name: "ERR_INVALID_REQUEST_ID",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_MULTI_SIG_REPLAY: {
        name: "ERR_MULTI_SIG_REPLAY",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNAUTHORIZED: {
        name: "ERR_UNAUTHORIZED",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      currentAggregatePubkey: {
        name: "current-aggregate-pubkey",
        type: {
          buffer: {
            length: 32,
          },
        },
        access: "variable",
      } as TypedAbiVariable<Uint8Array>,
      currentSignerPrincipal: {
        name: "current-signer-principal",
        type: "principal",
        access: "variable",
      } as TypedAbiVariable<string>,
      currentSignerSet: {
        name: "current-signer-set",
        type: {
          list: {
            type: {
              buffer: {
                length: 32,
              },
            },
            length: 15,
          },
        },
        access: "variable",
      } as TypedAbiVariable<Uint8Array[]>,
      lastWithdrawalRequestId: {
        name: "last-withdrawal-request-id",
        type: "uint128",
        access: "variable",
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_AGG_PUBKEY_REPLAY: {
        isOk: false,
        value: 402n,
      },
      ERR_INVALID_REQUEST_ID: {
        isOk: false,
        value: 401n,
      },
      ERR_MULTI_SIG_REPLAY: {
        isOk: false,
        value: 403n,
      },
      ERR_UNAUTHORIZED: {
        isOk: false,
        value: 400n,
      },
      currentAggregatePubkey: Uint8Array.from([0]),
      currentSignerPrincipal: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      currentSignerSet: [],
      lastWithdrawalRequestId: 0n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch25",
    clarity_version: "Clarity2",
    contractName: "sbtc-registry",
  },
} as const;

export const accounts = {
  wallet_4: {
    address: "ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND",
    balance: "100000000000000",
  },
  wallet_5: {
    address: "ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB",
    balance: "100000000000000",
  },
  deployer: {
    address: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    balance: "100000000000000",
  },
  wallet_8: {
    address: "ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP",
    balance: "100000000000000",
  },
  wallet_7: {
    address: "ST3PF13W7Z0RRM42A8VZRVFQ75SV1K26RXEP8YGKJ",
    balance: "100000000000000",
  },
  wallet_2: {
    address: "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
    balance: "100000000000000",
  },
  wallet_1: {
    address: "ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5",
    balance: "100000000000000",
  },
  wallet_6: {
    address: "ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0",
    balance: "100000000000000",
  },
  wallet_3: {
    address: "ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC",
    balance: "100000000000000",
  },
  faucet: {
    address: "STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6",
    balance: "100000000000000",
  },
} as const;

export const identifiers = {
  sbtcBootstrapSigners:
    "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-bootstrap-signers",
  sbtcDeposit: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-deposit",
  sbtcRegistry: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-registry",
} as const;

export const simnet = {
  accounts,
  contracts,
  identifiers,
} as const;

export const deployments = {
  sbtcBootstrapSigners: {
    devnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-bootstrap-signers",
    simnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-bootstrap-signers",
    testnet: null,
    mainnet: null,
  },
  sbtcDeposit: {
    devnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-deposit",
    simnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-deposit",
    testnet: null,
    mainnet: null,
  },
  sbtcRegistry: {
    devnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-registry",
    simnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-registry",
    testnet: null,
    mainnet: null,
  },
} as const;

export const project = {
  contracts,
  deployments,
} as const;
