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
          { name: "current-key", type: { buffer: { length: 33 } } },
          {
            name: "helper-response",
            type: { response: { ok: "uint128", error: "uint128" } },
          },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          currentKey: TypedAbiArg<Uint8Array, "currentKey">,
          helperResponse: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            "helperResponse"
          >,
        ],
        Response<bigint, bigint>
      >,
      rotateKeysWrapper: {
        name: "rotate-keys-wrapper",
        access: "public",
        args: [
          {
            name: "new-keys",
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 33 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], "newKeys">,
          newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">,
        ],
        Response<boolean, bigint>
      >,
      bytesLen: {
        name: "bytes-len",
        access: "read_only",
        args: [{ name: "bytes", type: { buffer: { length: 33 } } }],
        outputs: { type: { buffer: { length: 1 } } },
      } as TypedAbiFunction<
        [bytes: TypedAbiArg<Uint8Array, "bytes">],
        Uint8Array
      >,
      concatPubkeysFold: {
        name: "concat-pubkeys-fold",
        access: "read_only",
        args: [
          { name: "pubkey", type: { buffer: { length: 33 } } },
          { name: "iterator", type: { buffer: { length: 510 } } },
        ],
        outputs: { type: { buffer: { length: 510 } } },
      } as TypedAbiFunction<
        [
          pubkey: TypedAbiArg<Uint8Array, "pubkey">,
          iterator: TypedAbiArg<Uint8Array, "iterator">,
        ],
        Uint8Array
      >,
      pubkeysToBytes: {
        name: "pubkeys-to-bytes",
        access: "read_only",
        args: [
          {
            name: "pubkeys",
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
        ],
        outputs: { type: { buffer: { length: 510 } } },
      } as TypedAbiFunction<
        [pubkeys: TypedAbiArg<Uint8Array[], "pubkeys">],
        Uint8Array
      >,
      pubkeysToHash: {
        name: "pubkeys-to-hash",
        access: "read_only",
        args: [
          {
            name: "pubkeys",
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
          { name: "m", type: "uint128" },
        ],
        outputs: { type: { buffer: { length: 20 } } },
      } as TypedAbiFunction<
        [
          pubkeys: TypedAbiArg<Uint8Array[], "pubkeys">,
          m: TypedAbiArg<number | bigint, "m">,
        ],
        Uint8Array
      >,
      pubkeysToPrincipal: {
        name: "pubkeys-to-principal",
        access: "read_only",
        args: [
          {
            name: "pubkeys",
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
          { name: "m", type: "uint128" },
        ],
        outputs: { type: "principal" },
      } as TypedAbiFunction<
        [
          pubkeys: TypedAbiArg<Uint8Array[], "pubkeys">,
          m: TypedAbiArg<number | bigint, "m">,
        ],
        string
      >,
      pubkeysToSpendScript: {
        name: "pubkeys-to-spend-script",
        access: "read_only",
        args: [
          {
            name: "pubkeys",
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
          { name: "m", type: "uint128" },
        ],
        outputs: { type: { buffer: { length: 513 } } },
      } as TypedAbiFunction<
        [
          pubkeys: TypedAbiArg<Uint8Array[], "pubkeys">,
          m: TypedAbiArg<number | bigint, "m">,
        ],
        Uint8Array
      >,
      uintToByte: {
        name: "uint-to-byte",
        access: "read_only",
        args: [{ name: "n", type: "uint128" }],
        outputs: { type: { buffer: { length: 1 } } },
      } as TypedAbiFunction<[n: TypedAbiArg<number | bigint, "n">], Uint8Array>,
    },
    maps: {},
    variables: {
      BUFF_TO_BYTE: {
        name: "BUFF_TO_BYTE",
        type: {
          list: {
            type: {
              buffer: {
                length: 1,
              },
            },
            length: 256,
          },
        },
        access: "constant",
      } as TypedAbiVariable<Uint8Array[]>,
      ERR_INVALID_CALLER: {
        name: "ERR_INVALID_CALLER",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
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
      BUFF_TO_BYTE: [
        Uint8Array.from([0]),
        Uint8Array.from([1]),
        Uint8Array.from([2]),
        Uint8Array.from([3]),
        Uint8Array.from([4]),
        Uint8Array.from([5]),
        Uint8Array.from([6]),
        Uint8Array.from([7]),
        Uint8Array.from([8]),
        Uint8Array.from([9]),
        Uint8Array.from([10]),
        Uint8Array.from([11]),
        Uint8Array.from([12]),
        Uint8Array.from([13]),
        Uint8Array.from([14]),
        Uint8Array.from([15]),
        Uint8Array.from([16]),
        Uint8Array.from([17]),
        Uint8Array.from([18]),
        Uint8Array.from([19]),
        Uint8Array.from([20]),
        Uint8Array.from([21]),
        Uint8Array.from([22]),
        Uint8Array.from([23]),
        Uint8Array.from([24]),
        Uint8Array.from([25]),
        Uint8Array.from([26]),
        Uint8Array.from([27]),
        Uint8Array.from([28]),
        Uint8Array.from([29]),
        Uint8Array.from([30]),
        Uint8Array.from([31]),
        Uint8Array.from([32]),
        Uint8Array.from([33]),
        Uint8Array.from([34]),
        Uint8Array.from([35]),
        Uint8Array.from([36]),
        Uint8Array.from([37]),
        Uint8Array.from([38]),
        Uint8Array.from([39]),
        Uint8Array.from([40]),
        Uint8Array.from([41]),
        Uint8Array.from([42]),
        Uint8Array.from([43]),
        Uint8Array.from([44]),
        Uint8Array.from([45]),
        Uint8Array.from([46]),
        Uint8Array.from([47]),
        Uint8Array.from([48]),
        Uint8Array.from([49]),
        Uint8Array.from([51]),
        Uint8Array.from([51]),
        Uint8Array.from([52]),
        Uint8Array.from([53]),
        Uint8Array.from([54]),
        Uint8Array.from([55]),
        Uint8Array.from([56]),
        Uint8Array.from([57]),
        Uint8Array.from([58]),
        Uint8Array.from([59]),
        Uint8Array.from([60]),
        Uint8Array.from([61]),
        Uint8Array.from([62]),
        Uint8Array.from([63]),
        Uint8Array.from([64]),
        Uint8Array.from([65]),
        Uint8Array.from([66]),
        Uint8Array.from([67]),
        Uint8Array.from([68]),
        Uint8Array.from([69]),
        Uint8Array.from([70]),
        Uint8Array.from([71]),
        Uint8Array.from([72]),
        Uint8Array.from([73]),
        Uint8Array.from([74]),
        Uint8Array.from([75]),
        Uint8Array.from([76]),
        Uint8Array.from([77]),
        Uint8Array.from([78]),
        Uint8Array.from([79]),
        Uint8Array.from([80]),
        Uint8Array.from([81]),
        Uint8Array.from([82]),
        Uint8Array.from([83]),
        Uint8Array.from([84]),
        Uint8Array.from([85]),
        Uint8Array.from([86]),
        Uint8Array.from([87]),
        Uint8Array.from([88]),
        Uint8Array.from([89]),
        Uint8Array.from([90]),
        Uint8Array.from([91]),
        Uint8Array.from([92]),
        Uint8Array.from([93]),
        Uint8Array.from([94]),
        Uint8Array.from([95]),
        Uint8Array.from([96]),
        Uint8Array.from([97]),
        Uint8Array.from([98]),
        Uint8Array.from([99]),
        Uint8Array.from([100]),
        Uint8Array.from([101]),
        Uint8Array.from([102]),
        Uint8Array.from([103]),
        Uint8Array.from([104]),
        Uint8Array.from([105]),
        Uint8Array.from([106]),
        Uint8Array.from([107]),
        Uint8Array.from([108]),
        Uint8Array.from([109]),
        Uint8Array.from([110]),
        Uint8Array.from([111]),
        Uint8Array.from([112]),
        Uint8Array.from([113]),
        Uint8Array.from([114]),
        Uint8Array.from([115]),
        Uint8Array.from([116]),
        Uint8Array.from([117]),
        Uint8Array.from([118]),
        Uint8Array.from([119]),
        Uint8Array.from([120]),
        Uint8Array.from([121]),
        Uint8Array.from([122]),
        Uint8Array.from([123]),
        Uint8Array.from([124]),
        Uint8Array.from([125]),
        Uint8Array.from([126]),
        Uint8Array.from([127]),
        Uint8Array.from([128]),
        Uint8Array.from([129]),
        Uint8Array.from([130]),
        Uint8Array.from([131]),
        Uint8Array.from([132]),
        Uint8Array.from([133]),
        Uint8Array.from([134]),
        Uint8Array.from([135]),
        Uint8Array.from([136]),
        Uint8Array.from([137]),
        Uint8Array.from([138]),
        Uint8Array.from([139]),
        Uint8Array.from([140]),
        Uint8Array.from([141]),
        Uint8Array.from([142]),
        Uint8Array.from([143]),
        Uint8Array.from([144]),
        Uint8Array.from([145]),
        Uint8Array.from([146]),
        Uint8Array.from([147]),
        Uint8Array.from([148]),
        Uint8Array.from([149]),
        Uint8Array.from([150]),
        Uint8Array.from([151]),
        Uint8Array.from([152]),
        Uint8Array.from([153]),
        Uint8Array.from([154]),
        Uint8Array.from([155]),
        Uint8Array.from([156]),
        Uint8Array.from([157]),
        Uint8Array.from([158]),
        Uint8Array.from([159]),
        Uint8Array.from([160]),
        Uint8Array.from([161]),
        Uint8Array.from([162]),
        Uint8Array.from([163]),
        Uint8Array.from([164]),
        Uint8Array.from([165]),
        Uint8Array.from([166]),
        Uint8Array.from([167]),
        Uint8Array.from([168]),
        Uint8Array.from([169]),
        Uint8Array.from([170]),
        Uint8Array.from([171]),
        Uint8Array.from([172]),
        Uint8Array.from([173]),
        Uint8Array.from([174]),
        Uint8Array.from([175]),
        Uint8Array.from([176]),
        Uint8Array.from([177]),
        Uint8Array.from([178]),
        Uint8Array.from([179]),
        Uint8Array.from([180]),
        Uint8Array.from([181]),
        Uint8Array.from([182]),
        Uint8Array.from([183]),
        Uint8Array.from([184]),
        Uint8Array.from([185]),
        Uint8Array.from([186]),
        Uint8Array.from([187]),
        Uint8Array.from([188]),
        Uint8Array.from([189]),
        Uint8Array.from([190]),
        Uint8Array.from([191]),
        Uint8Array.from([192]),
        Uint8Array.from([193]),
        Uint8Array.from([194]),
        Uint8Array.from([195]),
        Uint8Array.from([196]),
        Uint8Array.from([197]),
        Uint8Array.from([198]),
        Uint8Array.from([199]),
        Uint8Array.from([200]),
        Uint8Array.from([201]),
        Uint8Array.from([202]),
        Uint8Array.from([203]),
        Uint8Array.from([204]),
        Uint8Array.from([205]),
        Uint8Array.from([206]),
        Uint8Array.from([207]),
        Uint8Array.from([208]),
        Uint8Array.from([209]),
        Uint8Array.from([210]),
        Uint8Array.from([211]),
        Uint8Array.from([212]),
        Uint8Array.from([213]),
        Uint8Array.from([214]),
        Uint8Array.from([215]),
        Uint8Array.from([216]),
        Uint8Array.from([217]),
        Uint8Array.from([218]),
        Uint8Array.from([219]),
        Uint8Array.from([220]),
        Uint8Array.from([221]),
        Uint8Array.from([222]),
        Uint8Array.from([223]),
        Uint8Array.from([224]),
        Uint8Array.from([225]),
        Uint8Array.from([226]),
        Uint8Array.from([227]),
        Uint8Array.from([228]),
        Uint8Array.from([229]),
        Uint8Array.from([230]),
        Uint8Array.from([231]),
        Uint8Array.from([232]),
        Uint8Array.from([233]),
        Uint8Array.from([234]),
        Uint8Array.from([235]),
        Uint8Array.from([236]),
        Uint8Array.from([237]),
        Uint8Array.from([238]),
        Uint8Array.from([239]),
        Uint8Array.from([240]),
        Uint8Array.from([241]),
        Uint8Array.from([242]),
        Uint8Array.from([243]),
        Uint8Array.from([244]),
        Uint8Array.from([245]),
        Uint8Array.from([246]),
        Uint8Array.from([247]),
        Uint8Array.from([248]),
        Uint8Array.from([249]),
        Uint8Array.from([250]),
        Uint8Array.from([251]),
        Uint8Array.from([252]),
        Uint8Array.from([253]),
        Uint8Array.from([254]),
        Uint8Array.from([255]),
      ],
      ERR_INVALID_CALLER: {
        isOk: false,
        value: 201n,
      },
      ERR_KEY_SIZE: {
        isOk: false,
        value: 200n,
      },
      ERR_KEY_SIZE_PREFIX: 200n,
      keySize: 33n,
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
            type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
          },
          { name: "new-address", type: "principal" },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 33 } } },
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
        outputs: { type: { buffer: { length: 33 } } },
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
                type: { buffer: { length: 33 } },
              },
              { name: "current-signer-principal", type: "principal" },
              {
                name: "current-signer-set",
                type: {
                  list: { type: { buffer: { length: 33 } }, length: 15 },
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
      getCurrentSignerSet: {
        name: "get-current-signer-set",
        access: "read_only",
        args: [],
        outputs: {
          type: { list: { type: { buffer: { length: 33 } }, length: 15 } },
        },
      } as TypedAbiFunction<[], Uint8Array[]>,
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
        key: { buffer: { length: 33 } },
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
            length: 33,
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
                length: 33,
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
  sbtcWithdrawal: {
    functions: {
      initiateWithdrawalRequest: {
        name: "initiate-withdrawal-request",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          {
            name: "recipient",
            type: {
              tuple: [
                { name: "hashbytes", type: { buffer: { length: 32 } } },
                { name: "version", type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: "max-fee", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            "recipient"
          >,
          maxFee: TypedAbiArg<number | bigint, "maxFee">,
        ],
        Response<bigint, bigint>
      >,
      validateRecipient: {
        name: "validate-recipient",
        access: "read_only",
        args: [
          {
            name: "recipient",
            type: {
              tuple: [
                { name: "hashbytes", type: { buffer: { length: 32 } } },
                { name: "version", type: { buffer: { length: 1 } } },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            "recipient"
          >,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {},
    variables: {
      ERR_INVALID_ADDR_HASHBYTES: {
        name: "ERR_INVALID_ADDR_HASHBYTES",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_ADDR_VERSION: {
        name: "ERR_INVALID_ADDR_VERSION",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      MAX_ADDRESS_VERSION: {
        name: "MAX_ADDRESS_VERSION",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_20: {
        name: "MAX_ADDRESS_VERSION_BUFF_20",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_32: {
        name: "MAX_ADDRESS_VERSION_BUFF_32",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_INVALID_ADDR_HASHBYTES: {
        isOk: false,
        value: 501n,
      },
      ERR_INVALID_ADDR_VERSION: {
        isOk: false,
        value: 500n,
      },
      MAX_ADDRESS_VERSION: 6n,
      mAX_ADDRESS_VERSION_BUFF_20: 4n,
      mAX_ADDRESS_VERSION_BUFF_32: 6n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch25",
    clarity_version: "Clarity2",
    contractName: "sbtc-withdrawal",
  },
} as const;

export const accounts = {
  deployer: {
    address: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
    balance: "100000000000000",
  },
  faucet: {
    address: "STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6",
    balance: "100000000000000",
  },
  wallet_1: {
    address: "ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5",
    balance: "100000000000000",
  },
  wallet_2: {
    address: "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
    balance: "100000000000000",
  },
  wallet_3: {
    address: "ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC",
    balance: "100000000000000",
  },
  wallet_4: {
    address: "ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND",
    balance: "100000000000000",
  },
  wallet_5: {
    address: "ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB",
    balance: "100000000000000",
  },
  wallet_6: {
    address: "ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0",
    balance: "100000000000000",
  },
  wallet_7: {
    address: "ST3PF13W7Z0RRM42A8VZRVFQ75SV1K26RXEP8YGKJ",
    balance: "100000000000000",
  },
  wallet_8: {
    address: "ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP",
    balance: "100000000000000",
  },
} as const;

export const identifiers = {
  sbtcBootstrapSigners:
    "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-bootstrap-signers",
  sbtcDeposit: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-deposit",
  sbtcRegistry: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-registry",
  sbtcWithdrawal: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-withdrawal",
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
  sbtcWithdrawal: {
    devnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-withdrawal",
    simnet: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-withdrawal",
    testnet: null,
    mainnet: null,
  },
} as const;

export const project = {
  contracts,
  deployments,
} as const;
