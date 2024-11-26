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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
          },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 33 } } },
          { name: "new-signature-threshold", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], "newKeys">,
          newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">,
          newSignatureThreshold: TypedAbiArg<
            number | bigint,
            "newSignatureThreshold"
          >,
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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
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
      ERR_SIGNATURE_THRESHOLD: {
        name: "ERR_SIGNATURE_THRESHOLD",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      keySize: {
        name: "key-size",
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
      ERR_SIGNATURE_THRESHOLD: {
        isOk: false,
        value: 202n,
      },
      keySize: 33n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch30",
    clarity_version: "Clarity3",
    contractName: "sbtc-bootstrap-signers",
  },
  sbtcDeposit: {
    functions: {
      completeIndividualDepositsHelper: {
        name: "complete-individual-deposits-helper",
        access: "private",
        args: [
          {
            name: "deposit",
            type: {
              tuple: [
                { name: "amount", type: "uint128" },
                { name: "burn-hash", type: { buffer: { length: 32 } } },
                { name: "burn-height", type: "uint128" },
                { name: "recipient", type: "principal" },
                { name: "sweep-txid", type: { buffer: { length: 32 } } },
                { name: "txid", type: { buffer: { length: 32 } } },
                { name: "vout-index", type: "uint128" },
              ],
            },
          },
          {
            name: "helper-response",
            type: { response: { ok: "uint128", error: "uint128" } },
          },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          deposit: TypedAbiArg<
            {
              amount: number | bigint;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              recipient: string;
              sweepTxid: Uint8Array;
              txid: Uint8Array;
              voutIndex: number | bigint;
            },
            "deposit"
          >,
          helperResponse: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            "helperResponse"
          >,
        ],
        Response<bigint, bigint>
      >,
      completeDepositWrapper: {
        name: "complete-deposit-wrapper",
        access: "public",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
          { name: "amount", type: "uint128" },
          { name: "recipient", type: "principal" },
          { name: "burn-hash", type: { buffer: { length: 32 } } },
          { name: "burn-height", type: "uint128" },
          { name: "sweep-txid", type: { buffer: { length: 32 } } },
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
          burnHash: TypedAbiArg<Uint8Array, "burnHash">,
          burnHeight: TypedAbiArg<number | bigint, "burnHeight">,
          sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">,
        ],
        Response<Response<boolean, bigint>, bigint>
      >,
      completeDepositsWrapper: {
        name: "complete-deposits-wrapper",
        access: "public",
        args: [
          {
            name: "deposits",
            type: {
              list: {
                type: {
                  tuple: [
                    { name: "amount", type: "uint128" },
                    { name: "burn-hash", type: { buffer: { length: 32 } } },
                    { name: "burn-height", type: "uint128" },
                    { name: "recipient", type: "principal" },
                    { name: "sweep-txid", type: { buffer: { length: 32 } } },
                    { name: "txid", type: { buffer: { length: 32 } } },
                    { name: "vout-index", type: "uint128" },
                  ],
                },
                length: 650,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          deposits: TypedAbiArg<
            {
              amount: number | bigint;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              recipient: string;
              sweepTxid: Uint8Array;
              txid: Uint8Array;
              voutIndex: number | bigint;
            }[],
            "deposits"
          >,
        ],
        Response<bigint, bigint>
      >,
      getBurnHeader: {
        name: "get-burn-header",
        access: "read_only",
        args: [{ name: "height", type: "uint128" }],
        outputs: { type: { optional: { buffer: { length: 32 } } } },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, "height">],
        Uint8Array | null
      >,
    },
    maps: {},
    variables: {
      ERR_DEPOSIT: {
        name: "ERR_DEPOSIT",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_DEPOSIT_INDEX_PREFIX: {
        name: "ERR_DEPOSIT_INDEX_PREFIX",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
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
      ERR_INVALID_BURN_HASH: {
        name: "ERR_INVALID_BURN_HASH",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
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
      ERR_LOWER_THAN_DUST: {
        name: "ERR_LOWER_THAN_DUST",
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
      dustLimit: {
        name: "dust-limit",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      txidLength: {
        name: "txid-length",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_DEPOSIT: {
        isOk: false,
        value: 303n,
      },
      ERR_DEPOSIT_INDEX_PREFIX: 303n,
      ERR_DEPOSIT_REPLAY: {
        isOk: false,
        value: 301n,
      },
      ERR_INVALID_BURN_HASH: {
        isOk: false,
        value: 305n,
      },
      ERR_INVALID_CALLER: {
        isOk: false,
        value: 304n,
      },
      ERR_LOWER_THAN_DUST: {
        isOk: false,
        value: 302n,
      },
      ERR_TXID_LEN: {
        isOk: false,
        value: 300n,
      },
      dustLimit: 546n,
      txidLength: 32n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch30",
    clarity_version: "Clarity3",
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
      completeDeposit: {
        name: "complete-deposit",
        access: "public",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
          { name: "amount", type: "uint128" },
          { name: "recipient", type: "principal" },
          { name: "burn-hash", type: { buffer: { length: 32 } } },
          { name: "burn-height", type: "uint128" },
          { name: "sweep-txid", type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, "txid">,
          voutIndex: TypedAbiArg<number | bigint, "voutIndex">,
          amount: TypedAbiArg<number | bigint, "amount">,
          recipient: TypedAbiArg<string, "recipient">,
          burnHash: TypedAbiArg<Uint8Array, "burnHash">,
          burnHeight: TypedAbiArg<number | bigint, "burnHeight">,
          sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawalAccept: {
        name: "complete-withdrawal-accept",
        access: "public",
        args: [
          { name: "request-id", type: "uint128" },
          { name: "bitcoin-txid", type: { buffer: { length: 32 } } },
          { name: "output-index", type: "uint128" },
          { name: "signer-bitmap", type: "uint128" },
          { name: "fee", type: "uint128" },
          { name: "burn-hash", type: { buffer: { length: 32 } } },
          { name: "burn-height", type: "uint128" },
          { name: "sweep-txid", type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, "requestId">,
          bitcoinTxid: TypedAbiArg<Uint8Array, "bitcoinTxid">,
          outputIndex: TypedAbiArg<number | bigint, "outputIndex">,
          signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">,
          fee: TypedAbiArg<number | bigint, "fee">,
          burnHash: TypedAbiArg<Uint8Array, "burnHash">,
          burnHeight: TypedAbiArg<number | bigint, "burnHeight">,
          sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawalReject: {
        name: "complete-withdrawal-reject",
        access: "public",
        args: [
          { name: "request-id", type: "uint128" },
          { name: "signer-bitmap", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, "requestId">,
          signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">,
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
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
          },
          { name: "new-address", type: "principal" },
          { name: "new-aggregate-pubkey", type: { buffer: { length: 33 } } },
          { name: "new-signature-threshold", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], "newKeys">,
          newAddress: TypedAbiArg<string, "newAddress">,
          newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">,
          newSignatureThreshold: TypedAbiArg<
            number | bigint,
            "newSignatureThreshold"
          >,
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
                { name: "sweep-burn-hash", type: { buffer: { length: 32 } } },
                { name: "sweep-burn-height", type: "uint128" },
                { name: "sweep-txid", type: { buffer: { length: 32 } } },
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
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        } | null
      >,
      getCompletedWithdrawalSweepData: {
        name: "get-completed-withdrawal-sweep-data",
        access: "read_only",
        args: [{ name: "id", type: "uint128" }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: "sweep-burn-hash", type: { buffer: { length: 32 } } },
                { name: "sweep-burn-height", type: "uint128" },
                { name: "sweep-txid", type: { buffer: { length: 32 } } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [id: TypedAbiArg<number | bigint, "id">],
        {
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
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
              { name: "current-signature-threshold", type: "uint128" },
              { name: "current-signer-principal", type: "principal" },
              {
                name: "current-signer-set",
                type: {
                  list: { type: { buffer: { length: 33 } }, length: 128 },
                },
              },
            ],
          },
        },
      } as TypedAbiFunction<
        [],
        {
          currentAggregatePubkey: Uint8Array;
          currentSignatureThreshold: bigint;
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
          type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
        },
      } as TypedAbiFunction<[], Uint8Array[]>,
      getDepositStatus: {
        name: "get-deposit-status",
        access: "read_only",
        args: [
          { name: "txid", type: { buffer: { length: 32 } } },
          { name: "vout-index", type: "uint128" },
        ],
        outputs: { type: { optional: "bool" } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, "txid">,
          voutIndex: TypedAbiArg<number | bigint, "voutIndex">,
        ],
        boolean | null
      >,
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
      isProtocolCaller: {
        name: "is-protocol-caller",
        access: "read_only",
        args: [],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<[], Response<boolean, bigint>>,
      validateProtocolCaller: {
        name: "validate-protocol-caller",
        access: "read_only",
        args: [{ name: "caller", type: "principal" }],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [caller: TypedAbiArg<string, "caller">],
        Response<boolean, bigint>
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
            { name: "sweep-burn-hash", type: { buffer: { length: 32 } } },
            { name: "sweep-burn-height", type: "uint128" },
            { name: "sweep-txid", type: { buffer: { length: 32 } } },
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
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        }
      >,
      completedWithdrawalSweep: {
        name: "completed-withdrawal-sweep",
        key: "uint128",
        value: {
          tuple: [
            { name: "sweep-burn-hash", type: { buffer: { length: 32 } } },
            { name: "sweep-burn-height", type: "uint128" },
            { name: "sweep-txid", type: { buffer: { length: 32 } } },
          ],
        },
      } as TypedAbiMap<
        number | bigint,
        {
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        }
      >,
      depositStatus: {
        name: "deposit-status",
        key: {
          tuple: [
            { name: "txid", type: { buffer: { length: 32 } } },
            { name: "vout-index", type: "uint128" },
          ],
        },
        value: "bool",
      } as TypedAbiMap<
        {
          txid: Uint8Array;
          voutIndex: number | bigint;
        },
        boolean
      >,
      protocolContracts: {
        name: "protocol-contracts",
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
      currentSignatureThreshold: {
        name: "current-signature-threshold",
        type: "uint128",
        access: "variable",
      } as TypedAbiVariable<bigint>,
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
            length: 128,
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
      currentSignatureThreshold: 0n,
      currentSignerPrincipal: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039",
      currentSignerSet: [],
      lastWithdrawalRequestId: 0n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch30",
    clarity_version: "Clarity3",
    contractName: "sbtc-registry",
  },
  sbtcToken: {
    functions: {
      protocolMintManyIter: {
        name: "protocol-mint-many-iter",
        access: "private",
        args: [
          {
            name: "item",
            type: {
              tuple: [
                { name: "amount", type: "uint128" },
                { name: "recipient", type: "principal" },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          item: TypedAbiArg<
            {
              amount: number | bigint;
              recipient: string;
            },
            "item"
          >,
        ],
        Response<boolean, bigint>
      >,
      protocolBurn: {
        name: "protocol-burn",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "owner", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          owner: TypedAbiArg<string, "owner">,
        ],
        Response<boolean, bigint>
      >,
      protocolBurnLocked: {
        name: "protocol-burn-locked",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "owner", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          owner: TypedAbiArg<string, "owner">,
        ],
        Response<boolean, bigint>
      >,
      protocolLock: {
        name: "protocol-lock",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "owner", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          owner: TypedAbiArg<string, "owner">,
        ],
        Response<boolean, bigint>
      >,
      protocolMint: {
        name: "protocol-mint",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "recipient", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          recipient: TypedAbiArg<string, "recipient">,
        ],
        Response<boolean, bigint>
      >,
      protocolMintMany: {
        name: "protocol-mint-many",
        access: "public",
        args: [
          {
            name: "recipients",
            type: {
              list: {
                type: {
                  tuple: [
                    { name: "amount", type: "uint128" },
                    { name: "recipient", type: "principal" },
                  ],
                },
                length: 200,
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                list: {
                  type: { response: { ok: "bool", error: "uint128" } },
                  length: 200,
                },
              },
              error: "uint128",
            },
          },
        },
      } as TypedAbiFunction<
        [
          recipients: TypedAbiArg<
            {
              amount: number | bigint;
              recipient: string;
            }[],
            "recipients"
          >,
        ],
        Response<Response<boolean, bigint>[], bigint>
      >,
      protocolSetName: {
        name: "protocol-set-name",
        access: "public",
        args: [{ name: "new-name", type: { "string-ascii": { length: 32 } } }],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [newName: TypedAbiArg<string, "newName">],
        Response<boolean, bigint>
      >,
      protocolSetSymbol: {
        name: "protocol-set-symbol",
        access: "public",
        args: [
          { name: "new-symbol", type: { "string-ascii": { length: 10 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [newSymbol: TypedAbiArg<string, "newSymbol">],
        Response<boolean, bigint>
      >,
      protocolSetTokenUri: {
        name: "protocol-set-token-uri",
        access: "public",
        args: [
          {
            name: "new-uri",
            type: { optional: { "string-utf8": { length: 256 } } },
          },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [newUri: TypedAbiArg<string | null, "newUri">],
        Response<boolean, bigint>
      >,
      protocolTransfer: {
        name: "protocol-transfer",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "sender", type: "principal" },
          { name: "recipient", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          sender: TypedAbiArg<string, "sender">,
          recipient: TypedAbiArg<string, "recipient">,
        ],
        Response<boolean, bigint>
      >,
      protocolUnlock: {
        name: "protocol-unlock",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "owner", type: "principal" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          owner: TypedAbiArg<string, "owner">,
        ],
        Response<boolean, bigint>
      >,
      transfer: {
        name: "transfer",
        access: "public",
        args: [
          { name: "amount", type: "uint128" },
          { name: "sender", type: "principal" },
          { name: "recipient", type: "principal" },
          { name: "memo", type: { optional: { buffer: { length: 34 } } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, "amount">,
          sender: TypedAbiArg<string, "sender">,
          recipient: TypedAbiArg<string, "recipient">,
          memo: TypedAbiArg<Uint8Array | null, "memo">,
        ],
        Response<boolean, bigint>
      >,
      getBalance: {
        name: "get-balance",
        access: "read_only",
        args: [{ name: "who", type: "principal" }],
        outputs: { type: { response: { ok: "uint128", error: "none" } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, "who">],
        Response<bigint, null>
      >,
      getBalanceAvailable: {
        name: "get-balance-available",
        access: "read_only",
        args: [{ name: "who", type: "principal" }],
        outputs: { type: { response: { ok: "uint128", error: "none" } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, "who">],
        Response<bigint, null>
      >,
      getBalanceLocked: {
        name: "get-balance-locked",
        access: "read_only",
        args: [{ name: "who", type: "principal" }],
        outputs: { type: { response: { ok: "uint128", error: "none" } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, "who">],
        Response<bigint, null>
      >,
      getDecimals: {
        name: "get-decimals",
        access: "read_only",
        args: [],
        outputs: { type: { response: { ok: "uint128", error: "none" } } },
      } as TypedAbiFunction<[], Response<bigint, null>>,
      getName: {
        name: "get-name",
        access: "read_only",
        args: [],
        outputs: {
          type: {
            response: { ok: { "string-ascii": { length: 32 } }, error: "none" },
          },
        },
      } as TypedAbiFunction<[], Response<string, null>>,
      getSymbol: {
        name: "get-symbol",
        access: "read_only",
        args: [],
        outputs: {
          type: {
            response: { ok: { "string-ascii": { length: 10 } }, error: "none" },
          },
        },
      } as TypedAbiFunction<[], Response<string, null>>,
      getTokenUri: {
        name: "get-token-uri",
        access: "read_only",
        args: [],
        outputs: {
          type: {
            response: {
              ok: { optional: { "string-utf8": { length: 256 } } },
              error: "none",
            },
          },
        },
      } as TypedAbiFunction<[], Response<string | null, null>>,
      getTotalSupply: {
        name: "get-total-supply",
        access: "read_only",
        args: [],
        outputs: { type: { response: { ok: "uint128", error: "none" } } },
      } as TypedAbiFunction<[], Response<bigint, null>>,
    },
    maps: {},
    variables: {
      ERR_NOT_AUTH: {
        name: "ERR_NOT_AUTH",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NOT_OWNER: {
        name: "ERR_NOT_OWNER",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      tokenDecimals: {
        name: "token-decimals",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      tokenName: {
        name: "token-name",
        type: {
          "string-ascii": {
            length: 32,
          },
        },
        access: "variable",
      } as TypedAbiVariable<string>,
      tokenSymbol: {
        name: "token-symbol",
        type: {
          "string-ascii": {
            length: 10,
          },
        },
        access: "variable",
      } as TypedAbiVariable<string>,
      tokenUri: {
        name: "token-uri",
        type: {
          optional: {
            "string-utf8": {
              length: 256,
            },
          },
        },
        access: "variable",
      } as TypedAbiVariable<string | null>,
    },
    constants: {
      ERR_NOT_AUTH: {
        isOk: false,
        value: 5n,
      },
      ERR_NOT_OWNER: {
        isOk: false,
        value: 4n,
      },
      tokenDecimals: 8n,
      tokenName: "sBTC",
      tokenSymbol: "sBTC",
      tokenUri: null,
    },
    non_fungible_tokens: [],
    fungible_tokens: [{ name: "sbtc-token" }, { name: "sbtc-token-locked" }],
    epoch: "Epoch30",
    clarity_version: "Clarity3",
    contractName: "sbtc-token",
  },
  sbtcWithdrawal: {
    functions: {
      completeIndividualWithdrawalHelper: {
        name: "complete-individual-withdrawal-helper",
        access: "private",
        args: [
          {
            name: "withdrawal",
            type: {
              tuple: [
                {
                  name: "bitcoin-txid",
                  type: { optional: { buffer: { length: 32 } } },
                },
                { name: "burn-hash", type: { buffer: { length: 32 } } },
                { name: "burn-height", type: "uint128" },
                { name: "fee", type: { optional: "uint128" } },
                { name: "output-index", type: { optional: "uint128" } },
                { name: "request-id", type: "uint128" },
                { name: "signer-bitmap", type: "uint128" },
                { name: "status", type: "bool" },
                {
                  name: "sweep-txid",
                  type: { optional: { buffer: { length: 32 } } },
                },
              ],
            },
          },
          {
            name: "helper-response",
            type: { response: { ok: "uint128", error: "uint128" } },
          },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          withdrawal: TypedAbiArg<
            {
              bitcoinTxid: Uint8Array | null;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              fee: number | bigint | null;
              outputIndex: number | bigint | null;
              requestId: number | bigint;
              signerBitmap: number | bigint;
              status: boolean;
              sweepTxid: Uint8Array | null;
            },
            "withdrawal"
          >,
          helperResponse: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            "helperResponse"
          >,
        ],
        Response<bigint, bigint>
      >,
      acceptWithdrawalRequest: {
        name: "accept-withdrawal-request",
        access: "public",
        args: [
          { name: "request-id", type: "uint128" },
          { name: "bitcoin-txid", type: { buffer: { length: 32 } } },
          { name: "signer-bitmap", type: "uint128" },
          { name: "output-index", type: "uint128" },
          { name: "fee", type: "uint128" },
          { name: "burn-hash", type: { buffer: { length: 32 } } },
          { name: "burn-height", type: "uint128" },
          { name: "sweep-txid", type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, "requestId">,
          bitcoinTxid: TypedAbiArg<Uint8Array, "bitcoinTxid">,
          signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">,
          outputIndex: TypedAbiArg<number | bigint, "outputIndex">,
          fee: TypedAbiArg<number | bigint, "fee">,
          burnHash: TypedAbiArg<Uint8Array, "burnHash">,
          burnHeight: TypedAbiArg<number | bigint, "burnHeight">,
          sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawals: {
        name: "complete-withdrawals",
        access: "public",
        args: [
          {
            name: "withdrawals",
            type: {
              list: {
                type: {
                  tuple: [
                    {
                      name: "bitcoin-txid",
                      type: { optional: { buffer: { length: 32 } } },
                    },
                    { name: "burn-hash", type: { buffer: { length: 32 } } },
                    { name: "burn-height", type: "uint128" },
                    { name: "fee", type: { optional: "uint128" } },
                    { name: "output-index", type: { optional: "uint128" } },
                    { name: "request-id", type: "uint128" },
                    { name: "signer-bitmap", type: "uint128" },
                    { name: "status", type: "bool" },
                    {
                      name: "sweep-txid",
                      type: { optional: { buffer: { length: 32 } } },
                    },
                  ],
                },
                length: 600,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: "uint128", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          withdrawals: TypedAbiArg<
            {
              bitcoinTxid: Uint8Array | null;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              fee: number | bigint | null;
              outputIndex: number | bigint | null;
              requestId: number | bigint;
              signerBitmap: number | bigint;
              status: boolean;
              sweepTxid: Uint8Array | null;
            }[],
            "withdrawals"
          >,
        ],
        Response<bigint, bigint>
      >,
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
      rejectWithdrawalRequest: {
        name: "reject-withdrawal-request",
        access: "public",
        args: [
          { name: "request-id", type: "uint128" },
          { name: "signer-bitmap", type: "uint128" },
        ],
        outputs: { type: { response: { ok: "bool", error: "uint128" } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, "requestId">,
          signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">,
        ],
        Response<boolean, bigint>
      >,
      getBurnHeader: {
        name: "get-burn-header",
        access: "read_only",
        args: [{ name: "height", type: "uint128" }],
        outputs: { type: { optional: { buffer: { length: 32 } } } },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, "height">],
        Uint8Array | null
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
      DUST_LIMIT: {
        name: "DUST_LIMIT",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
      ERR_ALREADY_PROCESSED: {
        name: "ERR_ALREADY_PROCESSED",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_DUST_LIMIT: {
        name: "ERR_DUST_LIMIT",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_FEE_TOO_HIGH: {
        name: "ERR_FEE_TOO_HIGH",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
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
      ERR_INVALID_BURN_HASH: {
        name: "ERR_INVALID_BURN_HASH",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
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
      ERR_INVALID_REQUEST: {
        name: "ERR_INVALID_REQUEST",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_WITHDRAWAL_INDEX: {
        name: "ERR_WITHDRAWAL_INDEX",
        type: {
          response: {
            ok: "none",
            error: "uint128",
          },
        },
        access: "constant",
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_WITHDRAWAL_INDEX_PREFIX: {
        name: "ERR_WITHDRAWAL_INDEX_PREFIX",
        type: "uint128",
        access: "constant",
      } as TypedAbiVariable<bigint>,
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
      DUST_LIMIT: 546n,
      ERR_ALREADY_PROCESSED: {
        isOk: false,
        value: 505n,
      },
      ERR_DUST_LIMIT: {
        isOk: false,
        value: 502n,
      },
      ERR_FEE_TOO_HIGH: {
        isOk: false,
        value: 506n,
      },
      ERR_INVALID_ADDR_HASHBYTES: {
        isOk: false,
        value: 501n,
      },
      ERR_INVALID_ADDR_VERSION: {
        isOk: false,
        value: 500n,
      },
      ERR_INVALID_BURN_HASH: {
        isOk: false,
        value: 508n,
      },
      ERR_INVALID_CALLER: {
        isOk: false,
        value: 504n,
      },
      ERR_INVALID_REQUEST: {
        isOk: false,
        value: 503n,
      },
      ERR_WITHDRAWAL_INDEX: {
        isOk: false,
        value: 507n,
      },
      ERR_WITHDRAWAL_INDEX_PREFIX: 507n,
      MAX_ADDRESS_VERSION: 6n,
      mAX_ADDRESS_VERSION_BUFF_20: 4n,
      mAX_ADDRESS_VERSION_BUFF_32: 6n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: "Epoch30",
    clarity_version: "Clarity3",
    contractName: "sbtc-withdrawal",
  },
} as const;

export const accounts = {
  deployer: {
    address: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039",
    balance: "100000000000000",
  },
  faucet: {
    address: "STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6",
    balance: "100000000000000",
  },
  wallet_1: {
    address: "ST1YEHRRYJ4GF9CYBFFN0ZVCXX1APSBEEQ5KEDN7M",
    balance: "100000000000000",
  },
  wallet_2: {
    address: "ST1WNJTS9JM1JYGK758B10DBAMBZ0K23ADP392SBV",
    balance: "100000000000000",
  },
  wallet_3: {
    address: "ST1MDWBDVDGAANEH9001HGXQA6XRNK7PX7A7X8M6R",
    balance: "100000000000000",
  },
} as const;

export const identifiers = {
  sbtcBootstrapSigners:
    "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-bootstrap-signers",
  sbtcDeposit: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-deposit",
  sbtcRegistry: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-registry",
  sbtcToken: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-token",
  sbtcWithdrawal: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-withdrawal",
} as const;

export const simnet = {
  accounts,
  contracts,
  identifiers,
} as const;

export const deployments = {
  sbtcBootstrapSigners: {
    devnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-bootstrap-signers",
    simnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-bootstrap-signers",
    testnet: null,
    mainnet: null,
  },
  sbtcDeposit: {
    devnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-deposit",
    simnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-deposit",
    testnet: null,
    mainnet: null,
  },
  sbtcRegistry: {
    devnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-registry",
    simnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-registry",
    testnet: null,
    mainnet: null,
  },
  sbtcToken: {
    devnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-token",
    simnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-token",
    testnet: null,
    mainnet: null,
  },
  sbtcWithdrawal: {
    devnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-withdrawal",
    simnet: "ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039.sbtc-withdrawal",
    testnet: null,
    mainnet: null,
  },
} as const;

export const project = {
  contracts,
  deployments,
} as const;
