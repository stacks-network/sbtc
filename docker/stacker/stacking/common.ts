import { StackingClient } from '@stacks/stacking';
import { StacksTestnet } from '@stacks/network';
import {
  getAddressFromPrivateKey,
  TransactionVersion,
  createStacksPrivateKey,
} from '@stacks/transactions';
import { getPublicKeyFromPrivate, publicKeyToBtcAddress } from '@stacks/encryption';
import {
  InfoApi,
  Configuration,
  BlocksApi,
  TransactionsApi,
  SmartContractsApi,
  AccountsApi,
} from '@stacks/blockchain-api-client';
import pino, { Logger } from 'pino';

const serviceName = process.env.SERVICE_NAME || 'JS';
export let logger: Logger;
if (process.env.STACKS_LOG_JSON === '1') {
  logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    name: serviceName,
  });
} else {
  logger = pino({
    name: serviceName,
    level: process.env.LOG_LEVEL || 'info',
    transport: {
      target: 'pino-pretty',
    },
    // @ts-ignore
    options: {
      colorize: true,
    },
  });
}

export const nodeUrl = `http://${process.env.STACKS_CORE_RPC_HOST}:${process.env.STACKS_CORE_RPC_PORT}`;
export const network = new StacksTestnet({ url: nodeUrl });
const apiConfig = new Configuration({
  basePath: nodeUrl,
});
export const infoApi = new InfoApi(apiConfig);
export const blocksApi = new BlocksApi(apiConfig);
export const txApi = new TransactionsApi(apiConfig);
export const contractsApi = new SmartContractsApi(apiConfig);
export const accountsApi = new AccountsApi(apiConfig);

export const EPOCH_30_START = parseEnvInt('STACKS_30_HEIGHT', true);
export const EPOCH_25_START = parseEnvInt('STACKS_25_HEIGHT', true);
export const POX_PREPARE_LENGTH = parseEnvInt('POX_PREPARE_LENGTH', true);
export const POX_REWARD_LENGTH = parseEnvInt('POX_REWARD_LENGTH', true);

export const accounts = process.env.STACKING_KEYS!.split(',').map((privKey, index) => {
  const pubKey = getPublicKeyFromPrivate(privKey);
  const stxAddress = getAddressFromPrivateKey(privKey, TransactionVersion.Testnet);
  const signerPrivKey = createStacksPrivateKey(privKey);
  const signerPubKey = getPublicKeyFromPrivate(signerPrivKey.data);
  return {
    privKey,
    pubKey,
    stxAddress,
    btcAddr: publicKeyToBtcAddress(pubKey),
    signerPrivKey: signerPrivKey,
    signerPubKey: signerPubKey,
    targetSlots: index + 1,
    index,
    client: new StackingClient(stxAddress, network),
    logger: logger.child({
      account: stxAddress,
      index: index,
    }),
  };
});

export type Account = typeof accounts[0];

export const MAX_U128 = 2n ** 128n - 1n;
export const maxAmount = MAX_U128;

export async function waitForSetup() {
  try {
    await accounts[0].client.getPoxInfo();
  } catch (error) {
    if (/(ECONNREFUSED|ENOTFOUND|SyntaxError)/.test(error.cause?.message)) {
      console.log(`Stacks node not ready, waiting...`);
    }
    await new Promise(resolve => setTimeout(resolve, 3000));
    return waitForSetup();
  }
}

export function parseEnvInt<T extends boolean = false>(
  envKey: string,
  required?: T
): T extends true ? number : number | undefined {
  let value = process.env[envKey];
  if (typeof value === 'undefined') {
    if (required) {
      throw new Error(`Missing required env var: ${envKey}`);
    }
    return undefined as T extends true ? number : number | undefined;
  }
  return parseInt(value, 10);
}

export function burnBlockToRewardCycle(burnBlock: number) {
  const cycleLength = BigInt(POX_REWARD_LENGTH);
  return Number(BigInt(burnBlock) / cycleLength) + 1;
}

export const EPOCH_30_START_CYCLE = burnBlockToRewardCycle(EPOCH_30_START);

export function isPreparePhase(burnBlock: number) {
  return POX_REWARD_LENGTH - (burnBlock % POX_REWARD_LENGTH) < POX_PREPARE_LENGTH;
}

export function didCrossPreparePhase(lastBurnHeight: number, newBurnHeight: number) {
  return isPreparePhase(newBurnHeight) && !isPreparePhase(lastBurnHeight);
}
