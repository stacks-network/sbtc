import { StacksTestnet } from '@stacks/network';
import { StackingClient } from '@stacks/stacking';
import {
  TransactionVersion,
  getAddressFromPrivateKey,
  getNonce,
  makeSTXTokenTransfer,
  broadcastTransaction,
  makeRandomPrivKey,
  StacksTransaction,
  makeContractDeploy,
  makeContractCall,
  tupleCV,
  uintCV,
  AnchorMode,
  PostConditionMode,
} from '@stacks/transactions';
import { readFileSync } from 'fs';
import { config } from 'dotenv';

if (process.argv.slice(2).length > 0) {
  config({ path: './tx-broadcaster.env' });
}
import { bytesToHex } from '@stacks/common';
import { logger, parseEnvInt, contractsApi, accountsApi } from './common';

const broadcastInterval = parseInt(process.env.NAKAMOTO_BLOCK_INTERVAL ?? '2');
const url = `http://${process.env.STACKS_CORE_RPC_HOST}:${process.env.STACKS_CORE_RPC_PORT}`;
const network = new StacksTestnet({ url });
const EPOCH_30_START = parseInt(process.env.STACKS_30_HEIGHT ?? '0');

const bootstrapperKey = process.env.BOOTSTRAPPER_KEY!;
const bootstrapper = {
  privKey: bootstrapperKey,
  stxAddress: getAddressFromPrivateKey(bootstrapperKey, TransactionVersion.Testnet),
};

const client = new StackingClient(bootstrapper.stxAddress, network);

const floodContract = readFileSync('./flooder.clar', { encoding: 'utf-8' });

const NUM_FLOODERS = parseEnvInt('NUM_FLOODERS', false) ?? 0;
// per account, how many tx to make per run
const TX_PER_FLOOD = parseEnvInt('TX_PER_FLOOD', false) ?? 10;

const flooders: { privKey: string; stxAddress: string; nonce: bigint }[] = [];

for (let i = 0; i < NUM_FLOODERS; i++) {
  const privKey = makeRandomPrivKey();
  flooders.push({
    privKey: bytesToHex(privKey.data),
    stxAddress: getAddressFromPrivateKey(privKey.data, TransactionVersion.Testnet),
    nonce: BigInt(0),
  });
}

let hasSentToFlooders = false;
const floodContractDeployer = bootstrapper.stxAddress;

async function bootstrapFlooders() {
  const nonce = await getNonce(bootstrapper.stxAddress, network);
  logger.info('Bootstrapping flooders');
  // sync iterate
  let i = 0n;
  let allWorked = true;
  const amount = 1000000 * 10_000; // 10k STX
  const transfersClarity = flooders.map(flooder => {
    return `(try! (stx-transfer? u${amount} tx-sender '${flooder.stxAddress}))`;
  });
  const contractBody = `
  (begin
    ${transfersClarity.join('\n')}
    (ok true)
  )
  `;
  const bootstrapTx = await makeContractDeploy({
    contractName: `bootstrap-${new Date().getTime().toString().slice(-4)}`,
    postConditionMode: PostConditionMode.Allow,
    fee: 3000000,
    network,
    nonce: nonce + i,
    senderKey: bootstrapper.privKey,
    anchorMode: AnchorMode.Any,
    codeBody: contractBody,
  });
  await broadcast(bootstrapTx, bootstrapper.stxAddress);
  i++;
  // console.log(contractBody);
  if (!(await isContractDeployed(floodContractDeployer))) {
    const ok = await broadcast(
      await makeContractDeploy({
        senderKey: bootstrapper.privKey,
        nonce: nonce + i,
        contractName: 'flood',
        codeBody: floodContract,
        fee: 3000000,
        anchorMode: 'any',
        network,
        postConditionMode: PostConditionMode.Allow,
      }),
      bootstrapper.stxAddress
    );
    if (!ok) allWorked = false;
  }
  if (allWorked) {
    hasSentToFlooders = true;
  }
}

async function isContractDeployed(address: string) {
  try {
    const result = await contractsApi.getContractSource({
      contractAddress: address,
      contractName: 'flood',
    });
    return !!result.source;
  } catch (e) {
    return false;
  }
}

async function run() {
  if (hasSentToFlooders) {
    await flood();
  } else {
    await bootstrapFlooders();
  }
}

async function flood() {
  const accountFloods = flooders.map(async (flooder, n) => {
    // const nonce = await getNonce(flooder.stxAddress, network);
    const nonces = accountsApi.getAccountNonces({
      principal: flooder.stxAddress,
    });
    const nonce = ((await nonces).last_executed_tx_nonce ?? -1) + 1;
    logger.info(`Flooder ${n} has nonce ${nonce.toString()}`);
    // return { ...account, nonce };
    let txFloods = new Array(TX_PER_FLOOD).fill(0).map(async (_, i) => {
      // const nonce = getFlooderNonce(flooder.stxAddress);
      const tx = await makeContractCall({
        contractAddress: floodContractDeployer,
        contractName: 'flood',
        functionName: 'set-data',
        functionArgs: [uintCV(1), uintCV(2), uintCV(3)],
        senderKey: flooder.privKey,
        nonce: nonce + i,
        anchorMode: 'any',
        network,
        fee: 10000,
      });
      await broadcast(tx, flooder.stxAddress);
    });
    await Promise.all(txFloods);
  });
  await Promise.all(accountFloods);
}

async function broadcast(tx: StacksTransaction, sender?: string) {
  const txType = tx.payload.payloadType;
  const label = sender ? accountLabel(sender) : 'Unknown';
  const broadcastResult = await broadcastTransaction(tx, network);
  if (broadcastResult.error) {
    logger.error({ ...broadcastResult, account: label }, `Error broadcasting ${txType}`);
    return false;
  } else {
    if (label.includes('Flooder')) return;
    logger.info(`Broadcast ${txType} from ${label} tx=${broadcastResult.txid}`);
    return true;
  }
}

async function waitForNakamoto() {
  while (true) {
    try {
      const poxInfo = await client.getPoxInfo();
      if (poxInfo.current_burnchain_block_height! <= EPOCH_30_START) {
        logger.info(
          `Nakamoto not activated yet, waiting... (current=${poxInfo.current_burnchain_block_height}), (epoch3=${EPOCH_30_START})`
        );
      } else {
        logger.info(
          `Nakamoto activation height reached, ready to submit txs for Nakamoto block production`
        );
        break;
      }
    } catch (error) {
      if (/(ECONNREFUSED|ENOTFOUND|SyntaxError)/.test(error.cause?.message)) {
        logger.info(`Stacks node not ready, waiting...`);
      } else {
        logger.error('Error getting pox info:', error);
      }
    }
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
}

function accountLabel(address: string) {
  if (address === bootstrapper.stxAddress) {
    return 'Bootstrapper';
  }
  const flooderIndex = flooders.findIndex(flooder => flooder.stxAddress === address);
  if (flooderIndex !== -1) {
    return `Flooder #${flooderIndex}`;
  }
  return `Unknown (${address})`;
}

async function loop() {
  await waitForNakamoto();
  while (true) {
    try {
      await run();
    } catch (e) {
      logger.error(e, 'Error submitting stx-transfer tx:');
    }
    await new Promise(resolve => setTimeout(resolve, broadcastInterval * 1000));
  }
}
loop();
