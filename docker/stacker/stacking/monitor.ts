import {
  accounts,
  nodeUrl,
  waitForSetup,
  EPOCH_30_START,
  didCrossPreparePhase,
  blocksApi,
  parseEnvInt,
  txApi,
  logger,
} from './common';
import { Transaction, ContractCallTransaction } from '@stacks/stacks-blockchain-api-types';

let lastBurnHeight = 0;
let lastStxHeight = 0;
let lastRewardCycle = 0;
let lastStxBlockTime = new Date().getTime();
let lastStxBlockDiff = 0;
let lastBlockWarnTime = 0;

logger.info('Starting monitor script...');

const EXIT_FROM_MONITOR = process.env.EXIT_FROM_MONITOR === '1';
const monitorInterval = parseEnvInt('MONITOR_INTERVAL') ?? 2;

logger.debug('Exit from monitor?', EXIT_FROM_MONITOR);

async function getTransactions(): Promise<ContractCallTransaction[]> {
  let res = await txApi.getTransactionsByBlock({
    heightOrHash: 'latest',
  });
  let txs = res.results as Transaction[];
  return txs.filter(tx => {
    return tx.tx_type === 'contract_call';
  }) as ContractCallTransaction[];
}

async function getInfo() {
  let { client } = accounts[0];
  const [poxInfo, blockInfo, txs] = await Promise.all([
    client.getPoxInfo(),
    blocksApi.getBlock({
      heightOrHash: 'latest',
    }),
    getTransactions(),
  ]);
  const { reward_cycle_id } = poxInfo;
  return {
    poxInfo,
    blockInfo,
    nextCycleId: reward_cycle_id + 1,
    txs,
  };
}

type StackerSet = {
  stacker_set: {
    signers: {
      signer_key: string;
    }[];
  };
};

async function getSignerSet(cycle: number) {
  const url = `${nodeUrl}/v2/stacker_set/${cycle}`;
  try {
    const res = await fetch(url);
    if (!res.ok) {
      return null;
    }
    const data = (await res.json()) as StackerSet;
    return data;
  } catch (error) {
    return null;
  }
}

async function loop() {
  try {
    const { poxInfo, blockInfo, ...info } = await getInfo();
    let { reward_cycle_id, current_burnchain_block_height } = poxInfo;
    let { height } = blockInfo;
    let showBurnMsg = false;
    let showPrepareMsg = false;
    let showCycleMsg = false;
    let showStxBlockMsg = false;
    let burnHeightDate = new Date(blockInfo.burn_block_time * 1000);
    let burnHeightTimeAgo = (new Date().getTime() - burnHeightDate.getTime()) / 1000;
    const loopLog = logger.child({
      height,
      burnHeight: current_burnchain_block_height,
      // burnHeightTime:
      cycle: reward_cycle_id,
      txCount: blockInfo.tx_count,
      rewardCycle: reward_cycle_id,
      lastBurnBlock: `${burnHeightTimeAgo.toFixed(0)}s ago`,
      burnHash: blockInfo.burn_block_hash,
    });

    if (current_burnchain_block_height && current_burnchain_block_height !== lastBurnHeight) {
      if (didCrossPreparePhase(lastBurnHeight, current_burnchain_block_height)) {
        showPrepareMsg = true;
      }
      showBurnMsg = true;
      lastBurnHeight = current_burnchain_block_height;
    }

    if (reward_cycle_id !== lastRewardCycle) {
      showCycleMsg = true;
      lastRewardCycle = reward_cycle_id;
    }

    const now = new Date().getTime();
    lastStxBlockDiff = now - lastStxBlockTime;

    if (height !== lastStxHeight) {
      showStxBlockMsg = true;
      lastStxHeight = height;
      lastStxBlockTime = now;
      lastBlockWarnTime = now;
    }

    // how many ms to warn about no stx blocks
    const blockWarnInterval = 60 * 1000;
    const lastWarnDiff = now - lastBlockWarnTime;
    // if no stx block in a minute
    if (lastStxBlockDiff > blockWarnInterval && lastWarnDiff > blockWarnInterval) {
      // const diff = new Date().getTime() - lastStxBlockTime;
      const lastSeen = new Date(lastStxBlockTime).toISOString();
      const minSinceStxBlock = (lastStxBlockDiff / (1000 * 60)).toFixed(2);
      lastBlockWarnTime = now;
      loopLog.warn(
        {
          lastSeen,
          secSinceStxBlock: lastStxBlockDiff / 1000,
          minSinceStxBlock,
          lastStxBlockTime,
        },
        `No new stx block since ${minSinceStxBlock} minutes ago`
      );
    }

    if (showBurnMsg) {
      loopLog.info('New burn block');
      if (current_burnchain_block_height === EPOCH_30_START) {
        loopLog.info('Starting Nakamoto');
      }
    }
    if (showPrepareMsg) {
      loopLog.info(
        {
          nextRewardCycle: reward_cycle_id + 1,
        },
        'Prepare phase started'
      );
      const nextSigners = await getSignerSet(reward_cycle_id + 1);
      if (nextSigners) {
        loopLog.info(
          {
            nextSigners: nextSigners.stacker_set.signers.length,
          },
          `Next cycle (${reward_cycle_id + 1}) has ${
            nextSigners.stacker_set.signers.length
          } signers`
        );
      }
    }

    if (!showBurnMsg && showStxBlockMsg && blockInfo.burn_block_height >= EPOCH_30_START) {
      loopLog.info({ lastStxBlockDiff: lastStxBlockDiff / 1000 }, 'Nakamoto block');
    }
    if (showStxBlockMsg && info.txs.length > 0) {
      info.txs.forEach(({ contract_call, sender_address, tx_status, ...tx }) => {
        if (contract_call.contract_id.includes('flood')) {
          return;
        }
        loopLog.info(
          {
            sender_address,
            contract_call: contract_call.function_name,
            tx_status,
            tx_result: tx.tx_result.repr,
            tx_id: tx.tx_id,
          },
          'New transaction confirmed'
        );
      });
    }

    if (showCycleMsg) {
      const currentSigners = await getSignerSet(reward_cycle_id);
      const signerCount = currentSigners?.stacker_set.signers.length ?? 0;
      loopLog.info(
        { signerCount },
        `New cycle started (${reward_cycle_id}) with ${signerCount} signers`
      );
    }

    if (reward_cycle_id >= EPOCH_30_START && !poxInfo.reward_slots) {
      logger.error('FATAL: no signers while going in to Epoch 3.0');
      exit();
    }
  } catch (error) {
    let message = 'Caught error in monitor run loop';
    if (error instanceof Error) {
      message += `: ${error.message}`;
    } else {
      console.error(error);
    }
    logger.error(message);
  }
}

function exit() {
  if (EXIT_FROM_MONITOR) {
    logger.info('Exiting...');
    process.exit(1);
  }
}

async function runLoop() {
  await loop();
  setTimeout(runLoop, monitorInterval * 1000);
}

async function run() {
  await waitForSetup();
  await runLoop();
}
process.on('SIGTERM', () => {
  process.exit(0);
});
process.on('SIGINT', () => {
  process.exit(0);
});
run();
