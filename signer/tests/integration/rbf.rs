use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use bitcoincore_rpc::json::GetTxOutResult;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;
use rand::distributions::Uniform;
use rand::Rng;
use signer::bitcoin::utxo::DepositRequest;
use signer::bitcoin::utxo::Fees;
use signer::bitcoin::utxo::RequestRef;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::bitcoin::utxo::SignerUtxo;
use signer::bitcoin::utxo::UnsignedTransaction;
use signer::bitcoin::utxo::WithdrawalRequest;
use signer::context::SbtcLimits;
use signer::storage::model::ScriptPubKey;
use signer::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;

use crate::utxo_construction::generate_withdrawal;
use crate::utxo_construction::make_deposit_request;
use regtest::Recipient;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;
use sbtc::testing::regtest::Faucet;

#[derive(Debug, Clone)]
pub struct FullUtxo {
    outpoint: OutPoint,
    tx_out: GetTxOutResult,
    script: ScriptBuf,
}

impl AsUtxo for FullUtxo {
    fn txid(&self) -> Txid {
        self.outpoint.txid
    }
    fn vout(&self) -> u32 {
        self.outpoint.vout
    }
    fn amount(&self) -> Amount {
        self.tx_out.value
    }
    fn script_pubkey(&self) -> &ScriptBuf {
        &self.script
    }
}

fn generate_depositor(rpc: &Client, faucet: &Faucet, signer: &Recipient) -> DepositRequest {
    let depositor = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    let outpoint = faucet.send_to(50_000_000, &depositor.address);
    let amount = rand::rngs::OsRng.sample(Uniform::new(100_000, 500_000));

    // Now lets make a deposit transaction and submit it. We need the UTXO
    // that was just sent to us.
    let tx_out: GetTxOutResult = rpc
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
        .unwrap()
        .unwrap();

    let utxo = FullUtxo {
        outpoint,
        script: tx_out.script_pub_key.script().unwrap(),
        tx_out,
    };

    let max_fee = amount / 2;
    let (deposit_tx, deposit_request, _) =
        make_deposit_request(&depositor, amount, utxo, max_fee, signers_public_key);
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    deposit_request
}

fn recreate_request_state(
    mut requests: SbtcRequests,
    ctx: &RbfContext,
    deposits: &[DepositRequest],
    withdrawals: &[WithdrawalRequest],
    fees: Fees,
) -> SbtcRequests {
    requests.signer_state.fee_rate = ctx.rbf_fee_rate;
    requests.signer_state.last_fees = Some(fees);

    requests.deposits = deposits.to_vec();
    requests.withdrawals = withdrawals.to_vec();
    requests.deposits.truncate(ctx.rbf_deposits);
    requests.withdrawals.truncate(ctx.rbf_withdrawals);
    requests
}

/// A struct to specify the different states/conditions for an RBF
/// transaction.
struct RbfContext {
    /// The number of outstanding deposit requests for the initial
    /// transaction.
    initial_deposits: usize,
    /// The number of outstanding withdrawal requests for the initial
    /// transaction.
    initial_withdrawals: usize,
    /// The market fee rate during the initial transaction.
    initial_fee_rate: f64,
    /// The number of deposit requests at the time of an RBF transaction.
    /// This number can be greater than, less than, or equal to the initial
    /// number of outstanding deposit requests.
    rbf_deposits: usize,
    /// The number of withdrawal requests at the time of an RBF transaction.
    /// This number can be greater than, less than, or equal to the initial
    /// number of outstanding withdrawal requests.
    rbf_withdrawals: usize,
    /// The market fee rate during the RBF transaction.
    rbf_fee_rate: f64,
}

/// In this test we aim to test RBF handling under different scenarios.
/// This is done in 4 steps.
///
/// 1. Create and submit a simple BTC transaction with one deposit and one
///    withdrawal.
/// 2. Submit an RBF transaction that we know will fail.
/// 3. Update the number of outstanding deposit and withdrawal requests
///    that we want to process, update the market fee rate, and use the
///    fees paid for the last successfully submitted transaction to
///    construct and submit an RBF transaction.
/// 4. Check that the withdrawal recipients have the expected balance.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case::test_matrix(
    [5, 0, 9],
    [5, 0, 9],
    [8., 16.],
    [5, 100]
)]
pub fn transaction_with_rbf(
    rbf_deposits: usize,
    rbf_withdrawals: usize,
    rbf_fee_rate: f64,
    failure_threshold: u16,
) {
    // This is not a case that we support; why would we replace a
    // submitted transaction without any peg-in or peg-out inputs and
    // outputs? So let's skip this case.
    if rbf_deposits == 0 && rbf_withdrawals == 0 {
        return;
    }
    let ctx = RbfContext {
        initial_deposits: 5,
        initial_withdrawals: 5,
        initial_fee_rate: 12.0,
        rbf_deposits,
        rbf_withdrawals,
        rbf_fee_rate,
    };
    let (rpc, faucet) = regtest::initialize_blockchain();

    // ** Step 1 **
    // Construct and send a simple BTC transaction.
    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    faucet.send_to(100_000_000, &signer.address);

    // We need to generate all deposits that we will need up front, since
    // we cannot generate new blocks once we submit the transaction that
    // we want to RBF (since it would then be confirmed).
    let deposits: Vec<DepositRequest> =
        std::iter::repeat_with(|| generate_depositor(rpc, faucet, &signer))
            .take(ctx.initial_deposits.max(ctx.rbf_deposits))
            .enumerate()
            .map(|(index, mut req)| {
                req.signer_bitmap.set(index, true);
                req
            })
            .collect();

    let mut withdrawal_recipients: Vec<Recipient> = Vec::new();
    let withdrawals: Vec<WithdrawalRequest> = std::iter::repeat_with(generate_withdrawal)
        .take(ctx.initial_withdrawals.max(ctx.rbf_withdrawals))
        .enumerate()
        .map(|(index, (mut req, recipient))| {
            withdrawal_recipients.push(recipient);
            req.signer_bitmap.set(index, true);
            req
        })
        .collect();

    faucet.generate_blocks(1);
    // We deposited the transaction to the signer, but it's not clear to the
    // wallet tracking the signer's address that the deposit is associated
    // with the signer since it's hidden within the merkle tree.
    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Okay now we try to peg-in the deposit by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    // We only use the specified initial number of deposits and withdrawals.
    let requests = SbtcRequests {
        deposits: deposits
            .clone()
            .into_iter()
            .take(ctx.initial_deposits)
            .collect(),
        withdrawals: withdrawals
            .clone()
            .into_iter()
            .take(ctx.initial_withdrawals)
            .collect(),
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: ctx.initial_fee_rate,
            public_key: signers_public_key,
            last_fees: None,
            // The value here isn't important, but it matches what happens
            // in Nakamoto testnet.
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: failure_threshold,
        num_signers: 2 * failure_threshold,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // Okay, lets submit the transaction. We also do a sanity check where
    // we try to submit an RBF transaction with an insufficient fee bump.
    // We need to note the fee for original transaction, so it is returned.
    let fees = {
        // There should only be one transaction here since there is only one
        // deposit request and no withdrawal requests.
        let mut transactions: Vec<UnsignedTransaction> = requests.construct_transactions().unwrap();

        let mut last_fee: u64 = 0;
        let mut last_size: usize = 0;

        // Add the signature and/or other required information to the witness data.
        transactions.iter_mut().for_each(|unsigned| {
            signer::testing::set_witness_data(unsigned, signer.keypair);
            rpc.send_raw_transaction(&unsigned.tx).unwrap();

            last_fee += unsigned.input_amounts() - unsigned.output_amounts();
            last_size += unsigned.tx.vsize();
        });

        // ** Step 2 **
        // Ccreate an RBF transaction that will fail.
        //
        // This is a little sanity check where we submit an RBF transaction
        // but where we change the fee but an amount that is too small.
        let mut transactions = requests.construct_transactions().unwrap();
        // We increase the fee paid but not by enough to be accepted
        transactions[0].tx.output[0].value -= Amount::from_sat(10);

        let one_response: Result<Vec<Txid>, BtcRpcError> = transactions
            .iter_mut()
            .map(|unsigned| {
                signer::testing::set_witness_data(unsigned, signer.keypair);
                rpc.send_raw_transaction(&unsigned.tx)
            })
            .collect();
        match one_response {
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { message, .. }))) => {
                assert!(message.starts_with("insufficient fee, rejecting replacement"))
            }
            _ => panic!("Unexpected response when sending bad replacement transaction"),
        }

        Fees {
            total: last_fee,
            rate: last_fee as f64 / last_size as f64,
        }
    };

    // Step 3. Construct an RBF transaction
    //
    // Let's update the request state with the new fee rate, the last fee amount paid
    // and modify the outstanding deposits and withdrawals.
    let requests = recreate_request_state(requests, &ctx, &deposits, &withdrawals, fees);

    let mut transactions = requests.construct_transactions().unwrap();

    transactions.iter_mut().for_each(|unsigned| {
        signer::testing::set_witness_data(unsigned, signer.keypair);
        rpc.send_raw_transaction(&unsigned.tx).unwrap();
    });

    faucet.generate_blocks(1);

    // Step 4: Check the recipients have the right balances
    //
    // Now lets check the balances and fees. We start with the signers'
    // balance.
    let total_fees: u64 = transactions
        .iter()
        .map(|utx| utx.input_amounts() - utx.output_amounts())
        .sum();
    let total_size: usize = transactions.iter().map(|utx| utx.tx.vsize()).sum();
    let fee_rate = total_fees as f64 / total_size as f64;

    more_asserts::assert_ge!(fee_rate, ctx.rbf_fee_rate);
    more_asserts::assert_gt!(total_fees, fees.total);

    let deposit_amounts: u64 = requests.deposits.iter().map(|req| req.amount).sum();
    let withdrawal_amounts: u64 = requests.withdrawals.iter().map(|req| req.amount).sum();
    let fees: u64 = transactions.iter().map(|unsigned| unsigned.tx_fee).sum();

    // The signer's balance should now reflect the deposits and withdrawals
    // less the fees that depositors are supposed to pay.
    let signers_balance = signer.get_balance(rpc);
    let expected_balance = 100_000_000 + deposit_amounts - withdrawal_amounts - fees;
    assert_eq!(signers_balance.to_sat(), expected_balance);

    // Any unused deposits still have their balances adjusted since their
    // deposits were confirmed, we just didn't peg them in. But for
    // withdrawals, the outputs from the requests associated with the
    // RBF transaction should have their balances adjusted while the
    // others should not.
    let fee_map: std::collections::HashMap<ScriptPubKey, u64> = transactions
        .iter()
        .flat_map(|utx| {
            utx.requests
                .iter()
                .filter_map(RequestRef::as_withdrawal)
                // We only care about the outputs that coorrespond to
                // withdrawals. The first two outputs are the signers' UTXO
                // and the OP_RETURN output, so we skip them first.
                .zip(utx.tx.output.iter().skip(2))
                .map(|(req, tx_out)| {
                    (
                        req.script_pubkey.clone(),
                        req.amount - tx_out.value.to_sat(),
                    )
                })
        })
        .collect();
    let iter = withdrawals
        .into_iter()
        .zip(withdrawal_recipients)
        .enumerate();
    for (index, (req, recipient)) in iter {
        let balance = recipient.get_balance(rpc);
        if index < ctx.rbf_withdrawals {
            let expected_balance = req.amount - fee_map.get(&req.script_pubkey).unwrap();
            assert_eq!(balance.to_sat(), expected_balance);
        } else {
            assert_eq!(balance.to_sat(), 0);
        }
    }
}
