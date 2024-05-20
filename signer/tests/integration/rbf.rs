use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;
use rand::distributions::Uniform;
use rand::Rng;
use signer::utxo::DepositRequest;
use signer::utxo::Fees;
use signer::utxo::SbtcRequests;
use signer::utxo::SignerBtcState;
use signer::utxo::SignerUtxo;
use signer::utxo::UnsignedTransaction;
use signer::utxo::WithdrawalRequest;

use crate::regtest;
use crate::utxo_construction::make_deposit_request;
use regtest::Recipient;
use regtest::DEPOSITS_LABEL;
use regtest::SIGNER_ADDRESS_LABEL;
use regtest::WITHDRAWAL_LABEL;

fn generate_depositor(rpc: &Client, faucet: &Recipient, signer: &Recipient) -> DepositRequest {
    let depositor = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    depositor.track_address(rpc, DEPOSITS_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 50_000_000, &depositor.address);
    let amount = rand::rngs::OsRng.sample(Uniform::new(100_000, 500_000));

    // Now lets make a deposit transaction and submit it
    let depositor_utxo = depositor.get_utxos(rpc, None).pop().unwrap();
    let (deposit_tx, deposit_request) = make_deposit_request(
        &depositor,
        amount,
        &depositor_utxo,
        signers_public_key,
        faucet.keypair.x_only_public_key().0,
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    deposit_request
}

fn generate_withdrawal(rpc: &Client) -> (WithdrawalRequest, Recipient) {
    let recipient = Recipient::new(AddressType::P2tr);
    recipient.track_address(rpc, WITHDRAWAL_LABEL);

    let req = WithdrawalRequest {
        amount: rand::rngs::OsRng.sample(Uniform::new(100_000, 250_000)),
        max_fee: 250_000,
        address: recipient.address.clone(),
        signer_bitmap: Vec::new(),
    };

    (req, recipient)
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
    [1, 0, 3],
    [1, 0, 3],
    [4., 16., 20.]
)]
fn transactions_with_rbf(rbf_deposits: usize, rbf_withdrawals: usize, rbf_fee_rate: f64) {
    // This is not a case that we support; why would we replace a
    // submitted transaction with one without any peg-in or peg-out
    // inputs and outputs? So let's skip this case.
    if rbf_deposits == 0 && rbf_withdrawals == 0 {
        return;
    }
    let ctx = RbfContext {
        initial_deposits: 1,
        initial_withdrawals: 1,
        initial_fee_rate: 12.0,
        rbf_deposits,
        rbf_withdrawals,
        rbf_fee_rate,
    };
    let (rpc, faucet) = regtest::initialize_blockchain();

    // Step 1: Construct and send a simple BTC transaction.
    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    signer.track_address(rpc, SIGNER_ADDRESS_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 100_000_000, &signer.address);

    // We need to generate all deposits that we will need up front, since
    // we cannot generate new blocks once we submit the transaction that
    // we want to RBF (since it would then be confirmed).
    let deposits: Vec<DepositRequest> =
        std::iter::repeat_with(|| generate_depositor(rpc, faucet, &signer))
            .take(ctx.initial_deposits.max(ctx.rbf_deposits))
            .collect();

    let mut withdrawal_recipients: Vec<Recipient> = Vec::new();
    let withdrawals: Vec<WithdrawalRequest> = std::iter::repeat_with(|| generate_withdrawal(rpc))
        .take(ctx.initial_withdrawals.max(ctx.rbf_withdrawals))
        .map(|(req, recipient)| {
            withdrawal_recipients.push(recipient);
            req
        })
        .collect();

    faucet.generate_blocks(rpc, 1);
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
        },
        accept_threshold: 4,
        num_signers: 7,
    };

    // Okay, lets submit the transaction. We also do a sanity check where
    // we try to submit an RBF transaction with an insufficient fee bump.
    // We need to note the fee for original transaction, so it is returned.
    let (last_fee, last_fee_rate) = {
        // There should only be one transaction here since there is only one
        // deposit request and no withdrawal requests.
        let mut transactions: Vec<UnsignedTransaction> = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);
        let mut unsigned: UnsignedTransaction = transactions.pop().unwrap();

        let last_fee: u64 = unsigned.input_amounts() - unsigned.output_amounts();

        // Add the signature and/or other required information to the witness data.
        regtest::set_witness_data(&mut unsigned, signer.keypair);

        rpc.send_raw_transaction(&unsigned.tx).unwrap();

        // Step 2: create an RBF transaction that will fail.
        //
        // This is a little sanity check where we submit an RBF transaction
        // but where we change the fee but an amount that is too small.
        let mut transactions = requests.construct_transactions().unwrap();
        let mut unsigned = transactions.pop().unwrap();

        // We increase the fee paid but not by enough to be accepted
        unsigned.tx.output[0].value -= Amount::from_sat(10);

        regtest::set_witness_data(&mut unsigned, signer.keypair);

        match rpc.send_raw_transaction(&unsigned.tx) {
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { message, .. }))) => {
                assert!(message.starts_with("insufficient fee, rejecting replacement"))
            }
            _ => panic!("Unexpected response when sending bad replacement transaction"),
        }
        (last_fee, last_fee as f64 / unsigned.tx.vsize() as f64)
    };

    // Step 3. Construct an RBF transaction
    //
    // Let's update the request state with the new fee rate, the last fee amount paid
    // and modify the outstanding deposits and withdrawals.
    let fees = Fees {
        total: last_fee,
        rate: last_fee_rate,
    };
    let requests = recreate_request_state(requests, &ctx, &deposits, &withdrawals, fees);

    let mut transactions = requests.construct_transactions().unwrap();
    let mut unsigned = transactions.pop().unwrap();
    regtest::set_witness_data(&mut unsigned, signer.keypair);

    // The moment of truth, does the network accept the RBF transaction?
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(rpc, 1);

    // Step 4: Check the recipients have the right balances
    //
    // Now lets check the balances and fees. We start with the signers'
    // balance.
    let total_fees = unsigned.input_amounts() - unsigned.output_amounts();
    let fee_rate = total_fees as f64 / unsigned.tx.vsize() as f64;

    more_asserts::assert_ge!(fee_rate, ctx.rbf_fee_rate);
    more_asserts::assert_gt!(total_fees, last_fee);

    let deposit_amounts: u64 = requests.deposits.iter().map(|req| req.amount).sum();
    let withdrawal_amounts: u64 = requests.withdrawals.iter().map(|req| req.amount).sum();
    let deposit_fees = unsigned.fee_per_request * requests.deposits.len() as u64;

    // The signer's balance should now reflect the deposits and withdrawals
    // less the fees that depositors are supposed to pay.
    let signers_balance = signer.get_balance(rpc);
    let expected_balance = 100_000_000 + deposit_amounts - withdrawal_amounts - deposit_fees;
    assert_eq!(signers_balance.to_sat(), expected_balance);

    // Any unused deposits still have their balances adjusted since their
    // deposits were confirmed, we just didn't peg them in. But for
    // withdrawals, the outputs from the requests associated with the
    // RBF transaction should have their balances adjusted while the
    // others should not.
    let iter = withdrawals
        .into_iter()
        .zip(withdrawal_recipients)
        .enumerate();
    for (index, (req, recipient)) in iter {
        let balance = recipient.get_balance(rpc);
        if index < ctx.rbf_withdrawals {
            let expected_balance = req.amount - unsigned.fee_per_request;
            assert_eq!(balance.to_sat(), expected_balance);
        } else {
            assert_eq!(balance.to_sat(), 0);
        }
    }
}
