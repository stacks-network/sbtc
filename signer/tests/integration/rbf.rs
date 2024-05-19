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
use signer::utxo::SbtcRequests;
use signer::utxo::SignerBtcState;
use signer::utxo::SignerUtxo;
use signer::utxo::UnsignedTransaction;
use signer::utxo::WithdrawalRequest;

use test_case::test_case;

use crate::regtest;
use crate::utxo_construction::make_deposit_request;
use regtest::Recipient;
use regtest::DEPOSITS_LABEL;
use regtest::SIGNER_ADDRESS_LABEL;
use regtest::WITHDRAWAL_LABEL;

fn generate_depositor(
    rpc: &Client,
    faucet: &Recipient,
    signer: &Recipient,
) -> (DepositRequest, Recipient) {
    let depositor = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    depositor.track_address(rpc, DEPOSITS_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 50_000_000, &depositor.address);
    faucet.generate_blocks(&rpc, 1);

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
    (deposit_request, depositor)
}

fn generate_withdrawal(rpc: &Client) -> (WithdrawalRequest, Recipient) {
    let withdrawer = Recipient::new(AddressType::P2tr);
    withdrawer.track_address(rpc, WITHDRAWAL_LABEL);

    let req = WithdrawalRequest {
        amount: rand::rngs::OsRng.sample(Uniform::new(100_000, 250_000)),
        max_fee: 250_000,
        address: withdrawer.address.clone(),
        signer_bitmap: Vec::new(),
    };

    (req, withdrawer)
}

struct RbfContext {
    initial_deposits: usize,
    initial_withdrawals: usize,
    initial_fee_rate: f64,
    rbf_deposits: usize,
    rbf_withdrawals: usize,
    rbf_fee_rate: f64,
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 1,
    rbf_withdrawals: 1,
    rbf_fee_rate: 10.0,
} ; "same-deposits-same-withdrawals-same-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 1,
    rbf_withdrawals: 1,
    rbf_fee_rate: 8.0,
} ; "same-deposits-same-withdrawals-lower-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 1,
    rbf_withdrawals: 1,
    rbf_fee_rate: 13.0,
} ; "same-deposits-same-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 2,
    rbf_withdrawals: 1,
    rbf_fee_rate: 13.0,
} ; "new-deposits-same-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 3,
    rbf_withdrawals: 3,
    rbf_fee_rate: 14.0,
} ; "new-deposits-new-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 3,
    rbf_withdrawals: 3,
    rbf_fee_rate: 10.0,
} ; "new-deposits-new-withdrawals-same-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 0,
    rbf_withdrawals: 1,
    rbf_fee_rate: 14.0,
} ; "fewer-deposits-same-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 2,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 1,
    rbf_withdrawals: 0,
    rbf_fee_rate: 10.0,
} ; "fewer-deposits-fewer-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 0,
    rbf_withdrawals: 3,
    rbf_fee_rate: 14.0,
} ; "fewer-deposits-new-withdrawals-greater-rate")]
#[test_case(RbfContext {
    initial_deposits: 1,
    initial_withdrawals: 1,
    initial_fee_rate: 10.0,
    rbf_deposits: 1,
    rbf_withdrawals: 0,
    rbf_fee_rate: 14.0,
} ; "same-deposits-fewer-withdrawals-greater-rate")]
fn transactions_with_rbf(ctx: RbfContext) {
    let (rpc, faucet) = regtest::initialize_blockchain();

    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    signer.track_address(&rpc, SIGNER_ADDRESS_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 100_000_000, &signer.address);

    let mut depositors: Vec<Recipient> = Vec::new();
    let deposits = std::iter::repeat_with(|| generate_depositor(rpc, faucet, &signer))
        .take(ctx.initial_deposits)
        .map(|(req, depositor)| {
            depositors.push(depositor);
            req
        })
        .collect();

    let mut withdrawalers: Vec<Recipient> = Vec::new();
    let withdrawals = std::iter::repeat_with(|| generate_withdrawal(rpc))
        .take(ctx.initial_withdrawals)
        .map(|(req, withdrawaler)| {
            withdrawalers.push(withdrawaler);
            req
        })
        .collect();

    faucet.generate_blocks(&rpc, 1);
    // We deposited the transaction to the signer, but it's not clear to the
    // wallet tracking the signer's address that the deposit is associated
    // with the signer since it's hidden within the merkle tree.
    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Okay now we try to peg-in the deposit by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let mut requests = SbtcRequests {
        deposits,
        withdrawals,
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

    let last_fee = {
        // There should only be one transaction here since there is only one
        // deposit request and no withdrawal requests.
        let mut transactions: Vec<UnsignedTransaction> = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);
        let mut unsigned: UnsignedTransaction = transactions.pop().unwrap();

        let last_fee: u64 = unsigned.input_amounts() - unsigned.output_amounts();

        // Add the signature and/or other required information to the witness data.
        regtest::set_witness_data(&mut unsigned, signer.keypair);

        rpc.send_raw_transaction(&unsigned.tx).unwrap();

        let mut transactions = requests.construct_transactions().unwrap();
        let mut unsigned = transactions.pop().unwrap();

        unsigned.tx.output[0].value -= Amount::from_sat(10);

        regtest::set_witness_data(&mut unsigned, signer.keypair);

        match rpc.send_raw_transaction(&unsigned.tx) {
            Err(BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { message, .. }))) => {
                assert!(message.starts_with("insufficient fee, rejecting replacement"))
            }
            _ => panic!("Unexpected response when sending bad replacement transaction"),
        }
        last_fee
    };

    requests.signer_state.fee_rate = ctx.rbf_fee_rate;
    requests.signer_state.last_fees = Some(last_fee);

    requests.deposits.truncate(ctx.rbf_deposits);    
    if requests.deposits.len() < ctx.rbf_deposits {
        let new_deposits = std::iter::repeat_with(|| generate_depositor(rpc, faucet, &signer))
            .take(ctx.rbf_deposits - requests.deposits.len())
            .map(|(req, depositor)| {
                depositors.push(depositor);
                req
            });
        requests.deposits.extend(new_deposits);
    }

    requests.withdrawals.truncate(ctx.rbf_withdrawals);
    if requests.withdrawals.len() < ctx.rbf_withdrawals {
        let new_withdrawals = std::iter::repeat_with(|| generate_withdrawal(rpc))
            .take(ctx.rbf_withdrawals - requests.withdrawals.len())
            .map(|(req, withdrawer)| {
                withdrawalers.push(withdrawer);
                req
            });
        requests.withdrawals.extend(new_withdrawals);
    }

    faucet.generate_blocks(&rpc, 1);
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();
    regtest::set_witness_data(&mut unsigned, signer.keypair);

    let total_fees = unsigned.input_amounts() - unsigned.output_amounts();
    let fee_rate = total_fees as f64 / unsigned.tx.vsize() as f64;

    more_asserts::assert_ge!(fee_rate, ctx.rbf_fee_rate);
    more_asserts::assert_gt!(total_fees, last_fee);

    // The moment of truth, does the network accept the RBF transaction?
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(rpc, 1);

    let deposits: u64 = requests.deposits.iter().map(|req| req.amount).sum();
    let withdrawals: u64 = requests.withdrawals.iter().map(|req| req.amount).sum();
    let deposit_fees = unsigned.fee_per_request * requests.deposits.len() as u64;

    // The signer's balance should now reflect the deposits and withdrawals
    // less the fees that depositors are supposed to pay.
    let signers_balance = signer.get_balance(rpc);
    let expected_balance = 100_000_000 + deposits - withdrawals - deposit_fees;
    assert_eq!(signers_balance.to_sat(), expected_balance);
}
