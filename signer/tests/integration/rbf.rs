use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use rand::distributions::Uniform;
use rand::Rng;
use signer::utxo::DepositRequest;
use signer::utxo::SbtcRequests;
use signer::utxo::SignerBtcState;
use signer::utxo::SignerUtxo;
use signer::utxo::WithdrawalRequest;

use test_case::test_case;

use crate::regtest;
use crate::utxo_construction::make_deposit_request;
use regtest::Recipient;
use regtest::DEPOSITS_LABEL;
use regtest::SIGNER_ADDRESS_LABEL;
use regtest::WITHDRAWAL_LABEL;

fn generate_depositor(rpc: &Client, faucet: &Recipient, signer: &Recipient) -> (DepositRequest, Recipient) {
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
    initial_fee_rate: u64,
    rbf_deposits: usize,
    rbf_withdrawals: usize,
    rbf_fee_rate: u64,
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(RbfContext {
    initial_deposits: 0,
    initial_withdrawals: 0,
    initial_fee_rate: 0,
    rbf_deposits: 0,
    rbf_withdrawals: 0,
    rbf_fee_rate: 0,
} ; "new-deposits-same-withdrawals")]
fn transactions_with_rbf_work(ctx: RbfContext) {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

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
            fee_rate: 10.0,
            public_key: signers_public_key,
            last_fees: None,
        },
        accept_threshold: 4,
        num_signers: 7,
    };

    let last_fee = {
        // There should only be one transaction here since there is only one
        // deposit request and no withdrawal requests.
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);
        let mut unsigned = transactions.pop().unwrap();

        let last_fee = unsigned.input_amounts() - unsigned.output_amounts();

        // Add the signature and/or other required information to the witness data.
        regtest::set_witness_data(&mut unsigned, signer.keypair);

        // The moment of truth, does the network accept the transaction?
        rpc.send_raw_transaction(&unsigned.tx).unwrap();

        let mut transactions = requests.construct_transactions().unwrap();
        let mut unsigned = transactions.pop().unwrap();

        unsigned.tx.output[0].value -= Amount::from_sat(100);
        unsigned.tx.output[1].value += Amount::from_sat(100);

        regtest::set_witness_data(&mut unsigned, signer.keypair);

        assert!(rpc.send_raw_transaction(&unsigned.tx).is_err());
        last_fee
    };

    requests.signer_state.last_fees = Some(signer::utxo::Fees { total: last_fee, rate: 10.0 });

    let mut transactions = requests.construct_transactions().unwrap();
    let mut unsigned = transactions.pop().unwrap();
    regtest::set_witness_data(&mut unsigned, signer.keypair);

    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(rpc, 1);

    // The signer's balance should now reflect the deposit.
    let signers_balance = signer.get_balance(rpc);

    more_asserts::assert_gt!(signers_balance.to_sat(), 124_000_000);
    more_asserts::assert_lt!(signers_balance.to_sat(), 125_000_000);
}
