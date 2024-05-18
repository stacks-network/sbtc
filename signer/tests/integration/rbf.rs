use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi;
use signer::utxo::SbtcRequests;
use signer::utxo::SignerBtcState;
use signer::utxo::SignerUtxo;
use signer::utxo::WithdrawalRequest;

use crate::regtest;
use crate::utxo_construction::make_deposit_request;
use regtest::Recipient;
use regtest::DEPOSITS_LABEL;
use regtest::SIGNER_ADDRESS_LABEL;
use regtest::WITHDRAWAL_LABEL;

#[test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
fn transactions_with_rbf_work() {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let signer = Recipient::new(AddressType::P2tr);
    let depositor = Recipient::new(AddressType::P2tr);
    let withdrawer = Recipient::new(AddressType::P2wpkh);
    let signers_public_key = signer.keypair.x_only_public_key().0;
    signer.track_address(&rpc, SIGNER_ADDRESS_LABEL);
    depositor.track_address(rpc, DEPOSITS_LABEL);
    withdrawer.track_address(rpc, WITHDRAWAL_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 100_000_000, &signer.address);
    faucet.send_to(rpc, 50_000_000, &depositor.address);
    faucet.generate_blocks(&rpc, 1);

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);
    assert_eq!(depositor.get_balance(rpc).to_sat(), 50_000_000);

    // Now lets make a deposit transaction and submit it
    let depositor_utxo = depositor.get_utxos(rpc, None).pop().unwrap();
    let deposit_amount = 25_000_000;

    let (deposit_tx, deposit_request) = make_deposit_request(
        &depositor,
        deposit_amount,
        &depositor_utxo,
        signers_public_key,
        faucet.keypair.x_only_public_key().0,
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    faucet.generate_blocks(rpc, 1);

    // The depositor's balance should be updated now.
    let depositor_balance = depositor.get_balance(rpc);
    assert_eq!(depositor_balance.to_sat(), 50_000_000 - 25_000_000 - fee);
    // We deposited the transaction to the signer, but it's not clear to the
    // wallet tracking the signer's address that the deposit is associated
    // with the signer since it's hidden within the merkle tree.
    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Okay now we try to peg-in the deposit by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let mut requests = SbtcRequests {
        deposits: vec![deposit_request],
        withdrawals: vec![WithdrawalRequest {
            amount: 20000,
            max_fee: 100_000,
            address: withdrawer.address,
            signer_bitmap: Vec::new(),
        }],
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
