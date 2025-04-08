ALTER TABLE sbtc_signer.bitcoin_withdrawals_outputs
DROP COLUMN stacks_txid;

ALTER TABLE sbtc_signer.withdrawal_signers
DROP COLUMN txid;
