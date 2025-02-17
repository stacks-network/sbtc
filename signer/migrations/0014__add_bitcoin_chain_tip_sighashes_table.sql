BEGIN;

-- 1. Drop the old primary key constraint on 'sighash'.
ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
    DROP CONSTRAINT bitcoin_tx_sighashes_pkey;

-- 2. Create a new primary key that includes 'chain_tip' as well.
ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
    ADD CONSTRAINT bitcoin_tx_sighashes_pkey
    PRIMARY KEY (sighash, chain_tip);

COMMIT;
