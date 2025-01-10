ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
ADD COLUMN x_only_public_key BYTEA;

-- The dkg_shares table should have at most one row in it at this point, so
-- all inputs should have been signed for using the same aggregate key.
-- Values in the dkg_shares.aggregate_key column are compressed public keys
-- keys, while, the values in the bitcoin_tx_sighashes.x_only_public_key
-- column are supposed to be x-only public keys, naturally. So we need to
-- lop off the first byte from the compressed public key.
UPDATE sbtc_signer.bitcoin_tx_sighashes
SET x_only_public_key = substring(ds.aggregate_key FROM 2)
FROM sbtc_signer.dkg_shares AS ds;

ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
ALTER COLUMN x_only_public_key SET NOT NULL;
