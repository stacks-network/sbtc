REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sbtc_signer FROM sbtc_user;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sbtc_signer FROM sbtc_user;

REVOKE CREATE ON SCHEMA sbtc_signer FROM sbtc_user;
REVOKE USAGE ON SCHEMA sbtc_signer FROM sbtc_user;

DROP USER IF EXISTS sbtc_user;
