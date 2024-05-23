-- Create the user if it doesn't exist
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'sbtc_user'
   ) THEN
      CREATE USER sbtc_user WITH PASSWORD 'sbtc_password';
   END IF;
END
$do$;

-- Grant privileges to the user
GRANT USAGE ON SCHEMA sbtc_signer TO sbtc_user;
GRANT CREATE ON SCHEMA sbtc_signer TO sbtc_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sbtc_signer TO sbtc_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sbtc_signer TO sbtc_user;
