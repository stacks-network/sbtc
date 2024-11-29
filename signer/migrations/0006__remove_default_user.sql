-- Delete default user if it exists
DO
$do$
BEGIN
   IF EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'sbtc_user'
   ) THEN
        DROP OWNED BY sbtc_user;
        DROP USER sbtc_user;
   END IF;
END
$do$;
