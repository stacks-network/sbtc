# sBTC Signer

### Building
Change to the signer directory and build the program using `cargo`.

   ```bash
   cd signer
   cargo build --release
   ```
### Running
You can run the signer by providing the required environment variables.

#### Required Environment Variables
- `DATABASE_URL`: Url of the postgresql database this signer should connect to.

#### Optional Environment Variables
If not specified, the default values from `./src/config/default.toml` will be used.
- `SIGNER_BLOCKLIST_CLIENT__HOST`=`<server-hostname-or-ip>`
- `SIGNER_BLOCKLIST_CLIENT__PORT`=`<server-port>`
- `SIGNER_STACKS_API_ENDPOINT`=`<schema-and-fqdn-and-port>`
- `SIGNER_STACKS_NODE_ENDPOINT`=`<schema-and-fqdn-and-port>`

#### Inspecting the signer database
The signer state will be stored in a `sbtc_signer` schema in the provided database at `$DATABASE_URL`.
Ensure that the user specified in `$DATABASE_URL` can access that schema.

```bash
SIGNER_BLOCKLIST_CLIENT__HOST=127.0.0.1 SIGNER_BLOCKLIST_CLIENT__PORT=8080  ../target/release/signer 
```
