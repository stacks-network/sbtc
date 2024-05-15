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


#### Optional Environment Variables
If not specified, the default values from `./src/config/default.toml` will be used.
- SIGNER_BLOCKLIST_CLIENT__HOST=<server-hostname-or-ip>
- SIGNER_BLOCKLIST_CLIENT__PORT=<server-port>

```bash
SIGNER_BLOCKLIST_CLIENT__HOST=127.0.0.1 SIGNER_BLOCKLIST_CLIENT__PORT=8080  ../target/release/signer 
```
