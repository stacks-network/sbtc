# Blocklist Client
This Blocklist Client is an auxiliary service for serving a sBTC signer in the process of handling sBTC requests.

### Building
Change to the blocklist-client directory and build the program using `cargo`.

   ```bash
   cd blocklist-client
   cargo build --release
   ```
### Running
You can run the blocklist client by providing the required environment variables.

#### Required Environment Variables
- BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=`<provider-url>`
- BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=`<your_api_key>`

#### Optional Environment Variables
If not specified, the default values from `./src/config/default.toml` will be used.
- BLOCKLIST_CLIENT_SERVER__HOST=`<server-hostname-or-ip>`
- BLOCKLIST_CLIENT_SERVER__PORT=`<server-port>`

   ```bash
    BLOCKLIST_CLIENT_SERVER__HOST=127.0.0.1 BLOCKLIST_CLIENT_SERVER__PORT=8080 BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key  ../target/release/blocklist-client 
   ```
