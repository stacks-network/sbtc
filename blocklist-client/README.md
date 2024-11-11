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
- BLOCKLIST_CLIENT_RISK_ANALYSIS__USE_SANCTIONS=`<true|false>`

Currently we implemented two risk providers, which can be chosen via the `BLOCKLIST_CLIENT_RISK_ANALYSIS__USE_SANCTIONS` environment variable. If set to `true`, the [sanctions](https://public.chainalysis.com/docs/index.html#introduction) provider will be used, otherwise the risk provider will be used. We currently lost information about the risk provider, so only with the `BLOCKLIST_CLIENT_RISK_ANALYSIS__USE_SANCTIONS` set to `true` the client will work.

   ```bash
    BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key BLOCKLIST_CLIENT_RISK_ANALYSIS__USE_SANCTIONS=true ../target/release/blocklist-client 
   ```

#### Optional Environment Variables
If not specified, the default values from `./src/config/default.toml` will be used.
- BLOCKLIST_CLIENT_SERVER__HOST=`<server-hostname-or-ip>`
- BLOCKLIST_CLIENT_SERVER__PORT=`<server-port>`

   ```bash
    BLOCKLIST_CLIENT_SERVER__HOST=127.0.0.1 BLOCKLIST_CLIENT_SERVER__PORT=8080 BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key BLOCKLIST_CLIENT_RISK_ANALYSIS__USE_SANCTIONS=true  ../target/release/blocklist-client 
   ```


### Aceessing the API

After you succesfully runned the blocklist client, you can access it like this:
`curl http://127.0.0.1:3030/screen/0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a`
and you should get a response like this:
```json
{"is_blocklisted":true,"severity":"Severe","accept":false,"reason":"sanctions"}%
```