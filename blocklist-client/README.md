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

   ```bash
    BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key ../target/release/blocklist-client 
   ```

#### Optional Environment Variables
If not specified, the default values from `./src/config/default.toml` will be used.
- BLOCKLIST_CLIENT_SERVER__HOST=`<server-hostname-or-ip>`
- BLOCKLIST_CLIENT_SERVER__PORT=`<server-port>`
- BLOCKLIST_CLIENT_ASSESSMENT__ASSESSMENT_METHOD=`<sanctions|risk_analysis>`

   ```bash
    BLOCKLIST_CLIENT_SERVER__HOST=127.0.0.1 BLOCKLIST_CLIENT_SERVER__PORT=8080 BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key BLOCKLIST_CLIENT_ASSESSMENT__ASSESSMENT_METHOD=risk_analysis  ../target/release/blocklist-client 
   ```


### Accessing the API

Once the blocklist client is running successfully, you can access it as follows:

`curl http://127.0.0.1:3030/screen/0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a` should return a response like 
```json
{"is_blocklisted":true,"severity":"Severe","accept":false,"reason":"sanctions"}%