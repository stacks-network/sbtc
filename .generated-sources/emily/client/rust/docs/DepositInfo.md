# DepositInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **u64** | Amount of BTC being deposited in satoshis. | 
**bitcoin_tx_output_index** | **u32** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **String** | Bitcoin transaction id. | 
**deposit_script** | **String** | Raw deposit script binary in hex. | 
**last_update_block_hash** | **String** | The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **u64** | The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**recipient** | **String** | Stacks address to received the deposited sBTC. | 
**reclaim_script** | **String** | Raw reclaim script binary in hex. | 
**status** | [**models::Status**](Status.md) |  | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


