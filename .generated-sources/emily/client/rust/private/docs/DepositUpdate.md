# DepositUpdate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_tx_output_index** | **u32** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **String** | Bitcoin transaction id. | 
**fulfillment** | Option<[**models::Fulfillment**](Fulfillment.md)> |  | [optional]
**last_update_block_hash** | **String** | The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **u64** | The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**status** | [**models::Status**](Status.md) |  | 
**status_message** | **String** | The status message of the deposit. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


