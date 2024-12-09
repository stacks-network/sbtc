# Withdrawal

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **u64** | Amount of BTC being withdrawn in satoshis. | 
**fulfillment** | Option<[**models::Fulfillment**](Fulfillment.md)> |  | [optional]
**last_update_block_hash** | **String** | The most recent Stacks block hash the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **u64** | The most recent Stacks block height the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**parameters** | [**models::WithdrawalParameters**](WithdrawalParameters.md) |  | 
**recipient** | **String** | The recipient Bitcoin address. | 
**request_id** | **u64** | The id of the Stacks withdrawal request that initiated the sBTC operation. | 
**stacks_block_hash** | **String** | The stacks block hash in which this request id was initiated. | 
**stacks_block_height** | **u64** | The height of the Stacks block in which this request id was initiated. | 
**status** | [**models::Status**](Status.md) |  | 
**status_message** | **String** | The status message of the withdrawal. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


