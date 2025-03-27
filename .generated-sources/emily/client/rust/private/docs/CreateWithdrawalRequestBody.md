# CreateWithdrawalRequestBody

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **u64** | Amount of BTC being withdrawn in satoshis. | 
**parameters** | [**models::WithdrawalParameters**](WithdrawalParameters.md) |  | 
**recipient** | **String** | The recipient's Bitcoin hex-encoded scriptPubKey. | 
**request_id** | **u64** | The id of the Stacks withdrawal request that initiated the sBTC operation. | 
**sender** | **String** | The sender's Stacks principal. | 
**stacks_block_hash** | **String** | The stacks block hash in which this request id was initiated. | 
**stacks_block_height** | **u64** | The stacks block hash in which this request id was initiated. | 
**txid** | **String** | The hex encoded txid of the stacks transaction that generated this event. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


