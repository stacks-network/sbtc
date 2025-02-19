# WithdrawalInfo

Reduced version of the Withdrawal.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **int** | Amount of BTC being withdrawn in satoshis. | 
**last_update_block_hash** | **str** | The most recent Stacks block hash the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **int** | The most recent Stacks block height the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**recipient** | **str** | The recipient Bitcoin address. | 
**request_id** | **int** | The id of the Stacks withdrawal request that initiated the sBTC operation. | 
**stacks_block_hash** | **str** | The stacks block hash in which this request id was initiated. | 
**stacks_block_height** | **int** | The height of the Stacks block in which this request id was initiated. | 
**status** | [**Status**](Status.md) |  | 

## Example

```python
from emily_client.models.withdrawal_info import WithdrawalInfo

# TODO update the JSON string below
json = "{}"
# create an instance of WithdrawalInfo from a JSON string
withdrawal_info_instance = WithdrawalInfo.from_json(json)
# print the JSON string representation of the object
print(WithdrawalInfo.to_json())

# convert the object into a dict
withdrawal_info_dict = withdrawal_info_instance.to_dict()
# create an instance of WithdrawalInfo from a dict
withdrawal_info_from_dict = WithdrawalInfo.from_dict(withdrawal_info_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


