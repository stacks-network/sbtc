# WithdrawalUpdate

A singular Withdrawal update that contains only the fields pertinent to updating the status of a withdrawal. This includes the key related data in addition to status history related data.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fulfillment** | [**Fulfillment**](Fulfillment.md) |  | [optional] 
**last_update_block_hash** | **str** | The most recent Stacks block hash the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **int** | The most recent Stacks block height the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**request_id** | **int** | The id of the Stacks withdrawal request that initiated the sBTC operation. | 
**status** | [**Status**](Status.md) |  | 
**status_message** | **str** | The status message of the withdrawal. | 

## Example

```python
from emily_client.models.withdrawal_update import WithdrawalUpdate

# TODO update the JSON string below
json = "{}"
# create an instance of WithdrawalUpdate from a JSON string
withdrawal_update_instance = WithdrawalUpdate.from_json(json)
# print the JSON string representation of the object
print(WithdrawalUpdate.to_json())

# convert the object into a dict
withdrawal_update_dict = withdrawal_update_instance.to_dict()
# create an instance of WithdrawalUpdate from a dict
withdrawal_update_from_dict = WithdrawalUpdate.from_dict(withdrawal_update_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


