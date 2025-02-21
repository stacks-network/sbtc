# UpdateWithdrawalsRequestBody

Request structure for the create withdrawal request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**withdrawals** | [**List[WithdrawalUpdate]**](WithdrawalUpdate.md) | Withdrawal updates to execute. | 

## Example

```python
from emily_client.models.update_withdrawals_request_body import UpdateWithdrawalsRequestBody

# TODO update the JSON string below
json = "{}"
# create an instance of UpdateWithdrawalsRequestBody from a JSON string
update_withdrawals_request_body_instance = UpdateWithdrawalsRequestBody.from_json(json)
# print the JSON string representation of the object
print(UpdateWithdrawalsRequestBody.to_json())

# convert the object into a dict
update_withdrawals_request_body_dict = update_withdrawals_request_body_instance.to_dict()
# create an instance of UpdateWithdrawalsRequestBody from a dict
update_withdrawals_request_body_from_dict = UpdateWithdrawalsRequestBody.from_dict(update_withdrawals_request_body_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


