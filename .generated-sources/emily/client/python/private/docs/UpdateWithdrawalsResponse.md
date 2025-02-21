# UpdateWithdrawalsResponse

Response to update withdrawals request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**withdrawals** | [**List[Withdrawal]**](Withdrawal.md) | Updated withdrawals. | 

## Example

```python
from emily_client.models.update_withdrawals_response import UpdateWithdrawalsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of UpdateWithdrawalsResponse from a JSON string
update_withdrawals_response_instance = UpdateWithdrawalsResponse.from_json(json)
# print the JSON string representation of the object
print(UpdateWithdrawalsResponse.to_json())

# convert the object into a dict
update_withdrawals_response_dict = update_withdrawals_response_instance.to_dict()
# create an instance of UpdateWithdrawalsResponse from a dict
update_withdrawals_response_from_dict = UpdateWithdrawalsResponse.from_dict(update_withdrawals_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


