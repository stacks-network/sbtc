# GetWithdrawalsResponse

Response to get withdrawals request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**next_token** | **str** | Next token for the search. | [optional] 
**withdrawals** | [**List[WithdrawalInfo]**](WithdrawalInfo.md) | Withdrawal infos: withdrawals with a little less data. | 

## Example

```python
from emily_client.models.get_withdrawals_response import GetWithdrawalsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GetWithdrawalsResponse from a JSON string
get_withdrawals_response_instance = GetWithdrawalsResponse.from_json(json)
# print the JSON string representation of the object
print(GetWithdrawalsResponse.to_json())

# convert the object into a dict
get_withdrawals_response_dict = get_withdrawals_response_instance.to_dict()
# create an instance of GetWithdrawalsResponse from a dict
get_withdrawals_response_from_dict = GetWithdrawalsResponse.from_dict(get_withdrawals_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


