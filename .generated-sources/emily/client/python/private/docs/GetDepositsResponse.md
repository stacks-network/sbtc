# GetDepositsResponse

Response to get deposits request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**deposits** | [**List[DepositInfo]**](DepositInfo.md) | Deposit infos: deposits with a little less data. | 
**next_token** | **str** | Next token for the search. | [optional] 

## Example

```python
from emily_client.models.get_deposits_response import GetDepositsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GetDepositsResponse from a JSON string
get_deposits_response_instance = GetDepositsResponse.from_json(json)
# print the JSON string representation of the object
print(GetDepositsResponse.to_json())

# convert the object into a dict
get_deposits_response_dict = get_deposits_response_instance.to_dict()
# create an instance of GetDepositsResponse from a dict
get_deposits_response_from_dict = GetDepositsResponse.from_dict(get_deposits_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


