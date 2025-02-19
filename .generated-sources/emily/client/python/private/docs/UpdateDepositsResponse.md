# UpdateDepositsResponse

Response to update deposits request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**deposits** | [**List[Deposit]**](Deposit.md) | Deposit infos: deposits with a little less data. | 

## Example

```python
from emily_client.models.update_deposits_response import UpdateDepositsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of UpdateDepositsResponse from a JSON string
update_deposits_response_instance = UpdateDepositsResponse.from_json(json)
# print the JSON string representation of the object
print(UpdateDepositsResponse.to_json())

# convert the object into a dict
update_deposits_response_dict = update_deposits_response_instance.to_dict()
# create an instance of UpdateDepositsResponse from a dict
update_deposits_response_from_dict = UpdateDepositsResponse.from_dict(update_deposits_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


