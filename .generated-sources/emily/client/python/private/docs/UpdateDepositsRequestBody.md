# UpdateDepositsRequestBody

Request structure for update deposit request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**deposits** | [**List[DepositUpdate]**](DepositUpdate.md) | Bitcoin transaction id. | 

## Example

```python
from emily_client.models.update_deposits_request_body import UpdateDepositsRequestBody

# TODO update the JSON string below
json = "{}"
# create an instance of UpdateDepositsRequestBody from a JSON string
update_deposits_request_body_instance = UpdateDepositsRequestBody.from_json(json)
# print the JSON string representation of the object
print(UpdateDepositsRequestBody.to_json())

# convert the object into a dict
update_deposits_request_body_dict = update_deposits_request_body_instance.to_dict()
# create an instance of UpdateDepositsRequestBody from a dict
update_deposits_request_body_from_dict = UpdateDepositsRequestBody.from_dict(update_deposits_request_body_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


