# DepositParameters

Deposit parameters.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**lock_time** | **int** | Bitcoin block height at which the reclaim script becomes executable. | 
**max_fee** | **int** | Maximum fee the signers are allowed to take from the deposit to facilitate the transaction. | 

## Example

```python
from emily_client.models.deposit_parameters import DepositParameters

# TODO update the JSON string below
json = "{}"
# create an instance of DepositParameters from a JSON string
deposit_parameters_instance = DepositParameters.from_json(json)
# print the JSON string representation of the object
print(DepositParameters.to_json())

# convert the object into a dict
deposit_parameters_dict = deposit_parameters_instance.to_dict()
# create an instance of DepositParameters from a dict
deposit_parameters_from_dict = DepositParameters.from_dict(deposit_parameters_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


