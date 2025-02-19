# Limits

Represents the current sBTC limits.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**account_caps** | [**Dict[str, AccountLimits]**](AccountLimits.md) | Represents the individual limits for requests coming from different accounts. | 
**peg_cap** | **int** | Represents the total cap for all pegged-in BTC/sBTC. | [optional] 
**per_deposit_cap** | **int** | Per deposit cap. If none then there is no cap. | [optional] 
**per_deposit_minimum** | **int** | Per deposit minimum. If none then there is no minimum. | [optional] 
**per_withdrawal_cap** | **int** | Per withdrawal cap. If none then there is no cap. | [optional] 

## Example

```python
from emily_client.models.limits import Limits

# TODO update the JSON string below
json = "{}"
# create an instance of Limits from a JSON string
limits_instance = Limits.from_json(json)
# print the JSON string representation of the object
print(Limits.to_json())

# convert the object into a dict
limits_dict = limits_instance.to_dict()
# create an instance of Limits from a dict
limits_from_dict = Limits.from_dict(limits_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


