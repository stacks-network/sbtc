# AccountLimits

The representation of a limit for a specific account.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**peg_cap** | **int** | Represents the current sBTC limits. | [optional] 
**per_deposit_cap** | **int** | Per deposit cap. If none then the cap is the same as the global per deposit cap. | [optional] 
**per_deposit_minimum** | **int** | Per deposit minimum. If none then there is no minimum. | [optional] 
**per_withdrawal_cap** | **int** | Per withdrawal cap. If none then the cap is the same as the global per withdrawal cap. | [optional] 

## Example

```python
from emily_client.models.account_limits import AccountLimits

# TODO update the JSON string below
json = "{}"
# create an instance of AccountLimits from a JSON string
account_limits_instance = AccountLimits.from_json(json)
# print the JSON string representation of the object
print(AccountLimits.to_json())

# convert the object into a dict
account_limits_dict = account_limits_instance.to_dict()
# create an instance of AccountLimits from a dict
account_limits_from_dict = AccountLimits.from_dict(account_limits_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


