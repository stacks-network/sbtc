# WithdrawalParameters

Withdrawal parameters.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**max_fee** | **int** | Maximum fee the signers are allowed to take from the withdrawal to facilitate the inclusion of the transaction onto the Bitcoin blockchain. | 

## Example

```python
from emily_client.models.withdrawal_parameters import WithdrawalParameters

# TODO update the JSON string below
json = "{}"
# create an instance of WithdrawalParameters from a JSON string
withdrawal_parameters_instance = WithdrawalParameters.from_json(json)
# print the JSON string representation of the object
print(WithdrawalParameters.to_json())

# convert the object into a dict
withdrawal_parameters_dict = withdrawal_parameters_instance.to_dict()
# create an instance of WithdrawalParameters from a dict
withdrawal_parameters_from_dict = WithdrawalParameters.from_dict(withdrawal_parameters_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


