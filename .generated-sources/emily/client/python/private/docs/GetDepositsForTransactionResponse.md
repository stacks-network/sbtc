# GetDepositsForTransactionResponse

Response to get deposits for transaction request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**deposits** | [**List[Deposit]**](Deposit.md) | Deposits. | 
**next_token** | **str** | Next token for the search. | [optional] 

## Example

```python
from emily_client.models.get_deposits_for_transaction_response import GetDepositsForTransactionResponse

# TODO update the JSON string below
json = "{}"
# create an instance of GetDepositsForTransactionResponse from a JSON string
get_deposits_for_transaction_response_instance = GetDepositsForTransactionResponse.from_json(json)
# print the JSON string representation of the object
print(GetDepositsForTransactionResponse.to_json())

# convert the object into a dict
get_deposits_for_transaction_response_dict = get_deposits_for_transaction_response_instance.to_dict()
# create an instance of GetDepositsForTransactionResponse from a dict
get_deposits_for_transaction_response_from_dict = GetDepositsForTransactionResponse.from_dict(get_deposits_for_transaction_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


