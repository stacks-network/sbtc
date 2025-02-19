# CreateWithdrawalRequestBody

Request structure for the create withdrawal request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **int** | Amount of BTC being withdrawn in satoshis. | 
**parameters** | [**WithdrawalParameters**](WithdrawalParameters.md) |  | 
**recipient** | **str** | The recipient Bitcoin address. | 
**request_id** | **int** | The id of the Stacks withdrawal request that initiated the sBTC operation. | 
**stacks_block_hash** | **str** | The stacks block hash in which this request id was initiated. | 
**stacks_block_height** | **int** | The stacks block hash in which this request id was initiated. | 

## Example

```python
from emily_client.models.create_withdrawal_request_body import CreateWithdrawalRequestBody

# TODO update the JSON string below
json = "{}"
# create an instance of CreateWithdrawalRequestBody from a JSON string
create_withdrawal_request_body_instance = CreateWithdrawalRequestBody.from_json(json)
# print the JSON string representation of the object
print(CreateWithdrawalRequestBody.to_json())

# convert the object into a dict
create_withdrawal_request_body_dict = create_withdrawal_request_body_instance.to_dict()
# create an instance of CreateWithdrawalRequestBody from a dict
create_withdrawal_request_body_from_dict = CreateWithdrawalRequestBody.from_dict(create_withdrawal_request_body_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


