# CreateDepositRequestBody

Request structure for create deposit request.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_tx_output_index** | **int** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **str** | Bitcoin transaction id. | 
**deposit_script** | **str** | Deposit script. | 
**reclaim_script** | **str** | Reclaim script. | 
**transaction_hex** | **str** | The raw transaction hex. | 

## Example

```python
from emily_client.models.create_deposit_request_body import CreateDepositRequestBody

# TODO update the JSON string below
json = "{}"
# create an instance of CreateDepositRequestBody from a JSON string
create_deposit_request_body_instance = CreateDepositRequestBody.from_json(json)
# print the JSON string representation of the object
print(CreateDepositRequestBody.to_json())

# convert the object into a dict
create_deposit_request_body_dict = create_deposit_request_body_instance.to_dict()
# create an instance of CreateDepositRequestBody from a dict
create_deposit_request_body_from_dict = CreateDepositRequestBody.from_dict(create_deposit_request_body_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


