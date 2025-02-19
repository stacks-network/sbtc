# DepositUpdate

A singular Deposit update that contains only the fields pertinent to updating the status of a deposit. This includes the key related data in addition to status history related data.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_tx_output_index** | **int** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **str** | Bitcoin transaction id. | 
**fulfillment** | [**Fulfillment**](Fulfillment.md) |  | [optional] 
**last_update_block_hash** | **str** | The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **int** | The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**status** | [**Status**](Status.md) |  | 
**status_message** | **str** | The status message of the deposit. | 

## Example

```python
from emily_client.models.deposit_update import DepositUpdate

# TODO update the JSON string below
json = "{}"
# create an instance of DepositUpdate from a JSON string
deposit_update_instance = DepositUpdate.from_json(json)
# print the JSON string representation of the object
print(DepositUpdate.to_json())

# convert the object into a dict
deposit_update_dict = deposit_update_instance.to_dict()
# create an instance of DepositUpdate from a dict
deposit_update_from_dict = DepositUpdate.from_dict(deposit_update_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


