# Deposit

Deposit.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **int** | Amount of BTC being deposited in satoshis. | 
**bitcoin_tx_output_index** | **int** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **str** | Bitcoin transaction id. | 
**deposit_script** | **str** | Raw deposit script binary in hex. | 
**fulfillment** | [**Fulfillment**](Fulfillment.md) |  | [optional] 
**last_update_block_hash** | **str** | The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **int** | The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**parameters** | [**DepositParameters**](DepositParameters.md) |  | 
**recipient** | **str** | Stacks address to received the deposited sBTC. | 
**reclaim_script** | **str** | Raw reclaim script binary in hex. | 
**status** | [**Status**](Status.md) |  | 
**status_message** | **str** | The status message of the deposit. | 

## Example

```python
from emily_client.models.deposit import Deposit

# TODO update the JSON string below
json = "{}"
# create an instance of Deposit from a JSON string
deposit_instance = Deposit.from_json(json)
# print the JSON string representation of the object
print(Deposit.to_json())

# convert the object into a dict
deposit_dict = deposit_instance.to_dict()
# create an instance of Deposit from a dict
deposit_from_dict = Deposit.from_dict(deposit_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


