# Fulfillment

Data about the fulfillment of an sBTC Operation.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_block_hash** | **str** | Bitcoin block hash of the block that contains the bitcoin transaction that fulfilled this transaction. | 
**bitcoin_block_height** | **int** | Bitcoin block height of the block that contains the bitcoin transaction that fulfilled this transaction. | 
**bitcoin_tx_index** | **int** | Bitcoin transaction output index of the Bitcoin transaction that fulfilled the operation that corresponds to the fulfillment of this specific operation. | 
**bitcoin_txid** | **str** | Bitcoin transaction id of the Bitcoin transaction that fulfilled the operation. | 
**btc_fee** | **int** | Satoshis consumed to fulfill the sBTC operation. | 
**stacks_txid** | **str** | Stacks transaction Id that fulfilled this operation. | 

## Example

```python
from emily_client.models.fulfillment import Fulfillment

# TODO update the JSON string below
json = "{}"
# create an instance of Fulfillment from a JSON string
fulfillment_instance = Fulfillment.from_json(json)
# print the JSON string representation of the object
print(Fulfillment.to_json())

# convert the object into a dict
fulfillment_dict = fulfillment_instance.to_dict()
# create an instance of Fulfillment from a dict
fulfillment_from_dict = Fulfillment.from_dict(fulfillment_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


