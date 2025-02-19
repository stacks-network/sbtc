# DepositInfo

Reduced version of the Deposit data.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**amount** | **int** | Amount of BTC being deposited in satoshis. | 
**bitcoin_tx_output_index** | **int** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **str** | Bitcoin transaction id. | 
**deposit_script** | **str** | Raw deposit script binary in hex. | 
**last_update_block_hash** | **str** | The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact. | 
**last_update_height** | **int** | The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact. | 
**recipient** | **str** | Stacks address to received the deposited sBTC. | 
**reclaim_script** | **str** | Raw reclaim script binary in hex. | 
**status** | [**Status**](Status.md) |  | 

## Example

```python
from emily_client.models.deposit_info import DepositInfo

# TODO update the JSON string below
json = "{}"
# create an instance of DepositInfo from a JSON string
deposit_info_instance = DepositInfo.from_json(json)
# print the JSON string representation of the object
print(DepositInfo.to_json())

# convert the object into a dict
deposit_info_dict = deposit_info_instance.to_dict()
# create an instance of DepositInfo from a dict
deposit_info_from_dict = DepositInfo.from_dict(deposit_info_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


