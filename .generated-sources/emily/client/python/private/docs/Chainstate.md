# Chainstate

Chainstate.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**stacks_block_hash** | **str** | Stacks block hash at the height. | 
**stacks_block_height** | **int** | Stacks block height. | 

## Example

```python
from emily_client.models.chainstate import Chainstate

# TODO update the JSON string below
json = "{}"
# create an instance of Chainstate from a JSON string
chainstate_instance = Chainstate.from_json(json)
# print the JSON string representation of the object
print(Chainstate.to_json())

# convert the object into a dict
chainstate_dict = chainstate_instance.to_dict()
# create an instance of Chainstate from a dict
chainstate_from_dict = Chainstate.from_dict(chainstate_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


