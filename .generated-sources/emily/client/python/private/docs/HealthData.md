# HealthData

Struct that represents the current status of the API.

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**is_okay** | **bool** | Whether the API is okay. | 

## Example

```python
from emily_client.models.health_data import HealthData

# TODO update the JSON string below
json = "{}"
# create an instance of HealthData from a JSON string
health_data_instance = HealthData.from_json(json)
# print the JSON string representation of the object
print(HealthData.to_json())

# convert the object into a dict
health_data_dict = health_data_instance.to_dict()
# create an instance of HealthData from a dict
health_data_from_dict = HealthData.from_dict(health_data_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


