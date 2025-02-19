# emily_client.HealthApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**check_health**](HealthApi.md#check_health) | **GET** /health | Get health handler.


# **check_health**
> HealthData check_health()

Get health handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.health_data import HealthData
from emily_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = emily_client.Configuration(
    host = "http://localhost"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: ApiGatewayKey
configuration.api_key['ApiGatewayKey'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['ApiGatewayKey'] = 'Bearer'

# Enter a context with an instance of the API client
with emily_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = emily_client.HealthApi(api_client)

    try:
        # Get health handler.
        api_response = api_instance.check_health()
        print("The response of HealthApi->check_health:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling HealthApi->check_health: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**HealthData**](HealthData.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Successfully retrieved health data. |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

