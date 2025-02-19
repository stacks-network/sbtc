# emily_client.ChainstateApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_chain_tip**](ChainstateApi.md#get_chain_tip) | **GET** /chainstate | Get chain tip handler.
[**get_chainstate_at_height**](ChainstateApi.md#get_chainstate_at_height) | **GET** /chainstate/{height} | Get chainstate handler.
[**set_chainstate**](ChainstateApi.md#set_chainstate) | **POST** /chainstate | Set chainstate handler.
[**update_chainstate**](ChainstateApi.md#update_chainstate) | **PUT** /chainstate | Update chainstate handler.


# **get_chain_tip**
> Chainstate get_chain_tip()

Get chain tip handler.

### Example


```python
import emily_client
from emily_client.models.chainstate import Chainstate
from emily_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = emily_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with emily_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = emily_client.ChainstateApi(api_client)

    try:
        # Get chain tip handler.
        api_response = api_instance.get_chain_tip()
        print("The response of ChainstateApi->get_chain_tip:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ChainstateApi->get_chain_tip: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**Chainstate**](Chainstate.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Chain tip retrieved successfully |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_chainstate_at_height**
> Chainstate get_chainstate_at_height(height)

Get chainstate handler.

### Example


```python
import emily_client
from emily_client.models.chainstate import Chainstate
from emily_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = emily_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with emily_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = emily_client.ChainstateApi(api_client)
    height = 56 # int | Height of the blockchain data to receive.

    try:
        # Get chainstate handler.
        api_response = api_instance.get_chainstate_at_height(height)
        print("The response of ChainstateApi->get_chainstate_at_height:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ChainstateApi->get_chainstate_at_height: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **height** | **int**| Height of the blockchain data to receive. | 

### Return type

[**Chainstate**](Chainstate.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Chainstate retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **set_chainstate**
> Chainstate set_chainstate(chainstate)

Set chainstate handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.chainstate import Chainstate
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
    api_instance = emily_client.ChainstateApi(api_client)
    chainstate = emily_client.Chainstate() # Chainstate | 

    try:
        # Set chainstate handler.
        api_response = api_instance.set_chainstate(chainstate)
        print("The response of ChainstateApi->set_chainstate:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ChainstateApi->set_chainstate: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chainstate** | [**Chainstate**](Chainstate.md)|  | 

### Return type

[**Chainstate**](Chainstate.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Chainstate updated successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_chainstate**
> Chainstate update_chainstate(chainstate)

Update chainstate handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.chainstate import Chainstate
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
    api_instance = emily_client.ChainstateApi(api_client)
    chainstate = emily_client.Chainstate() # Chainstate | 

    try:
        # Update chainstate handler.
        api_response = api_instance.update_chainstate(chainstate)
        print("The response of ChainstateApi->update_chainstate:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ChainstateApi->update_chainstate: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chainstate** | [**Chainstate**](Chainstate.md)|  | 

### Return type

[**Chainstate**](Chainstate.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Chainstate updated successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

