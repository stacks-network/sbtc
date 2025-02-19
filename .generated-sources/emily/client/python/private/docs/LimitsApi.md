# emily_client.LimitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_limits**](LimitsApi.md#get_limits) | **GET** /limits | Get the global limits.
[**get_limits_for_account**](LimitsApi.md#get_limits_for_account) | **GET** /limits/{account} | Get limits for account handler.
[**set_limits**](LimitsApi.md#set_limits) | **POST** /limits | Get limits handler.
[**set_limits_for_account**](LimitsApi.md#set_limits_for_account) | **POST** /limits/{account} | Set limits for account handler.


# **get_limits**
> Limits get_limits()

Get the global limits.

### Example


```python
import emily_client
from emily_client.models.limits import Limits
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
    api_instance = emily_client.LimitsApi(api_client)

    try:
        # Get the global limits.
        api_response = api_instance.get_limits()
        print("The response of LimitsApi->get_limits:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling LimitsApi->get_limits: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Limits retrieved successfully |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_limits_for_account**
> AccountLimits get_limits_for_account(account)

Get limits for account handler.

### Example


```python
import emily_client
from emily_client.models.account_limits import AccountLimits
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
    api_instance = emily_client.LimitsApi(api_client)
    account = 'account_example' # str | The account for which to get the limits.

    try:
        # Get limits for account handler.
        api_response = api_instance.get_limits_for_account(account)
        print("The response of LimitsApi->get_limits_for_account:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling LimitsApi->get_limits_for_account: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **account** | **str**| The account for which to get the limits. | 

### Return type

[**AccountLimits**](AccountLimits.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Account limits retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **set_limits**
> Limits set_limits(limits)

Get limits handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.limits import Limits
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
    api_instance = emily_client.LimitsApi(api_client)
    limits = emily_client.Limits() # Limits | 

    try:
        # Get limits handler.
        api_response = api_instance.set_limits(limits)
        print("The response of LimitsApi->set_limits:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling LimitsApi->set_limits: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limits** | [**Limits**](Limits.md)|  | 

### Return type

[**Limits**](Limits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Limits updated successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **set_limits_for_account**
> AccountLimits set_limits_for_account(account, account_limits)

Set limits for account handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.account_limits import AccountLimits
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
    api_instance = emily_client.LimitsApi(api_client)
    account = 'account_example' # str | The account for which to set the limits.
    account_limits = emily_client.AccountLimits() # AccountLimits | 

    try:
        # Set limits for account handler.
        api_response = api_instance.set_limits_for_account(account, account_limits)
        print("The response of LimitsApi->set_limits_for_account:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling LimitsApi->set_limits_for_account: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **account** | **str**| The account for which to set the limits. | 
 **account_limits** | [**AccountLimits**](AccountLimits.md)|  | 

### Return type

[**AccountLimits**](AccountLimits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Set account limits successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

