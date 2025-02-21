# emily_client.WithdrawalApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_withdrawal**](WithdrawalApi.md#create_withdrawal) | **POST** /withdrawal | Create withdrawal handler.
[**get_withdrawal**](WithdrawalApi.md#get_withdrawal) | **GET** /withdrawal/{id} | Get withdrawal handler.
[**get_withdrawals**](WithdrawalApi.md#get_withdrawals) | **GET** /withdrawal | Get withdrawals handler.
[**update_withdrawals**](WithdrawalApi.md#update_withdrawals) | **PUT** /withdrawal | Update withdrawals handler.


# **create_withdrawal**
> Withdrawal create_withdrawal(create_withdrawal_request_body)

Create withdrawal handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.create_withdrawal_request_body import CreateWithdrawalRequestBody
from emily_client.models.withdrawal import Withdrawal
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
    api_instance = emily_client.WithdrawalApi(api_client)
    create_withdrawal_request_body = emily_client.CreateWithdrawalRequestBody() # CreateWithdrawalRequestBody | 

    try:
        # Create withdrawal handler.
        api_response = api_instance.create_withdrawal(create_withdrawal_request_body)
        print("The response of WithdrawalApi->create_withdrawal:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling WithdrawalApi->create_withdrawal: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **create_withdrawal_request_body** | [**CreateWithdrawalRequestBody**](CreateWithdrawalRequestBody.md)|  | 

### Return type

[**Withdrawal**](Withdrawal.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Withdrawal created successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_withdrawal**
> Withdrawal get_withdrawal(id)

Get withdrawal handler.

### Example


```python
import emily_client
from emily_client.models.withdrawal import Withdrawal
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
    api_instance = emily_client.WithdrawalApi(api_client)
    id = 56 # int | id associated with the Withdrawal

    try:
        # Get withdrawal handler.
        api_response = api_instance.get_withdrawal(id)
        print("The response of WithdrawalApi->get_withdrawal:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling WithdrawalApi->get_withdrawal: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **int**| id associated with the Withdrawal | 

### Return type

[**Withdrawal**](Withdrawal.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Withdrawal retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_withdrawals**
> GetWithdrawalsResponse get_withdrawals(status, next_token=next_token, page_size=page_size)

Get withdrawals handler.

### Example


```python
import emily_client
from emily_client.models.get_withdrawals_response import GetWithdrawalsResponse
from emily_client.models.status import Status
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
    api_instance = emily_client.WithdrawalApi(api_client)
    status = emily_client.Status() # Status | the status to search by when getting all deposits.
    next_token = 'next_token_example' # str | the next token value from the previous return of this api call. (optional)
    page_size = 56 # int | the maximum number of items in the response list. (optional)

    try:
        # Get withdrawals handler.
        api_response = api_instance.get_withdrawals(status, next_token=next_token, page_size=page_size)
        print("The response of WithdrawalApi->get_withdrawals:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling WithdrawalApi->get_withdrawals: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **status** | [**Status**](.md)| the status to search by when getting all deposits. | 
 **next_token** | **str**| the next token value from the previous return of this api call. | [optional] 
 **page_size** | **int**| the maximum number of items in the response list. | [optional] 

### Return type

[**GetWithdrawalsResponse**](GetWithdrawalsResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Withdrawals retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_withdrawals**
> UpdateWithdrawalsResponse update_withdrawals(update_withdrawals_request_body)

Update withdrawals handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.update_withdrawals_request_body import UpdateWithdrawalsRequestBody
from emily_client.models.update_withdrawals_response import UpdateWithdrawalsResponse
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
    api_instance = emily_client.WithdrawalApi(api_client)
    update_withdrawals_request_body = emily_client.UpdateWithdrawalsRequestBody() # UpdateWithdrawalsRequestBody | 

    try:
        # Update withdrawals handler.
        api_response = api_instance.update_withdrawals(update_withdrawals_request_body)
        print("The response of WithdrawalApi->update_withdrawals:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling WithdrawalApi->update_withdrawals: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **update_withdrawals_request_body** | [**UpdateWithdrawalsRequestBody**](UpdateWithdrawalsRequestBody.md)|  | 

### Return type

[**UpdateWithdrawalsResponse**](UpdateWithdrawalsResponse.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Withdrawals updated successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

