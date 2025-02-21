# emily_client.DepositApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_deposit**](DepositApi.md#create_deposit) | **POST** /deposit | Create deposit handler.
[**get_deposit**](DepositApi.md#get_deposit) | **GET** /deposit/{txid}/{index} | Get deposit handler.
[**get_deposits**](DepositApi.md#get_deposits) | **GET** /deposit | Get deposits handler.
[**get_deposits_for_recipient**](DepositApi.md#get_deposits_for_recipient) | **GET** /deposit/recipient/{recipient} | Get deposits by recipient handler.
[**get_deposits_for_transaction**](DepositApi.md#get_deposits_for_transaction) | **GET** /deposit/{txid} | Get deposits for transaction handler.
[**update_deposits**](DepositApi.md#update_deposits) | **PUT** /deposit | Update deposits handler.


# **create_deposit**
> Deposit create_deposit(create_deposit_request_body)

Create deposit handler.

### Example


```python
import emily_client
from emily_client.models.create_deposit_request_body import CreateDepositRequestBody
from emily_client.models.deposit import Deposit
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
    api_instance = emily_client.DepositApi(api_client)
    create_deposit_request_body = emily_client.CreateDepositRequestBody() # CreateDepositRequestBody | 

    try:
        # Create deposit handler.
        api_response = api_instance.create_deposit(create_deposit_request_body)
        print("The response of DepositApi->create_deposit:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->create_deposit: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **create_deposit_request_body** | [**CreateDepositRequestBody**](CreateDepositRequestBody.md)|  | 

### Return type

[**Deposit**](Deposit.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Deposit created successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**409** | Duplicate request |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_deposit**
> Deposit get_deposit(txid, index)

Get deposit handler.

### Example


```python
import emily_client
from emily_client.models.deposit import Deposit
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
    api_instance = emily_client.DepositApi(api_client)
    txid = 'txid_example' # str | txid associated with the Deposit.
    index = 'index_example' # str | output index associated with the Deposit.

    try:
        # Get deposit handler.
        api_response = api_instance.get_deposit(txid, index)
        print("The response of DepositApi->get_deposit:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->get_deposit: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **txid** | **str**| txid associated with the Deposit. | 
 **index** | **str**| output index associated with the Deposit. | 

### Return type

[**Deposit**](Deposit.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Deposit retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_deposits**
> GetDepositsResponse get_deposits(status, next_token=next_token, page_size=page_size)

Get deposits handler.

### Example


```python
import emily_client
from emily_client.models.get_deposits_response import GetDepositsResponse
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
    api_instance = emily_client.DepositApi(api_client)
    status = emily_client.Status() # Status | the status to search by when getting all deposits.
    next_token = 'next_token_example' # str | the next token value from the previous return of this api call. (optional)
    page_size = 56 # int | the maximum number of items in the response list. (optional)

    try:
        # Get deposits handler.
        api_response = api_instance.get_deposits(status, next_token=next_token, page_size=page_size)
        print("The response of DepositApi->get_deposits:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->get_deposits: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **status** | [**Status**](.md)| the status to search by when getting all deposits. | 
 **next_token** | **str**| the next token value from the previous return of this api call. | [optional] 
 **page_size** | **int**| the maximum number of items in the response list. | [optional] 

### Return type

[**GetDepositsResponse**](GetDepositsResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Deposits retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_deposits_for_recipient**
> GetDepositsResponse get_deposits_for_recipient(recipient, next_token=next_token, page_size=page_size)

Get deposits by recipient handler.

### Example


```python
import emily_client
from emily_client.models.get_deposits_response import GetDepositsResponse
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
    api_instance = emily_client.DepositApi(api_client)
    recipient = 'recipient_example' # str | the status to search by when getting all deposits.
    next_token = 'next_token_example' # str | the next token value from the previous return of this api call. (optional)
    page_size = 56 # int | the maximum number of items in the response list. (optional)

    try:
        # Get deposits by recipient handler.
        api_response = api_instance.get_deposits_for_recipient(recipient, next_token=next_token, page_size=page_size)
        print("The response of DepositApi->get_deposits_for_recipient:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->get_deposits_for_recipient: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **recipient** | **str**| the status to search by when getting all deposits. | 
 **next_token** | **str**| the next token value from the previous return of this api call. | [optional] 
 **page_size** | **int**| the maximum number of items in the response list. | [optional] 

### Return type

[**GetDepositsResponse**](GetDepositsResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Deposits retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_deposits_for_transaction**
> GetDepositsForTransactionResponse get_deposits_for_transaction(txid, next_token=next_token, page_size=page_size)

Get deposits for transaction handler.

### Example


```python
import emily_client
from emily_client.models.get_deposits_for_transaction_response import GetDepositsForTransactionResponse
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
    api_instance = emily_client.DepositApi(api_client)
    txid = 'txid_example' # str | txid associated with the Deposit.
    next_token = 'next_token_example' # str | the next token value from the previous return of this api call. (optional)
    page_size = 56 # int | the maximum number of items in the response list. (optional)

    try:
        # Get deposits for transaction handler.
        api_response = api_instance.get_deposits_for_transaction(txid, next_token=next_token, page_size=page_size)
        print("The response of DepositApi->get_deposits_for_transaction:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->get_deposits_for_transaction: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **txid** | **str**| txid associated with the Deposit. | 
 **next_token** | **str**| the next token value from the previous return of this api call. | [optional] 
 **page_size** | **int**| the maximum number of items in the response list. | [optional] 

### Return type

[**GetDepositsForTransactionResponse**](GetDepositsForTransactionResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Deposits retrieved successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_deposits**
> UpdateDepositsResponse update_deposits(update_deposits_request_body)

Update deposits handler.

### Example

* Api Key Authentication (ApiGatewayKey):

```python
import emily_client
from emily_client.models.update_deposits_request_body import UpdateDepositsRequestBody
from emily_client.models.update_deposits_response import UpdateDepositsResponse
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
    api_instance = emily_client.DepositApi(api_client)
    update_deposits_request_body = emily_client.UpdateDepositsRequestBody() # UpdateDepositsRequestBody | 

    try:
        # Update deposits handler.
        api_response = api_instance.update_deposits(update_deposits_request_body)
        print("The response of DepositApi->update_deposits:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DepositApi->update_deposits: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **update_deposits_request_body** | [**UpdateDepositsRequestBody**](UpdateDepositsRequestBody.md)|  | 

### Return type

[**UpdateDepositsResponse**](UpdateDepositsResponse.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Deposits updated successfully |  -  |
**400** | Invalid request body |  -  |
**404** | Address not found |  -  |
**405** | Method not allowed |  -  |
**500** | Internal server error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

