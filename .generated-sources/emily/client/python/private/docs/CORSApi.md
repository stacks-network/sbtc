# emily_client.CORSApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**chainstate_height_options**](CORSApi.md#chainstate_height_options) | **OPTIONS** /chainstate/{height} | CORS support
[**chainstate_options**](CORSApi.md#chainstate_options) | **OPTIONS** /chainstate | CORS support
[**deposit_options**](CORSApi.md#deposit_options) | **OPTIONS** /deposit | CORS support
[**deposit_recipient_recipient_options**](CORSApi.md#deposit_recipient_recipient_options) | **OPTIONS** /deposit/recipient/{recipient} | CORS support
[**deposit_txid_index_options**](CORSApi.md#deposit_txid_index_options) | **OPTIONS** /deposit/{txid}/{index} | CORS support
[**deposit_txid_options**](CORSApi.md#deposit_txid_options) | **OPTIONS** /deposit/{txid} | CORS support
[**health_options**](CORSApi.md#health_options) | **OPTIONS** /health | CORS support
[**limits_account_options**](CORSApi.md#limits_account_options) | **OPTIONS** /limits/{account} | CORS support
[**limits_options**](CORSApi.md#limits_options) | **OPTIONS** /limits | CORS support
[**withdrawal_id_options**](CORSApi.md#withdrawal_id_options) | **OPTIONS** /withdrawal/{id} | CORS support
[**withdrawal_options**](CORSApi.md#withdrawal_options) | **OPTIONS** /withdrawal | CORS support


# **chainstate_height_options**
> chainstate_height_options(height)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    height = 56 # int | Height of the blockchain data to receive.

    try:
        # CORS support
        api_instance.chainstate_height_options(height)
    except Exception as e:
        print("Exception when calling CORSApi->chainstate_height_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **height** | **int**| Height of the blockchain data to receive. | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **chainstate_options**
> chainstate_options()

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)

    try:
        # CORS support
        api_instance.chainstate_options()
    except Exception as e:
        print("Exception when calling CORSApi->chainstate_options: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **deposit_options**
> deposit_options()

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)

    try:
        # CORS support
        api_instance.deposit_options()
    except Exception as e:
        print("Exception when calling CORSApi->deposit_options: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **deposit_recipient_recipient_options**
> deposit_recipient_recipient_options(recipient)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    recipient = 'recipient_example' # str | the status to search by when getting all deposits.

    try:
        # CORS support
        api_instance.deposit_recipient_recipient_options(recipient)
    except Exception as e:
        print("Exception when calling CORSApi->deposit_recipient_recipient_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **recipient** | **str**| the status to search by when getting all deposits. | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **deposit_txid_index_options**
> deposit_txid_index_options(txid, index)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    txid = 'txid_example' # str | txid associated with the Deposit.
    index = 'index_example' # str | output index associated with the Deposit.

    try:
        # CORS support
        api_instance.deposit_txid_index_options(txid, index)
    except Exception as e:
        print("Exception when calling CORSApi->deposit_txid_index_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **txid** | **str**| txid associated with the Deposit. | 
 **index** | **str**| output index associated with the Deposit. | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **deposit_txid_options**
> deposit_txid_options(txid)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    txid = 'txid_example' # str | txid associated with the Deposit.

    try:
        # CORS support
        api_instance.deposit_txid_options(txid)
    except Exception as e:
        print("Exception when calling CORSApi->deposit_txid_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **txid** | **str**| txid associated with the Deposit. | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **health_options**
> health_options()

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)

    try:
        # CORS support
        api_instance.health_options()
    except Exception as e:
        print("Exception when calling CORSApi->health_options: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **limits_account_options**
> limits_account_options(account)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    account = 'account_example' # str | The account for which to get the limits.

    try:
        # CORS support
        api_instance.limits_account_options(account)
    except Exception as e:
        print("Exception when calling CORSApi->limits_account_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **account** | **str**| The account for which to get the limits. | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **limits_options**
> limits_options()

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)

    try:
        # CORS support
        api_instance.limits_options()
    except Exception as e:
        print("Exception when calling CORSApi->limits_options: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **withdrawal_id_options**
> withdrawal_id_options(id)

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)
    id = 56 # int | id associated with the Withdrawal

    try:
        # CORS support
        api_instance.withdrawal_id_options(id)
    except Exception as e:
        print("Exception when calling CORSApi->withdrawal_id_options: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **int**| id associated with the Withdrawal | 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **withdrawal_options**
> withdrawal_options()

CORS support

Handles CORS preflight requests

### Example


```python
import emily_client
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
    api_instance = emily_client.CORSApi(api_client)

    try:
        # CORS support
        api_instance.withdrawal_options()
    except Exception as e:
        print("Exception when calling CORSApi->withdrawal_options: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined


[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

