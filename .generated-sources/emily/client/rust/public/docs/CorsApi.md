# \CorsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**chainstate_height_options**](CorsApi.md#chainstate_height_options) | **OPTIONS** /chainstate/{height} | CORS support
[**chainstate_options**](CorsApi.md#chainstate_options) | **OPTIONS** /chainstate | CORS support
[**deposit_options**](CorsApi.md#deposit_options) | **OPTIONS** /deposit | CORS support
[**deposit_recipient_recipient_options**](CorsApi.md#deposit_recipient_recipient_options) | **OPTIONS** /deposit/recipient/{recipient} | CORS support
[**deposit_txid_index_options**](CorsApi.md#deposit_txid_index_options) | **OPTIONS** /deposit/{txid}/{index} | CORS support
[**deposit_txid_options**](CorsApi.md#deposit_txid_options) | **OPTIONS** /deposit/{txid} | CORS support
[**health_options**](CorsApi.md#health_options) | **OPTIONS** /health | CORS support
[**limits_account_options**](CorsApi.md#limits_account_options) | **OPTIONS** /limits/{account} | CORS support
[**limits_options**](CorsApi.md#limits_options) | **OPTIONS** /limits | CORS support
[**testing_wipe_options**](CorsApi.md#testing_wipe_options) | **OPTIONS** /testing/wipe | CORS support
[**withdrawal_id_options**](CorsApi.md#withdrawal_id_options) | **OPTIONS** /withdrawal/{id} | CORS support
[**withdrawal_options**](CorsApi.md#withdrawal_options) | **OPTIONS** /withdrawal | CORS support



## chainstate_height_options

> chainstate_height_options(height)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **u64** | Height of the blockchain data to receive. | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## chainstate_options

> chainstate_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deposit_options

> deposit_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deposit_recipient_recipient_options

> deposit_recipient_recipient_options(recipient)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**recipient** | **String** | the status to search by when getting all deposits. | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deposit_txid_index_options

> deposit_txid_index_options(txid, index)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**txid** | **String** | txid associated with the Deposit. | [required] |
**index** | **String** | output index associated with the Deposit. | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deposit_txid_options

> deposit_txid_options(txid)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**txid** | **String** | txid associated with the Deposit. | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## health_options

> health_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## limits_account_options

> limits_account_options(account)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**account** | **String** | The account for which to get the limits. | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## limits_options

> limits_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## testing_wipe_options

> testing_wipe_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## withdrawal_id_options

> withdrawal_id_options(id)
CORS support

Handles CORS preflight requests

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **u64** | id associated with the Withdrawal | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## withdrawal_options

> withdrawal_options()
CORS support

Handles CORS preflight requests

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

