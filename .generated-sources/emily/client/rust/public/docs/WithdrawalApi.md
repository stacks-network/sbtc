# \WithdrawalApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_withdrawal**](WithdrawalApi.md#get_withdrawal) | **GET** /withdrawal/{id} | Get withdrawal handler.
[**get_withdrawals**](WithdrawalApi.md#get_withdrawals) | **GET** /withdrawal | Get withdrawals handler.



## get_withdrawal

> models::Withdrawal get_withdrawal(id)
Get withdrawal handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **u64** | id associated with the Withdrawal | [required] |

### Return type

[**models::Withdrawal**](Withdrawal.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_withdrawals

> models::GetWithdrawalsResponse get_withdrawals(status, next_token, page_size)
Get withdrawals handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**status** | [**Status**](.md) | the status to search by when getting all deposits. | [required] |
**next_token** | Option<**String**> | the next token value from the previous return of this api call. |  |
**page_size** | Option<**i32**> | the maximum number of items in the response list. |  |

### Return type

[**models::GetWithdrawalsResponse**](GetWithdrawalsResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

