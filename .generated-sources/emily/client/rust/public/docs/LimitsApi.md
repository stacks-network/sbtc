# \LimitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_limits**](LimitsApi.md#get_limits) | **GET** /limits | Get the global limits.
[**get_limits_for_account**](LimitsApi.md#get_limits_for_account) | **GET** /limits/{account} | Get limits for account handler.



## get_limits

> models::Limits get_limits()
Get the global limits.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_limits_for_account

> models::AccountLimits get_limits_for_account(account)
Get limits for account handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**account** | **String** | The account for which to get the limits. | [required] |

### Return type

[**models::AccountLimits**](AccountLimits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

