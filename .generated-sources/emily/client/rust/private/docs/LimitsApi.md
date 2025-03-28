# \LimitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_limits**](LimitsApi.md#get_limits) | **GET** /limits | Get the global limits.
[**get_limits_for_account**](LimitsApi.md#get_limits_for_account) | **GET** /limits/{account} | Get limits for account handler.
[**set_limits**](LimitsApi.md#set_limits) | **POST** /limits | Set limits handler.
[**set_limits_for_account**](LimitsApi.md#set_limits_for_account) | **POST** /limits/{account} | Set limits for account handler.



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


## set_limits

> models::Limits set_limits(limits)
Set limits handler.

Note, that `available_to_withdraw` is not settable, but is calculated based on the other fields. Value of `available_to_withdraw` passed to this endpoint will be ignored.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limits** | [**Limits**](Limits.md) |  | [required] |

### Return type

[**models::Limits**](Limits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_limits_for_account

> models::AccountLimits set_limits_for_account(account, account_limits)
Set limits for account handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**account** | **String** | The account for which to set the limits. | [required] |
**account_limits** | [**AccountLimits**](AccountLimits.md) |  | [required] |

### Return type

[**models::AccountLimits**](AccountLimits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

