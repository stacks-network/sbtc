# \LimitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_limits**](LimitsApi.md#get_limits) | **GET** /limits | Get chain tip handler.
[**get_limits_for_account**](LimitsApi.md#get_limits_for_account) | **GET** /limits/{account} | Update chainstate handler.
[**set_limits**](LimitsApi.md#set_limits) | **POST** /limits | Get chainstate handler.
[**set_limits_for_account**](LimitsApi.md#set_limits_for_account) | **POST** /limits/{account} | Set account limits handler.



## get_limits

> models::Limits get_limits()
Get chain tip handler.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Limits**](Limits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_limits_for_account

> models::AccountLimits get_limits_for_account(account)
Update chainstate handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**account** | **String** | The account for which to get the limits. | [required] |

### Return type

[**models::AccountLimits**](AccountLimits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_limits

> models::Limits set_limits(limits)
Get chainstate handler.

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
Set account limits handler.

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

