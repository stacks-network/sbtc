# \AddressApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**check_address**](AddressApi.md#check_address) | **GET** /screen/{address} | Handles requests to check the blocklist status of a given address.



## check_address

> models::BlocklistStatus check_address(address)
Handles requests to check the blocklist status of a given address.

Converts successful blocklist status results to JSON and returns them, or converts errors into Warp rejections.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**address** | **String** | Address to get risk assessment for | [required] |

### Return type

[**models::BlocklistStatus**](BlocklistStatus.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

