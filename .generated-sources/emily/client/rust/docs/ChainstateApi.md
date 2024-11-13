# \ChainstateApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_chain_tip**](ChainstateApi.md#get_chain_tip) | **GET** /chainstate | Get chain tip handler.
[**get_chainstate_at_height**](ChainstateApi.md#get_chainstate_at_height) | **GET** /chainstate/{height} | Get chainstate handler.
[**set_chainstate**](ChainstateApi.md#set_chainstate) | **POST** /chainstate | Set chainstate handler.
[**update_chainstate**](ChainstateApi.md#update_chainstate) | **PUT** /chainstate | Update chainstate handler.



## get_chain_tip

> models::Chainstate get_chain_tip()
Get chain tip handler.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Chainstate**](Chainstate.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_chainstate_at_height

> models::Chainstate get_chainstate_at_height(height)
Get chainstate handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**height** | **u64** | Height of the blockchain data to receive. | [required] |

### Return type

[**models::Chainstate**](Chainstate.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_chainstate

> models::Chainstate set_chainstate(chainstate)
Set chainstate handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**chainstate** | [**Chainstate**](Chainstate.md) |  | [required] |

### Return type

[**models::Chainstate**](Chainstate.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_chainstate

> models::Chainstate update_chainstate(chainstate)
Update chainstate handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**chainstate** | [**Chainstate**](Chainstate.md) |  | [required] |

### Return type

[**models::Chainstate**](Chainstate.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

