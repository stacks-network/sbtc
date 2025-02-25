# Limits

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**account_caps** | [**std::collections::HashMap<String, models::AccountLimits>**](AccountLimits.md) | Represents the individual limits for requests coming from different accounts. | 
**peg_cap** | Option<**u64**> | Represents the total cap for all pegged-in BTC/sBTC. | [optional]
**per_deposit_cap** | Option<**u64**> | Per deposit cap. If none then there is no cap. | [optional]
**per_deposit_minimum** | Option<**u64**> | Per deposit minimum. If none then there is no minimum. | [optional]
**per_withdrawal_cap** | Option<**u64**> | Per withdrawal cap. If none then there is no cap. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


