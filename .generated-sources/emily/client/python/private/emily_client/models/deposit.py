# coding: utf-8

"""
    emily-openapi-spec

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.1.0
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import pprint
import re  # noqa: F401
import json

from pydantic import BaseModel, ConfigDict, Field, StrictStr
from typing import Any, ClassVar, Dict, List, Optional
from typing_extensions import Annotated
from emily_client.models.deposit_parameters import DepositParameters
from emily_client.models.fulfillment import Fulfillment
from emily_client.models.status import Status
from typing import Optional, Set
from typing_extensions import Self

class Deposit(BaseModel):
    """
    Deposit.
    """ # noqa: E501
    amount: Annotated[int, Field(strict=True, ge=0)] = Field(description="Amount of BTC being deposited in satoshis.")
    bitcoin_tx_output_index: Annotated[int, Field(strict=True, ge=0)] = Field(description="Output index on the bitcoin transaction associated with this specific deposit.", alias="bitcoinTxOutputIndex")
    bitcoin_txid: StrictStr = Field(description="Bitcoin transaction id.", alias="bitcoinTxid")
    deposit_script: StrictStr = Field(description="Raw deposit script binary in hex.", alias="depositScript")
    fulfillment: Optional[Fulfillment] = None
    last_update_block_hash: StrictStr = Field(description="The most recent Stacks block hash the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact.", alias="lastUpdateBlockHash")
    last_update_height: Annotated[int, Field(strict=True, ge=0)] = Field(description="The most recent Stacks block height the API was aware of when the deposit was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact.", alias="lastUpdateHeight")
    parameters: DepositParameters
    recipient: StrictStr = Field(description="Stacks address to received the deposited sBTC.")
    reclaim_script: StrictStr = Field(description="Raw reclaim script binary in hex.", alias="reclaimScript")
    status: Status
    status_message: StrictStr = Field(description="The status message of the deposit.", alias="statusMessage")
    __properties: ClassVar[List[str]] = ["amount", "bitcoinTxOutputIndex", "bitcoinTxid", "depositScript", "fulfillment", "lastUpdateBlockHash", "lastUpdateHeight", "parameters", "recipient", "reclaimScript", "status", "statusMessage"]

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        protected_namespaces=(),
    )


    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        """Create an instance of Deposit from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of the model using alias.

        This has the following differences from calling pydantic's
        `self.model_dump(by_alias=True)`:

        * `None` is only added to the output dict for nullable fields that
          were set at model initialization. Other fields with value `None`
          are ignored.
        """
        excluded_fields: Set[str] = set([
        ])

        _dict = self.model_dump(
            by_alias=True,
            exclude=excluded_fields,
            exclude_none=True,
        )
        # override the default output from pydantic by calling `to_dict()` of fulfillment
        if self.fulfillment:
            _dict['fulfillment'] = self.fulfillment.to_dict()
        # override the default output from pydantic by calling `to_dict()` of parameters
        if self.parameters:
            _dict['parameters'] = self.parameters.to_dict()
        # set to None if fulfillment (nullable) is None
        # and model_fields_set contains the field
        if self.fulfillment is None and "fulfillment" in self.model_fields_set:
            _dict['fulfillment'] = None

        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of Deposit from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "amount": obj.get("amount"),
            "bitcoinTxOutputIndex": obj.get("bitcoinTxOutputIndex"),
            "bitcoinTxid": obj.get("bitcoinTxid"),
            "depositScript": obj.get("depositScript"),
            "fulfillment": Fulfillment.from_dict(obj["fulfillment"]) if obj.get("fulfillment") is not None else None,
            "lastUpdateBlockHash": obj.get("lastUpdateBlockHash"),
            "lastUpdateHeight": obj.get("lastUpdateHeight"),
            "parameters": DepositParameters.from_dict(obj["parameters"]) if obj.get("parameters") is not None else None,
            "recipient": obj.get("recipient"),
            "reclaimScript": obj.get("reclaimScript"),
            "status": obj.get("status"),
            "statusMessage": obj.get("statusMessage")
        })
        return _obj


