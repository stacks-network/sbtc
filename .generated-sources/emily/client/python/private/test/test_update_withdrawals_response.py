# coding: utf-8

"""
    emily-openapi-spec

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.1.0
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


import unittest

from private-emily-client.models.update_withdrawals_response import UpdateWithdrawalsResponse

class TestUpdateWithdrawalsResponse(unittest.TestCase):
    """UpdateWithdrawalsResponse unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> UpdateWithdrawalsResponse:
        """Test UpdateWithdrawalsResponse
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `UpdateWithdrawalsResponse`
        """
        model = UpdateWithdrawalsResponse()
        if include_optional:
            return UpdateWithdrawalsResponse(
                withdrawals = [
                    private-emily-client.models.withdrawal.Withdrawal(
                        amount = 0, 
                        fulfillment = null, 
                        last_update_block_hash = '', 
                        last_update_height = 0, 
                        parameters = private-emily-client.models.withdrawal_parameters.WithdrawalParameters(
                            max_fee = 0, ), 
                        recipient = '', 
                        request_id = 0, 
                        stacks_block_hash = '', 
                        stacks_block_height = 0, 
                        status = 'pending', 
                        status_message = '', )
                    ]
            )
        else:
            return UpdateWithdrawalsResponse(
                withdrawals = [
                    private-emily-client.models.withdrawal.Withdrawal(
                        amount = 0, 
                        fulfillment = null, 
                        last_update_block_hash = '', 
                        last_update_height = 0, 
                        parameters = private-emily-client.models.withdrawal_parameters.WithdrawalParameters(
                            max_fee = 0, ), 
                        recipient = '', 
                        request_id = 0, 
                        stacks_block_hash = '', 
                        stacks_block_height = 0, 
                        status = 'pending', 
                        status_message = '', )
                    ],
        )
        """

    def testUpdateWithdrawalsResponse(self):
        """Test UpdateWithdrawalsResponse"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
