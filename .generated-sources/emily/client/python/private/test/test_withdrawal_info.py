# coding: utf-8

"""
    emily-openapi-spec

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.1.0
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


import unittest

from private-emily-client.models.withdrawal_info import WithdrawalInfo

class TestWithdrawalInfo(unittest.TestCase):
    """WithdrawalInfo unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> WithdrawalInfo:
        """Test WithdrawalInfo
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `WithdrawalInfo`
        """
        model = WithdrawalInfo()
        if include_optional:
            return WithdrawalInfo(
                amount = 0,
                last_update_block_hash = '',
                last_update_height = 0,
                recipient = '',
                request_id = 0,
                stacks_block_hash = '',
                stacks_block_height = 0,
                status = 'pending'
            )
        else:
            return WithdrawalInfo(
                amount = 0,
                last_update_block_hash = '',
                last_update_height = 0,
                recipient = '',
                request_id = 0,
                stacks_block_hash = '',
                stacks_block_height = 0,
                status = 'pending',
        )
        """

    def testWithdrawalInfo(self):
        """Test WithdrawalInfo"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
