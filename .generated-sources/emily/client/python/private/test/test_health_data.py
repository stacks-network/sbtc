# coding: utf-8

"""
    emily-openapi-spec

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.1.0
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


import unittest

from private-emily-client.models.health_data import HealthData

class TestHealthData(unittest.TestCase):
    """HealthData unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> HealthData:
        """Test HealthData
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `HealthData`
        """
        model = HealthData()
        if include_optional:
            return HealthData(
                is_okay = True
            )
        else:
            return HealthData(
                is_okay = True,
        )
        """

    def testHealthData(self):
        """Test HealthData"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
