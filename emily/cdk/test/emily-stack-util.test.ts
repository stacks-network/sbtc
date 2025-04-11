import { Constants } from '../lib/constants';
import { EmilyStackProps } from '../lib/emily-stack-props';
import { EmilyStackUtils } from '../lib/emily-stack-utils';

describe('EmilyStackUtils Test', () => {

    beforeEach(() => {
        jest.resetModules();
    })

    it('test resource name is generated properly.', async () => {
        const testEmilyStackProps: EmilyStackProps = {
            stackName: "testStack",
            stageName: Constants.UNIT_TEST_STAGE_NAME, // Default to dev stage.
            env: {
                account: "testAwsAccount",
                region: "testAwsRegion",
            },
            deployerAddress: "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS",
        }
        const resourceName: string = EmilyStackUtils
            .getResourceName("ResourceId", testEmilyStackProps);
        expect(resourceName).toEqual(`ResourceId-testAwsAccount-testAwsRegion-${Constants.UNIT_TEST_STAGE_NAME}`);
    });

    it('Test resource name is generated properly.', async () => {
        process.env = {
            AWS_STAGE: Constants.UNIT_TEST_STAGE_NAME,
            AWS_ACCOUNT: "TestAccount",
            AWS_REGION: "TestRegion",
            DEPLOYER_ADDRESS: "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS",
        };
        const resourceName: string = EmilyStackUtils.getStackName("StackId");
        expect(resourceName).toEqual(`StackId-TestAccount-TestRegion-${Constants.UNIT_TEST_STAGE_NAME}`);
    });
});
