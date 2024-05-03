import { EmilyStackProps } from '../lib/emily-stack-props';
import { EmilyStackUtils } from '../lib/emily-stack-utils';

describe('EmilyStackUtils Test', () => {

    beforeEach(() => {
        jest.resetModules();
    })

    it('test resource name is generated properly.', async () => {
        const testEmilyStackProps: EmilyStackProps = {
            stackName: "testStack",
            stageName: "testStage", // Default to dev stage.
            env: {
                account: "testAwsAccount",
                region: "testAwsRegion",
            },
        }
        const resourceName: string = EmilyStackUtils
            .getResourceName("ResourceId", testEmilyStackProps);
        expect(resourceName).toEqual("ResourceId-testAwsAccount-testAwsRegion-testStage");
    });

    it('Test resource name is generated properly.', async () => {
        process.env = {
            AWS_STAGE: "TestStage",
            AWS_ACCOUNT: "TestAccount" ,
            AWS_REGION: "TestRegion",
        };
        const resourceName: string = EmilyStackUtils.getStackName("StackId");
        expect(resourceName).toEqual("StackId-TestAccount-TestRegion-TestStage");
    });
});
