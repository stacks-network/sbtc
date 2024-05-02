import { Template } from 'aws-cdk-lib/assertions';
import * as cdk from 'aws-cdk-lib';
import { EmilyStack } from '../lib/emily-stack';
import { EmilyStackProps } from '../lib/emily-stack-props';
import { Environment } from 'aws-cdk-lib/aws-appconfig';

// Constant test values
const TEST_STACK_PROPS: EmilyStackProps = {
    stageName: "dummyStage",
    env: {
        account: "account",
        region: "region",
    },
}

describe('EmilyStack Test', () => {

    it('should create DynamoDB tables', async () => {
        // Arrange
        const app = new cdk.App();
        const stack = new EmilyStack(app, 'TestStack', TEST_STACK_PROPS);

        // Act
        const template = Template.fromStack(stack);

        // Assert
        const tableResources = template.findResources('AWS::DynamoDB::Table');
        const tableNames = Object.keys(tableResources)
            .map(tableLogicalId => tableResources[tableLogicalId].Properties.TableName);

        // Check that the tables made it in; No need to include tests on the properties
        // that duplicate the specification.
        expect(tableNames).toContain("DepositTable-account-region-dummyStage");
        expect(tableNames).toContain("WithdrawalTable-account-region-dummyStage");
        expect(tableNames).toContain("ChainstateTable-account-region-dummyStage");
    });

    it('should create a Lambda function', async () => {
        // Arrange
        const app = new cdk.App();
        const stack = new EmilyStack(app, 'TestStack', TEST_STACK_PROPS);

        // Act
        const template = Template.fromStack(stack);

        // Assert
        template.hasResourceProperties('AWS::Lambda::Function', {
            // TODO: Add check for properties linking resources created during cdk build.
            Handler: "main",
            Runtime: "provided.al2023",
            Architectures: [ "arm64" ],
            Timeout: 5,
        });

        const lambdaResources = template.findResources('AWS::Lambda::Function');
        expect(Object.keys(lambdaResources)).toHaveLength(1);
        Object.keys(lambdaResources).forEach(lambdaLogicalId => {
            const environment = lambdaResources[lambdaLogicalId].Properties.Environment.Variables;
            expect(environment.DEPOSIT_TABLE_NAME.Ref).toMatch(/^DepositTable/);
            expect(environment.WITHDRAWAL_TABLE_NAME.Ref).toMatch(/^WithdrawalTable/);
            expect(environment.CHAINSTATE_TABLE_NAME.Ref).toMatch(/^ChainstateTable/);
            expect(environment.IS_LOCAL).toEqual("false");
        });
    });

    it('should create a REST API', async () => {
        // Arrange
        const app = new cdk.App();
        const stack = new EmilyStack(app, 'TestStack', TEST_STACK_PROPS);

        // Act
        const template = Template.fromStack(stack);

        // Assert
        template.hasResourceProperties('AWS::ApiGateway::RestApi', {
            // Ignore properties because they change if you change the
            // API template and there's no reason to add another dependency
            // to these tests; the normal inconsistency is just an error
            // that you can't ignore.
        });
    });
});
