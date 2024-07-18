// Import the AWS CDK
import * as cdk from 'aws-cdk-lib';
import * as apig from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { Constants } from './constants';
import { EmilyStackProps } from './emily-stack-props';
import { EmilyStackUtils } from './emily-stack-utils';

/**
 * @class EmilyStack
 * @classdesc Creates a stack with DynamoDB tables and a Lambda function.
 */
export class EmilyStack extends cdk.Stack {

    /**
     * @constructor
     * @param {Construct} scope The AWS CDK construct scope.
     * @param {string} id The stack ID.
     * @param {EmilyStackProps} props The stack properties.
     */
    constructor(scope: Construct, id: string, props: EmilyStackProps) {
        super(scope, id, props);

        const depositTableId: string = 'DepositTable';
        const depositTableName: string = EmilyStackUtils.getResourceName(depositTableId, props);
        const depositTable: dynamodb.Table = this.createOrUpdateDepositTable(
            depositTableId,
            depositTableName,
        );

        const withdrawalTableId: string = 'WithdrawalTable';
        const withdrawalTableName: string = EmilyStackUtils.getResourceName(withdrawalTableId, props);
        const withdrawalTable: dynamodb.Table = this.createOrUpdateWithdrawalTable(
            withdrawalTableId,
            withdrawalTableName,
        );

        const chainstateTableId: string = 'ChainstateTable';
        const chainstateTableName: string = EmilyStackUtils.getResourceName(chainstateTableId, props);
        const chainstateTable: dynamodb.Table = this.createOrUpdateChainstateTable(
            chainstateTableId,
            chainstateTableName,
        );

        const operationLambda: lambda.Function = this.createOrUpdateOperationLambda(
            depositTableName,
            withdrawalTableName,
            chainstateTableName,
            props
        );

        // Give the operation lambda full access to the DynamoDB tables.
        depositTable.grantReadWriteData(operationLambda);
        withdrawalTable.grantReadWriteData(operationLambda);
        chainstateTable.grantReadWriteData(operationLambda);

        const emilyApi: apig.SpecRestApi = this.createOrUpdateApi(operationLambda, props);
    }

    /**
     * Creates or updates a DynamoDB table for deposits.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table with configured indexes is returned.
     */
    createOrUpdateDepositTable(
        depositTableId: string,
        depositTableName: string,
    ): dynamodb.Table {
        const table: dynamodb.Table = new dynamodb.Table(this, depositTableId, {
            tableName: depositTableName,
            partitionKey: {
                name: 'BitcoinTxid',
                type: dynamodb.AttributeType.STRING,
            },
            sortKey: {
                name: 'BitcoinTxOutputIndex',
                type: dynamodb.AttributeType.NUMBER,
            }
        });

        const indexName: string = "DepositStatus";
        table.addGlobalSecondaryIndex({
            indexName: indexName,
            partitionKey: {
                name: 'OpStatus',
                type:  dynamodb.AttributeType.STRING
            },
            sortKey: {
                name: 'LastUpdateHeight',
                type:  dynamodb.AttributeType.NUMBER
            },
            projectionType: dynamodb.ProjectionType.INCLUDE,
            nonKeyAttributes: [
                "BitcoinTxid",
                "BitcoinTxOutputIndex",
                "Recipient",
                "Amount",
                "LastUpdateBlockHash",
            ]
        });

        // TODO(TBD): Add an additional GSI for querying by user; not required for MVP.
        return table;
    }

    /**
     * Creates or updates a DynamoDB table for withdrawals.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table with configured indexes is returned.
     */
    createOrUpdateWithdrawalTable(
        tableId: string,
        tableName: string,
    ): dynamodb.Table {
        // Create DynamoDB table to store the messages. Encrypted by default.
        const table: dynamodb.Table = new dynamodb.Table(this, tableId, {
            tableName: tableName,
            partitionKey: {
                name: 'RequestId',
                type: dynamodb.AttributeType.NUMBER,
            },
            sortKey: {
                name: 'StacksBlockHash',
                type: dynamodb.AttributeType.STRING,
            }
        });

        const indexName: string = "WithdrawalStatus";
        table.addGlobalSecondaryIndex({
            indexName: indexName,
            partitionKey: {
                name: 'OpStatus',
                type:  dynamodb.AttributeType.STRING
            },
            sortKey: {
                name: 'LastUpdateHeight',
                type:  dynamodb.AttributeType.NUMBER
            },
            projectionType: dynamodb.ProjectionType.INCLUDE,
            nonKeyAttributes: [
                "RequestId",
                "StacksBlockHash",
                "StacksBlockHeight",
                "Recipient",
                "Amount",
                "LastUpdateBlockHash",
            ]
        });

        // TODO(TBD): Add an additional GSI for querying by user; not required for MVP.
        return table;
    }

    /**
     * Creates or updates a DynamoDB table for chain state.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table is returned without additional configuration.
     */
    createOrUpdateChainstateTable(
        tableId: string,
        tableName: string,
    ): dynamodb.Table {
        // Create DynamoDB table to store the messages. Encrypted by default.
        return new dynamodb.Table(this, tableId, {
            tableName: tableName,
            partitionKey: {
                name: 'Height',
                type: dynamodb.AttributeType.NUMBER,
            },
            sortKey: {
                name: 'Hash',
                type: dynamodb.AttributeType.STRING,
            }
        });
    }

    /**
     * Creates or updates the operation Lambda function.
     * @param {string} depositTableName The name of the deposit DynamoDB table.
     * @param {string} withdrawalTableName The name of the withdrawal DynamoDB table.
     * @param {string} chainstateTableName The name of the chainstate DynamoDB table.
     * @param {EmilyStackProps} props The stack properties.
     * @returns {lambda.Function} The created or updated Lambda function.
     * @post Lambda function with environment variables set and permissions for DynamoDB access is returned.
     */
    createOrUpdateOperationLambda(
        depositTableName: string,
        withdrawalTableName: string,
        chainstateTableName: string,
        props: EmilyStackProps
    ): lambda.Function {

        const operationLambdaId: string = "OperationLambda";
        const operationLambda: lambda.Function = new lambda.Function(this, operationLambdaId, {
            functionName: EmilyStackUtils.getResourceName(operationLambdaId, props),
            architecture: EmilyStackUtils.getLambdaArchitecture(props),
            runtime: lambda.Runtime.PROVIDED_AL2023,
            code: lambda.Code.fromAsset(EmilyStackUtils.getPathFromProjectRoot(
                props.stageName === Constants.UNIT_TEST_STAGE_NAME
                    ? "emily/cdk/test/assets/empty-lambda.zip"
                    : "target/lambda/emily-handler/bootstrap.zip"
            )),
            // Lambda should be very fast. Something is wrong if it takes > 5 seconds.
            timeout: cdk.Duration.seconds(5),
            handler: "main",
            environment: {
                // Give lambda access to the table name.
                DEPOSIT_TABLE_NAME: depositTableName,
                WITHDRAWAL_TABLE_NAME: withdrawalTableName,
                CHAINSTATE_TABLE_NAME: chainstateTableName,
                // Declare an environment variable that will be overwritten in local SAM
                // deployments the AWS stack. SAM can only set environment variables that are
                // already expected to be present in the lambda.
                IS_LOCAL: "false",
            }
        });

        // Return lambda resource.
        return operationLambda;
    }

    /**
     * Creates or updates the API Gateway to connect with the Lambda function.
     * @param {lambda.Function} operationLambda The Lambda function to connect to the API.
     * @param {EmilyStackProps} props The stack properties.
     * @returns {apig.SpecRestApi} The created or updated API Gateway.
     * @post An API Gateway with execute permissions linked to the Lambda function is returned.
     */
    createOrUpdateApi(
        operationLambda: lambda.Function,
        props: EmilyStackProps
    ): apig.SpecRestApi {

        const restApiId: string  = "EmilyAPI";
        const restApi: apig.SpecRestApi = new apig.SpecRestApi(this, restApiId, {
            restApiName: EmilyStackUtils.getResourceName(restApiId, props),
            apiDefinition: EmilyStackUtils.restApiDefinitionWithLambdaIntegration(
                EmilyStackUtils.getPathFromProjectRoot(
                    ".generated-sources/emily/openapi/emily-openapi-spec.json"
                ),
                [
                    // This must match the Lambda name from the @aws.apigateway#integration trait in the
                    // smithy operations and resources that should be handled by this Lambda.
                    ["OperationLambda", operationLambda]
                ],
            ),
            deployOptions: { stageName: props.stageName },
        });

        // Give the the rest api execute ARN permission to invoke the lambda.
        operationLambda.addPermission("ApiInvokeLambdaPermission", {
            principal: new iam.ServicePrincipal("apigateway.amazonaws.com"),
            action: "lambda:InvokeFunction",
            sourceArn: restApi.arnForExecuteApi(),
        });

        // Return api resource.
        return restApi;
    }
}
