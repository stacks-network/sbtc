// Import the AWS CDK
import * as cdk from 'aws-cdk-lib';
import * as apig from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { EmilyStackProps } from './emily-stack-props';
import { EmilyStackUtils } from './emily-stack-utils';

/**
* @class CloudFormationStack
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
        const depositTable: dynamodb.Table = this.createOrUpdateDepositTable(props);
        const withdrawalTable: dynamodb.Table = this.createOrUpdateWithdrawalTable(props);
        const chainstateTable: dynamodb.Table = this.createOrUpdateChainstateTable(props);
        const operationLambda: lambda.Function = this.createOrUpdateOperationLambda(
            depositTable,
            withdrawalTable,
            chainstateTable,
            props
        );
        const emilyApi: apig.SpecRestApi = this.createOrUpdateApi(operationLambda, props);
    }

    createOrUpdateDepositTable(props: EmilyStackProps): dynamodb.Table {
        const tableId: string = 'DepositTable';
        const table: dynamodb.Table = new dynamodb.Table(this, tableId, {
            tableName: EmilyStackUtils.getResourceName(tableId, props),
            partitionKey: {
                name: 'BitcoinTxid',
                type: dynamodb.AttributeType.BINARY,
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
                type:  dynamodb.AttributeType.NUMBER
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
            ]
        });

        // TODO: Add an additional GSI for querying by user; not required for MVP.
        return table;
    }

    createOrUpdateWithdrawalTable(props: EmilyStackProps): dynamodb.Table {
        // Create DynamoDB table to store the messages. Encrypted by default.
        const tableId: string = 'WithdrawalTable';
        const table: dynamodb.Table = new dynamodb.Table(this, tableId, {
            tableName: EmilyStackUtils.getResourceName(tableId, props),
            partitionKey: {
                name: 'RequestId',
                type: dynamodb.AttributeType.STRING,
            },
            sortKey: {
                name: 'StacksBlockHash',
                type: dynamodb.AttributeType.BINARY,
            }
        });

        const indexName: string = "WithdrawalStatus";
        table.addGlobalSecondaryIndex({
            indexName: indexName,
            partitionKey: {
                name: 'OpStatus',
                type:  dynamodb.AttributeType.NUMBER
            },
            sortKey: {
                name: 'LastUpdateHeight',
                type:  dynamodb.AttributeType.NUMBER
            },
            projectionType: dynamodb.ProjectionType.INCLUDE,
            nonKeyAttributes: [
                "RequestId",
                "StacksBlockHash",
                "Recipient",
                "Amount",
            ]
        });

        // TODO: Add an additional GSI for querying by user; not required for MVP.
        return table;
    }

    createOrUpdateChainstateTable(props: EmilyStackProps): dynamodb.Table {
        // Create DynamoDB table to store the messages. Encrypted by default.
        const tableId: string = 'ChainstateTable';
        return new dynamodb.Table(this, tableId, {
            tableName: EmilyStackUtils.getResourceName(tableId, props),
            partitionKey: {
                name: 'BlockHeight',
                type: dynamodb.AttributeType.NUMBER,
            },
            sortKey: {
                name: 'BlockHash',
                type: dynamodb.AttributeType.BINARY,
            }
        });
    }

    createOrUpdateOperationLambda(
        depositTable: dynamodb.Table,
        withdrawalTable: dynamodb.Table,
        chainstateTable: dynamodb.Table,
        props: EmilyStackProps
    ): lambda.Function {

        // This must match the Lambda name from the @aws.apigateway#integration trait in the
        // smithy operations and resources that should be handled by this Lambda.
        const operationLambdaId: string = "OperationLambda";

        const operationLambda: lambda.Function = new lambda.Function(this, operationLambdaId, {
            functionName: EmilyStackUtils.getResourceName(operationLambdaId, props),
            architecture: lambda.Architecture.ARM_64, // <- Will need to change when run locally for x86
            runtime: lambda.Runtime.PROVIDED_AL2023,
            code: lambda.Code.fromAsset(EmilyStackUtils.getPathFromProjectRoot(
                "target/lambda/emily-operation-lambda/bootstrap.zip"
            )),
            // Lambda should be very fast. Something is wrong if it takes > 5 seconds.
            timeout: cdk.Duration.seconds(30),
            handler: "main",
            environment: {
                // Give lambda access to the table name.
                DEPOSIT_TABLE_NAME: depositTable.tableName,
                WITHDRAWAL_TABLE_NAME: withdrawalTable.tableName,
                CHAINSTATE_TABLE_NAME: chainstateTable.tableName,
                // Declare an environment variable that will be overwritten in local SAM
                // deployments the AWS stack. SAM can only set environment variables that are
                // already expected to be present in the lambda.
                IS_LOCAL: "false",
            }
        });

        // Give the server lambda full access to the DynamoDB table.
        depositTable.grantReadWriteData(operationLambda);
        withdrawalTable.grantReadWriteData(operationLambda);
        chainstateTable.grantReadWriteData(operationLambda);

        // Return lambda resource.
        return operationLambda;
    }

    createOrUpdateApi(
        serverLambda: lambda.Function,
        props: EmilyStackProps
    ): apig.SpecRestApi {

        const restApiId: string  = "EmilyAPI";
        const restApi: apig.SpecRestApi = new apig.SpecRestApi(this, restApiId, {
            restApiName: EmilyStackUtils.getResourceName(restApiId, props),
            apiDefinition: EmilyStackUtils.restApiDefinition(EmilyStackUtils.getPathFromProjectRoot(
                ".generated-sources/openapi/openapi/Emily.openapi.json"
            )),
            deployOptions: { stageName: props.stageName },
        });

        // Give the the rest api execute ARN permission to invoke the lambda.
        serverLambda.addPermission("ApiInvokeLambdaPermission", {
            principal: new iam.ServicePrincipal("apigateway.amazonaws.com"),
            action: "lambda:InvokeFunction",
            sourceArn: restApi.arnForExecuteApi(),
        });

        // Return api resource.
        return restApi;
    }
}
