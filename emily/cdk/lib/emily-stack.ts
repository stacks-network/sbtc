// Import the AWS CDK
import * as cdk from 'aws-cdk-lib';
import * as apig from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cr from 'aws-cdk-lib/custom-resources';
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

        // Set persistent resources to be deleted when the stack is deleted in a development environment.
        //
        // In a production environment we don't want to do this as it would result in data loss
        // without an explicit action to delete the resources.
        const persistentResourceRemovalPolicy: cdk.RemovalPolicy = EmilyStackUtils.isDevelopmentStack()
            ? cdk.RemovalPolicy.DESTROY
            : cdk.RemovalPolicy.RETAIN;

        // we should support 'undefine' type because the PIT option is not available in local DynamoDB
        // and will make it crash
        const pointInTimeRecovery: undefined | boolean = EmilyStackUtils.isDevelopmentStack() ? undefined : true;

        const depositTableId: string = 'DepositTable';
        const depositTableName: string = EmilyStackUtils.getResourceName(depositTableId, props);
        const depositTable: dynamodb.Table = this.createOrUpdateDepositTable(
            depositTableId,
            depositTableName,
            persistentResourceRemovalPolicy,
            pointInTimeRecovery,
        );

        const withdrawalTableId: string = 'WithdrawalTable';
        const withdrawalTableName: string = EmilyStackUtils.getResourceName(withdrawalTableId, props);
        const withdrawalTable: dynamodb.Table = this.createOrUpdateWithdrawalTable(
            withdrawalTableId,
            withdrawalTableName,
            persistentResourceRemovalPolicy,
            pointInTimeRecovery,
        );

        const chainstateTableId: string = 'ChainstateTable';
        const chainstateTableName: string = EmilyStackUtils.getResourceName(chainstateTableId, props);
        const chainstateTable: dynamodb.Table = this.createOrUpdateChainstateTable(
            chainstateTableId,
            chainstateTableName,
            persistentResourceRemovalPolicy,
            pointInTimeRecovery,
        );

        const limitTableId: string = 'LimitTable';
        const limitTableName: string = EmilyStackUtils.getResourceName(limitTableId, props);
        const limitTable: dynamodb.Table = this.createOrUpdateLimitTable(
            limitTableId,
            limitTableName,
            persistentResourceRemovalPolicy,
            pointInTimeRecovery,
        );

        if (!EmilyStackUtils.isTablesOnly()) {
            const operationLambda: lambda.Function = this.createOrUpdateOperationLambda(
                depositTableName,
                withdrawalTableName,
                chainstateTableName,
                limitTableName,
                persistentResourceRemovalPolicy,
                props
            );

            // Create an alias for the lambda.
            const alias = new lambda.Alias(this, "OperationLambdaAlias", {
                aliasName: "Current",
                version: operationLambda.currentVersion,
            });

            // Give the operation lambda full access to the DynamoDB tables.
            depositTable.grantReadWriteData(operationLambda);
            withdrawalTable.grantReadWriteData(operationLambda);
            chainstateTable.grantReadWriteData(operationLambda);
            limitTable.grantReadWriteData(operationLambda);

            const emilyApis: apig.SpecRestApi[] = this.createOrUpdateApi(
                alias,
                props,
            );
        }
    }

    /**
     * Creates or updates a DynamoDB table for deposits.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @param {cdk.RemovalPolicy} removalPolicy The removal policy for the table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table with configured indexes is returned.
     */
    createOrUpdateDepositTable(
        depositTableId: string,
        depositTableName: string,
        removalPolicy: cdk.RemovalPolicy,
        pointInTimeRecovery: undefined | boolean,
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
            },
            removalPolicy: removalPolicy,
            billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // On-demand provisioning
            pointInTimeRecovery: pointInTimeRecovery,
        });

        const byStatusIndexName: string = "DepositStatus";
        table.addGlobalSecondaryIndex({
            indexName: byStatusIndexName,
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
                "ReclaimScript",
                "DepositScript",
            ]
        });

        const byRecipientIndexName: string = "DepositRecipient";
        table.addGlobalSecondaryIndex({
            indexName: byRecipientIndexName,
            partitionKey: {
                name: 'Recipient',
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
                "OpStatus",
                "Amount",
                "LastUpdateBlockHash",
                "ReclaimScript",
                "DepositScript",
            ]
        });

        // TODO(388): Add an additional GSI for querying by user; not required for MVP.
        return table;
    }

    /**
     * Creates or updates a DynamoDB table for withdrawals.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @param {cdk.RemovalPolicy} removalPolicy The removal policy for the table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table with configured indexes is returned.
     */
    createOrUpdateWithdrawalTable(
        tableId: string,
        tableName: string,
        removalPolicy: cdk.RemovalPolicy,
        pointInTimeRecovery: undefined | boolean,
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
            },
            removalPolicy: removalPolicy,
            billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // On-demand provisioning
            pointInTimeRecovery: pointInTimeRecovery,
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

        // TODO(388): Add an additional GSI for querying by user; not required for MVP.
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
        removalPolicy: cdk.RemovalPolicy,
        pointInTimeRecovery: undefined | boolean,
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
            },
            removalPolicy: removalPolicy,
            billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // On-demand provisioning
            pointInTimeRecovery: pointInTimeRecovery,
        });
    }

    /**
     * Creates or updates a DynamoDB table for limits.
     * @param {string} tableId The id of the table AWS resource.
     * @param {string} tableName The name of the DynamoDB table.
     * @returns {dynamodb.Table} The created or updated DynamoDB table.
     * @post A DynamoDB table is returned without additional configuration.
     */
    createOrUpdateLimitTable(
        tableId: string,
        tableName: string,
        removalPolicy: cdk.RemovalPolicy,
        pointInTimeRecovery: undefined | boolean,
    ): dynamodb.Table {
        // Create DynamoDB table to store the messages. Encrypted by default.
        return new dynamodb.Table(this, tableId, {
            tableName: tableName,
            partitionKey: {
                name: 'Account',
                type: dynamodb.AttributeType.STRING,
            },
            sortKey: {
                name: 'Timestamp',
                type: dynamodb.AttributeType.NUMBER,
            },
            removalPolicy: removalPolicy,
            billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // On-demand provisioning
            pointInTimeRecovery: pointInTimeRecovery,
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
        limitTableName: string,
        removalPolicy: cdk.RemovalPolicy,
        props: EmilyStackProps
    ): lambda.Function {

        const operationLambdaId: string = "OperationLambda";
        const operationLambda: lambda.Function = new lambda.Function(this, operationLambdaId, {
            functionName: EmilyStackUtils.getResourceName(operationLambdaId, props),
            architecture: lambda.Architecture.X86_64,
            runtime: lambda.Runtime.PROVIDED_AL2023,
            code: lambda.Code.fromAsset(EmilyStackUtils.getPathFromProjectRoot(
                props.stageName === Constants.UNIT_TEST_STAGE_NAME
                    ? "emily/cdk/test/assets/empty-lambda.zip"
                    : "target/lambda/emily-lambda/bootstrap.zip"
            )),
            // Lambda should be very fast. Something is wrong if it takes > 5 seconds.
            timeout: cdk.Duration.seconds(5),
            handler: "main",
            environment: {
                // Give lambda access to the table name.
                DEPOSIT_TABLE_NAME: depositTableName,
                WITHDRAWAL_TABLE_NAME: withdrawalTableName,
                CHAINSTATE_TABLE_NAME: chainstateTableName,
                LIMIT_TABLE_NAME: limitTableName,
                // Declare an environment variable that will be overwritten in local SAM
                // deployments the AWS stack. SAM can only set environment variables that are
                // already expected to be present in the lambda.
                IS_LOCAL: "false",
                TRUSTED_REORG_API_KEY: props.trustedReorgApiKey,
            },
            description: `Emily Api Handler. ${EmilyStackUtils.getLambdaGitIdentifier()}`,
            currentVersionOptions: {
                removalPolicy,
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
        operationLambda: lambda.Alias,
        props: EmilyStackProps
    ): apig.SpecRestApi[] {

        let apisToCreate = [
            {
                purpose: "public",
                numApiKeys: EmilyStackUtils.getNumSignerApiKeys(),
            },
            {
                purpose: "private",
                numApiKeys: 1,
            },
        ];
        // Add testing api if it's a development stack.
        if (EmilyStackUtils.isDevelopmentStack()) {
            apisToCreate.push({
                purpose: "testing",
                numApiKeys: 3,
            });
        }
        // Create all the apis.
        return apisToCreate
            .map((apiToCreate) => this.createOrUpdateSpecificApi(
                operationLambda,
                apiToCreate.numApiKeys,
                apiToCreate.purpose as "public" | "private" | "testing",
                props
            ));
    }

    /**
     * Creates or updates a specific API Gateway to connect with the Lambda function.
     * @param {lambda.Function} operationLambda The Lambda function to connect to the API.
     * @param {number} numApiKeys The number of API keys to create for the API.
     * @param {string} apiPurpose The purpose of the API.
     * @param {EmilyStackProps} props The stack properties.
     * @returns {apig.SpecRestApi} The created or updated API Gateway.
     * @post An API Gateway with execute permissions linked to the Lambda function is returned.
     */
    createOrUpdateSpecificApi(
        operationLambda: lambda.Alias,
        numApiKeys: number,
        apiPurpose: "public" | "private" | "testing",
        props: EmilyStackProps,
    ): apig.SpecRestApi {
        const apiPurposeTitleCase = apiPurpose.charAt(0).toUpperCase() + apiPurpose.slice(1);
        const apiPurposeResourceIdSuffix = apiPurpose === "public" ? "" : `-${apiPurposeTitleCase}`;

        const apiId: string = `EmilyAPI${apiPurposeResourceIdSuffix}`;
        const api: apig.SpecRestApi = new apig.SpecRestApi(this, apiId, {
            restApiName: EmilyStackUtils.getResourceName(apiId, props),
            apiDefinition: EmilyStackUtils.restApiDefinitionWithLambdaIntegration(
                EmilyStackUtils.getPathFromProjectRoot(
                    `.generated-sources/emily/openapi/generated-specs/${apiPurpose}-emily-openapi-spec.json`
                ),
                [
                    // This must match the Lambda name from the @aws.apigateway#integration trait in the
                    // smithy operations and resources that should be handled by this Lambda.
                    ["OperationLambda", operationLambda]
                ],
            ),
            deployOptions: { stageName: props.stageName },
        });

        // Create a usage plan that will be used by the Signers. This will allow us to throttle
        // the general API more than the signers.
        const apiUsagePlanId: string = `SignerApiUsagePlan${apiPurposeResourceIdSuffix}`;
        const apiUsagePlan = api.addUsagePlan(apiUsagePlanId, {
            name: EmilyStackUtils.getResourceName(apiUsagePlanId, props),
            throttle: {
                // These are very high limits. We can adjust them down as needed.
                rateLimit: 100,
                burstLimit: 200,
            },
            apiStages: [
                {
                    api: api,
                    stage: api.deploymentStage,
                }
            ]
        });

        let api_keys = [];
        for (let i = 0; i < numApiKeys; i++) {
            // Create an API Key
            const apiKeyId: string = `ApiKey${apiPurposeResourceIdSuffix}-${i}`;
            const apiKey = api.addApiKey(apiKeyId, {
                apiKeyName: EmilyStackUtils.getResourceName(apiKeyId, props),
            });

            // Associate the API Key with the Usage Plan and specify stages
            apiUsagePlan.addApiKey(apiKey);
            api_keys.push(apiKey);
        }

        // Give the rest api execute ARN permission to invoke the lambda.
        const apiInvokeLambdaPermissionId: string = `ApiInvokeLambdaPermission${apiPurposeResourceIdSuffix}`;
        operationLambda.addPermission(apiInvokeLambdaPermissionId, {
            principal: new iam.ServicePrincipal("apigateway.amazonaws.com"),
            action: "lambda:InvokeFunction",
            sourceArn: api.arnForExecuteApi(),
        });

        // Only add the custom domain name it's specified.
        let customRootDomainNameRoot = EmilyStackUtils.getCustomRootDomainName();
        let hostedZoneId = EmilyStackUtils.getHostedZoneId();
        if (customRootDomainNameRoot !== undefined) {
            // Error if the hosted zone ID is not provided.
            if (hostedZoneId === undefined) {
                throw new Error("Custom domain name specified but hosted zone ID not provided.");
            }

            // Create the custom domain name of the format:
            //   if stage != prod: [stage].[purpose].[customRootDomainNameRoot]
            //   if stage == prod: [purpose].[customRootDomainNameRoot]
            const stagePrefix = EmilyStackUtils.getStageName() === Constants.PROD_STAGE_NAME
                ? ""
                : `${EmilyStackUtils.getStageName()}.`;
            const purposePrefix = apiPurpose != "public" ? `${apiPurpose}.` : "";
            const customDomainName = `${purposePrefix}${stagePrefix}${customRootDomainNameRoot}`;

            // Get zone.
            const hostedZoneResourceId = `HostedZone${apiPurposeResourceIdSuffix}`;
            const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, hostedZoneResourceId, {
                hostedZoneId: hostedZoneId,
                zoneName: customDomainName,
            });

            // Get certificate.
            const DomainCertificateId = `DomainCertificate${apiPurposeResourceIdSuffix}`;
            const certificate = new certificatemanager.Certificate(this, DomainCertificateId, {
                domainName: customDomainName,
                validation: certificatemanager.CertificateValidation.fromDns(hostedZone),
            });

            // Create a custom domain.
            let customDomainId = `CustomDomain${apiPurposeResourceIdSuffix}`;
            const customDomain = new apig.DomainName(this, customDomainId, {
                domainName: customDomainName,
                certificate: certificate,
                // If the endpoint is in us-east-1 then we'll use EDGE because it's a better faster
                // option globally. If the stack is in any region other than us-east-1 you'll need
                // to make the certificate in us-east-1 independently and then reference it here if you
                // want to use the EDGE endpoint type. That's a big pain and simply not worth it,
                // especially if we only deploy "prod" in us-east-1.
                endpointType: this.region == 'us-east-1' && !EmilyStackUtils.isDevelopmentStack()
                    ? apig.EndpointType.EDGE
                    : apig.EndpointType.REGIONAL,
            });

            // Map custom domain to API Gateway
            let basePathMappingId = `BasePathMapping${apiPurposeResourceIdSuffix}`;
            new apig.BasePathMapping(this, basePathMappingId, {
                domainName: customDomain,
                restApi: api,
                stage: api.deploymentStage,
            });

            // Create a Route 53 alias record
            let aliasRecordId = `AliasRecord${apiPurposeResourceIdSuffix}`;
            new route53.ARecord(this, aliasRecordId, {
                zone: hostedZone,
                target: route53.RecordTarget.fromAlias(new route53Targets.ApiGatewayDomain(customDomain)),
            });
        }

        // Return api resource.
        return api;
    }
}
