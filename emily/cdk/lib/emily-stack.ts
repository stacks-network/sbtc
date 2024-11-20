// Import the AWS CDK
import * as cdk from 'aws-cdk-lib';
import * as apig from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
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

        const depositTableId: string = 'DepositTable';
        const depositTableName: string = EmilyStackUtils.getResourceName(depositTableId, props);
        const depositTable: dynamodb.Table = this.createOrUpdateDepositTable(
            depositTableId,
            depositTableName,
            persistentResourceRemovalPolicy,
        );

        const withdrawalTableId: string = 'WithdrawalTable';
        const withdrawalTableName: string = EmilyStackUtils.getResourceName(withdrawalTableId, props);
        const withdrawalTable: dynamodb.Table = this.createOrUpdateWithdrawalTable(
            withdrawalTableId,
            withdrawalTableName,
            persistentResourceRemovalPolicy,
        );

        const chainstateTableId: string = 'ChainstateTable';
        const chainstateTableName: string = EmilyStackUtils.getResourceName(chainstateTableId, props);
        const chainstateTable: dynamodb.Table = this.createOrUpdateChainstateTable(
            chainstateTableId,
            chainstateTableName,
            persistentResourceRemovalPolicy,
        );

        const limitTableId: string = 'LimitTable';
        const limitTableName: string = EmilyStackUtils.getResourceName(limitTableId, props);
        const limitTable: dynamodb.Table = this.createOrUpdateLimitTable(
            limitTableId,
            limitTableName,
            persistentResourceRemovalPolicy,
        );

        if (!EmilyStackUtils.isTablesOnly()) {
            const operationLambda: lambda.Function = this.createOrUpdateOperationLambda(
                depositTableName,
                withdrawalTableName,
                chainstateTableName,
                limitTableName,
                props
            );

            // Give the operation lambda full access to the DynamoDB tables.
            depositTable.grantReadWriteData(operationLambda);
            withdrawalTable.grantReadWriteData(operationLambda);
            chainstateTable.grantReadWriteData(operationLambda);
            limitTable.grantReadWriteData(operationLambda);

            const emilyApis: apig.SpecRestApi[] = this.createOrUpdateApi(operationLambda, props);
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
    ): apig.SpecRestApi[] {

        let apisToCreate = [
            {
                purpose: "public",
                numApiKeys: 0,
            },
            {
                purpose: "signer",
                numApiKeys: EmilyStackUtils.getNumSignerApiKeys(),
            },
            {
                purpose: "admin",
                numApiKeys: 1,
            },
        ];
        // Add testing api if it's a development stack.
        if (EmilyStackUtils.isDevelopmentStack()) {
            apisToCreate.push({
                purpose: "testing",
                numApiKeys: 1,
            });
        }
        // Create all the apis.
        return apisToCreate
            .map((apiToCreate) => this.createOrUpdateSpecificApi(
                operationLambda,
                apiToCreate.numApiKeys,
                apiToCreate.purpose as "public" | "signer" | "admin" | "testing",
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
        operationLambda: lambda.Function,
        numApiKeys: number,
        apiPurpose: "public" | "signer" |  "admin" | "testing",
        props: EmilyStackProps,
    ): apig.SpecRestApi {

        const apiPurposeTitleCase = apiPurpose.charAt(0).toUpperCase() + apiPurpose.slice(1);
        // TODO: Change this to `Api{}-${apiPurposeTitleCase}`
        const apiId: string = `${apiPurposeTitleCase}Api`;
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

        // Give the the rest api execute ARN permission to invoke the lambda.
        let apiInvokeLambdaPermissionId: string = `ApiUsagePlan-${apiPurposeTitleCase}`;
        operationLambda.addPermission(apiInvokeLambdaPermissionId, {
            principal: new iam.ServicePrincipal("apigateway.amazonaws.com"),
            action: "lambda:InvokeFunction",
            sourceArn: api.arnForExecuteApi(),
        });

        // If there are API keys, create a usage plan for the API and then create the API keys.
        let apiKeys = [];
        let apiUsagePlan = null;
        if (numApiKeys > 0) {
            const apiUsagePlanId: string = `ApiUsagePlan-${apiPurposeTitleCase}`;
            apiUsagePlan = api.addUsagePlan(apiUsagePlanId, {
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
            // Iterate over the number of API keys to create and create them.
            for (let i = 0; i < numApiKeys; i++) {
                const apiKeyId: string = `ApiKey-${apiPurposeTitleCase}-${i + 1}`;
                const apiKey = api.addApiKey(apiKeyId, {
                    apiKeyName: EmilyStackUtils.getResourceName(apiKeyId, props),
                });
                // Associate the API Key with the Usage Plan and specify stages
                apiUsagePlan.addApiKey(apiKey);
                apiKeys.push(apiKey);
            }
        }

        // Attach custom root domain name.
        let customRootDomainName = EmilyStackUtils.getCustomRootDomainName();
        let hostedZoneId = EmilyStackUtils.getHostedZoneId();
        if (customRootDomainName !== undefined) {
            // Error if the hosted zone ID is not provided but the custom root domain name is.
            if (hostedZoneId === undefined) {
                throw new Error("Custom domain name specified but hosted zone ID not provided.");
            }
            // Add any necessary prefixes to the domain name to differentiate the api being called.
            // The format will be `stage.purpose.customRootDomainName` where the corresponding value
            // will be added if it's not public or production.
            //
            // A dev stack's signer api: dev.signer.customRootDomainName
            // A dev stack's public api: dev.customRootDomainName
            // a production stacks public api: customRootDomainName
            const domainNameStagePrefix = EmilyStackUtils.isProductionStack()
                ? ""
                : `${EmilyStackUtils.getStageName()}.`;
            const domainNamePurposePrefix = apiPurpose === "public"
                ? ""
                : `${apiPurpose}.`;
            const customDomainName = `${domainNameStagePrefix}${domainNamePurposePrefix}${customRootDomainName}`;
            const hostedZoneConstructId = `HostedZone-${apiPurposeTitleCase}`;
            const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, hostedZoneConstructId, {
                hostedZoneId: hostedZoneId,
                zoneName: customDomainName,
            });
            // Make certificate.
            let certificateId = `DomainCertificate-${apiPurposeTitleCase}`;
            const certificate = new certificatemanager.Certificate(this, certificateId, {
                // This "name" will only be provided in the "Name" tag of the resource since
                // setting the physical resource id of the certificate is not supported.
                certificateName: EmilyStackUtils.getResourceName(certificateId, props),
                domainName: customDomainName,
                validation: certificatemanager.CertificateValidation.fromDns(hostedZone),
            });
            // Create the custom domain.
            const customDomainId = `Domain-${apiPurposeTitleCase}`;
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
            // Map custom domain to API Gateway. This maps the specific stage of the api that was deployed
            // above to the custom domain.
            let basePathMappingId = `DomainBasePathMapping-${apiPurposeTitleCase}`;
            new apig.BasePathMapping(this, basePathMappingId, {
                domainName: customDomain,
                restApi: api,
                stage: api.deploymentStage,
            });
            // Create a Route 53 alias record to map the custom domain to the API Gateway.
            let aliasRecordId = `DomainAliasRecord-${apiPurposeTitleCase}`;
            new route53.ARecord(this, aliasRecordId, {
                zone: hostedZone,
                target: route53.RecordTarget.fromAlias(new route53Targets.ApiGatewayDomain(customDomain)),
            });
        }
        // Return api resource.
        return api;
    }
}
